//! pico2hsm firmware entry point.
//!
//! Embassy async executor entry point for the RP2350. Initialises board
//! peripherals, the OTP subsystem, USB CCID transport, and the APDU
//! dispatcher, then runs the main SC-HSM command loop.
//!
//! # Initialisation sequence
//! 1. Board peripherals — SPI buses, LED.
//! 2. OTP — read storage key material + device identity.
//! 3. Storage master key derivation via HKDF.
//! 4. USB CCID transport init (embassy-usb + CcidTransport).
//! 5. APDU dispatcher + SC-HSM protocol handler created.
//! 6. Concurrent run: USB device manager + CCID command loop.
//!
//! # Concurrency model
//! `embassy_futures::join::join` drives the USB device manager
//! (`UsbDevice::run`) and the CCID command loop in a single Embassy task.
//! Both futures run cooperatively: the USB manager handles enumeration and
//! control transfers while the CCID loop awaits and processes APDU commands.
//!
//! # Board selection
//! The correct board impl is selected at compile time:
//! - `rp2350_one_4m`                     → `Rp2350OneBoard`
//! - `rp2350_geek_*`                     → `Rp2350GeekBoard`
//!
//! # Host (x86_64) note
//! This binary only makes sense on ARM. When compiled for x86_64 (e.g., during
//! `cargo test`), the ARM-specific code is gated out and a no-op `main` is
//! provided so that the binary target compiles without errors.

#![cfg_attr(target_arch = "arm", no_std)]
#![cfg_attr(target_arch = "arm", no_main)]
#![allow(unused)]

// ─── ARM-only imports ─────────────────────────────────────────────────────────

#[cfg(target_arch = "arm")]
use defmt_rtt as _;
#[cfg(target_arch = "arm")]
use embassy_executor::Spawner;
#[cfg(target_arch = "arm")]
use embassy_time::Timer;
#[cfg(target_arch = "arm")]
use panic_probe as _;
#[allow(unused_imports)]
use pico2hsm_firmware::{serial_fmt, serial_print, serial_println};

#[cfg(target_arch = "arm")]
use core::ptr::addr_of_mut;
#[cfg(target_arch = "arm")]
extern "C" {
    /// cortex-m-rt: lowest address the main stack may use — above .bss
    /// *and* .uninit (where defmt-rtt keeps its buffer).
    static _stack_end: u8;
}
#[cfg(target_arch = "arm")]
use embassy_rp::multicore::{spawn_core1, Stack};
#[cfg(target_arch = "arm")]
use embassy_rp::spinlock_mutex::SpinlockRawMutex;
#[cfg(target_arch = "arm")]
use embassy_sync::channel::Channel;
#[cfg(target_arch = "arm")]
use static_cell::StaticCell;

// ─── Core1 stack (ARM only) ──────────────────────────────────────────────────

/// Stack for core1.  Measured worst path (2026-10, pico2_4m debug, from the
/// `sub sp` prologues): dispatcher_loop 16 KB → dispatch_with_store 8 KB →
/// process_apdu_with_store 8 KB → route_with_store 4 KB → bip_slip 13 KB →
/// fetch_key 12 KB → read_key 7 KB ≈ 70 KB, so 128 KB leaves ~58 KB.
/// Do not reduce below 96 KB.
///
/// Core1 runs a synchronous dispatch loop (no Embassy executor) — the
/// full 128 KB is available as call-stack, with no async state machine
/// overhead.
#[cfg(target_arch = "arm")]
static mut CORE1_STACK: Stack<131072> = Stack::new();

/// Core0 → Core1: raw APDU bytes.  Empty Vec = reset-dispatcher signal.
/// Uses RP2350 hardware spinlock 29 for SMP-safe access across both cores.
#[cfg(target_arch = "arm")]
static APDU_CHANNEL: Channel<SpinlockRawMutex<29>, heapless::Vec<u8, 4096>, 1> = Channel::new();
/// Core1 → Core0: serialised response bytes (data + SW1 SW2).
/// Uses RP2350 hardware spinlock 30.
#[cfg(target_arch = "arm")]
static RESP_CHANNEL: Channel<SpinlockRawMutex<30>, heapless::Vec<u8, 4098>, 1> = Channel::new();

/// Core1 → Core0: flash operation requests.
/// Uses RP2350 hardware spinlock 27.
#[cfg(target_arch = "arm")]
static FLASH_REQ: Channel<SpinlockRawMutex<27>, FlashOp, 1> = Channel::new();
/// Core0 → Core1: flash operation results.
/// Uses RP2350 hardware spinlock 26.
#[cfg(target_arch = "arm")]
static FLASH_RESP: Channel<SpinlockRawMutex<26>, Result<(), pico2hsm_core::error::HsmError>, 1> =
    Channel::new();

/// Flash operation request — sent from core1 to core0 for flash persistence.
///
/// Core1 cannot call `embassy_rp::flash` directly (the `in_ram()` function
/// asserts `core_id == 0`).  Instead, `Core1KeyStore` sends each op to core0
/// via `FLASH_REQ` and blocks on `FLASH_RESP` until it completes.
#[cfg(target_arch = "arm")]
enum FlashOp {
    /// Encrypt and persist a key object to flash.
    ///
    /// Points at core1's `KeyObject` rather than carrying a copy: core1 stays
    /// blocked on `FLASH_RESP` until core0 has finished with it, so the
    /// pointee outlives every use, and no plaintext copy of the key is left
    /// behind in the channel slot.
    SaveKey(*const pico2hsm_firmware::security::key_management::KeyObject),
    /// Delete a key from persistent storage.
    EraseKey(pico2hsm_core::key::KeyId),
    /// Wipe ALL keys. Called by INITIALIZE only.
    WipeAll,
    /// Wipe only keys owned by the given applet.
    WipeByOwner(pico2hsm_core::key::AppletId),
    /// Reload keys from flash into the dispatcher (USB reconnect / reset).
    /// Core0 calls `dispatcher.load_keys_from_store(store)` via the raw
    /// pointer while core1 is awaiting the response.
    ReloadKeys,
}

// SAFETY: the only non-Send field is `SaveKey`'s pointer, which core0
// dereferences only while core1 is blocked waiting for `FLASH_RESP`.
#[cfg(target_arch = "arm")]
unsafe impl Send for FlashOp {}

/// A `KeyStore` implementation used by the core1 dispatcher during APDU
/// processing.
///
/// **SD card boards** (`rp2350_geek_sdcard`, `waveshare_rp2350_lcd_sdcard`):
/// All operations (read and write) go directly through the `store_ptr`.
/// SD card writes are plain SPI transactions with no core affinity — no need
/// to round-trip through core0.  This avoids blocking core0's async executor
/// (which must stay responsive for USB servicing and CCID time extensions).
///
/// **QMI flash boards** (all others):
/// Reads go through `store_ptr` (XIP memory-mapped, safe from any core).
/// Writes are sent to core0 one at a time and complete before the call
/// returns, because `embassy_rp::flash` asserts `core_id == 0`.  Being
/// synchronous means callers see real write errors, later reads in the same
/// APDU see earlier writes, and a PIN retry counter is on flash before the
/// PIN is compared.
#[cfg(target_arch = "arm")]
struct Core1KeyStore {
    /// Raw pointer to the BoardKeyStore.
    store_ptr: *mut pico2hsm_firmware::storage::BoardKeyStore,
}

#[cfg(target_arch = "arm")]
impl Core1KeyStore {
    fn new(store_ptr: *mut pico2hsm_firmware::storage::BoardKeyStore) -> Self {
        Core1KeyStore { store_ptr }
    }

    /// Whether this board uses direct SD card writes (no core0 channel needed).
    const fn is_direct_write() -> bool {
        cfg!(any(
            feature = "rp2350_geek_sdcard",
            feature = "waveshare_rp2350_lcd_sdcard",
        ))
    }

    /// Run `op` on core0 and block until it reports the result.
    fn on_core0(op: FlashOp) -> Result<(), pico2hsm_core::error::HsmError> {
        blocking_send(&FLASH_REQ, op);
        blocking_receive(&FLASH_RESP)
    }

    fn direct(&mut self) -> &mut pico2hsm_firmware::storage::BoardKeyStore {
        // SAFETY: core0 touches the store only while core1 is blocked in
        // `on_core0`, so this reference is never aliased by a live access.
        unsafe { &mut *self.store_ptr }
    }
}

#[cfg(target_arch = "arm")]
impl pico2hsm_firmware::storage::KeyStore for Core1KeyStore {
    fn save_key(
        &mut self,
        obj: &pico2hsm_firmware::security::key_management::KeyObject,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            return self.direct().save_key(obj);
        }
        Self::on_core0(FlashOp::SaveKey(obj))
    }

    fn fetch_key(
        &mut self,
        key_id: pico2hsm_core::key::KeyId,
    ) -> Result<
        Option<pico2hsm_firmware::security::key_management::KeyObject>,
        pico2hsm_core::error::HsmError,
    > {
        // Direct read — safe from any core.
        // For QMI flash this is XIP memory-mapped; for SD card it's SPI reads.
        self.direct().fetch_key(key_id)
    }

    fn erase_key(
        &mut self,
        key_id: pico2hsm_core::key::KeyId,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            return self.direct().erase_key(key_id);
        }
        Self::on_core0(FlashOp::EraseKey(key_id))
    }

    fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            return self.direct().wipe_all();
        }
        Self::on_core0(FlashOp::WipeAll)
    }

    fn wipe_by_owner(
        &mut self,
        owner: pico2hsm_core::key::AppletId,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            return self.direct().wipe_by_owner(owner);
        }
        Self::on_core0(FlashOp::WipeByOwner(owner))
    }

    fn enumerate_keys(&self) -> heapless::Vec<pico2hsm_core::key::KeyId, 64> {
        heapless::Vec::new()
    }
    fn for_each_key(&self, _f: &mut dyn FnMut(pico2hsm_core::key::KeyId)) {}
}

/// One-time initialised key store — lives for the duration of the firmware.
/// Owned by core0 for flash writes; core1 accesses via FLASH_REQ/FLASH_RESP.
#[cfg(target_arch = "arm")]
static KEYSTORE_CELL: StaticCell<pico2hsm_firmware::storage::BoardKeyStore> = StaticCell::new();

/// Key count — updated by core1 dispatcher after each APDU dispatch.
/// Read by core0 board runners to display key count on LCD.
#[cfg(target_arch = "arm")]
static KEY_COUNT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Re-export for convenient access in this binary crate.
#[cfg(target_arch = "arm")]
use pico2hsm_firmware::CORE1_PROGRESS;
#[cfg(target_arch = "arm")]
use pico2hsm_firmware::{WATCHDOG_HEARTBEAT, WATCHDOG_STALL_LIMIT, WATCHDOG_SUPPRESS};

/// Dispatcher — stored in BSS outside the async task state machine so that
/// the `dispatcher_task` pool does not need to hold the full 50 KB Dispatcher
/// struct (which would overflow when combined with the 4 KB APDU/response
/// buffers that are also live at each await point).
#[cfg(target_arch = "arm")]
static DISPATCHER_CELL: StaticCell<pico2hsm_firmware::apdu::dispatcher::Dispatcher> =
    StaticCell::new();

/// Wrapper around a raw pointer to Dispatcher that implements `Send`.
///
/// SAFETY: The Dispatcher is initialized on core0, then exclusively used by
/// core1 (except during ReloadKeys, where core0 writes through the pointer
/// while core1 is blocked awaiting FLASH_RESP). This exclusive access pattern
/// makes cross-core transfer safe.
#[cfg(target_arch = "arm")]
struct DispatcherPtr(
    *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher,
    *mut pico2hsm_firmware::storage::BoardKeyStore,
);
#[cfg(target_arch = "arm")]
unsafe impl Send for DispatcherPtr {}

/// Block until a message can be sent on the channel.
///
/// Uses `try_send` (no async runtime required) and `wfe` to sleep between
/// attempts.  Core0 issues `sev` after each channel operation that could
/// unblock core1, so the `wfe` wakes promptly.
///
/// `try_send` calls `receiver_waker.wake()` on success, which wakes core0's
/// async receiver — no changes needed on the core0 side.
#[cfg(target_arch = "arm")]
fn blocking_send<M: embassy_sync::blocking_mutex::raw::RawMutex, T, const N: usize>(
    channel: &Channel<M, T, N>,
    mut message: T,
) {
    loop {
        match channel.try_send(message) {
            Ok(()) => {
                // Wake core0 in case it is in WFE/WFI (embassy executor idle).
                cortex_m::asm::sev();
                return;
            }
            Err(embassy_sync::channel::TrySendError::Full(returned)) => {
                message = returned;
                cortex_m::asm::wfe();
            }
        }
    }
}

/// Block until a message is received from the channel.
///
/// Uses `try_receive` (no async runtime required) and `wfe` to sleep between
/// attempts.  Core0 issues `sev` after each `APDU_CHANNEL.send()` and
/// `FLASH_RESP.send()` to wake core1.
#[cfg(target_arch = "arm")]
fn blocking_receive<M: embassy_sync::blocking_mutex::raw::RawMutex, T, const N: usize>(
    channel: &Channel<M, T, N>,
) -> T {
    loop {
        match channel.try_receive() {
            Ok(value) => return value,
            Err(_) => cortex_m::asm::wfe(),
        }
    }
}

/// APDU dispatcher loop — runs on core1 so that blocking ECC crypto does not
/// starve the USB driver which runs cooperatively on core0.
///
/// This is a synchronous loop with no Embassy executor — core1 sleeps via
/// `wfe` (Wait For Event) while idle and is woken by core0 via `sev` (Send
/// Event) when an APDU arrives.  This eliminates ~10–20 KB of async state
/// machine overhead that the Embassy executor would otherwise add.
///
/// Takes a raw pointer to the `Dispatcher` which was initialized and loaded
/// from the keystore by core0 before spawning core1.  Core0 never touches the
/// Dispatcher after this point, so the mutable reference is exclusive.
///
/// **QMI flash boards**: flash writes are delegated to core0 via
/// `FLASH_REQ`/`FLASH_RESP` channels because `embassy_rp::flash` asserts
/// `core_id == 0`.
///
/// **SD card boards**: all storage I/O happens directly on core1 via SPI.
/// No core0 round-trip needed — core0 stays free for USB servicing and
/// CCID time extensions throughout the entire APDU dispatch.
#[cfg(target_arch = "arm")]
fn dispatcher_loop(ptr_wrapper: DispatcherPtr) -> ! {
    let dispatcher_ptr = ptr_wrapper.0;
    let store_ptr = ptr_wrapper.1;
    // Core1 must not call defmt: embassy-rp's critical_section uses Spinlock31; if Core1
    // holds it while spinning for RTT buffer space, Core0 blocks with interrupts disabled
    // and USB processing stalls entirely.

    // Seed the software CSPRNG from hardware TRNG before any crypto operations.
    // reseed() does not call defmt, so it is safe to call here on Core1.
    let _ = pico2hsm_firmware::crypto::rng::reseed();

    // SAFETY: dispatcher_ptr was initialized on core0 and core0 never accesses
    // the Dispatcher after spawning core1.  The pointer is valid for the
    // lifetime of the firmware (backed by StaticCell in BSS).
    let dispatcher = unsafe { &mut *dispatcher_ptr };

    let mut session = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
    loop {
        let mut apdu_bytes = blocking_receive(&APDU_CHANNEL);
        // A new host session (USB reset/deconfigure or card power cycle)
        // must not inherit PIN/key authentication from the previous one.
        let now = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
        if now != session {
            dispatcher.clear_session();
            session = now;
        }
        // No defmt logging inside the receive loop.  All embassy_rp TRACE logs
        // from Core0 fill the RTT buffer rapidly; any defmt write from Core1
        // here would block on BLOCK_IF_FULL mode and deadlock both cores.
        if apdu_bytes.is_empty() {
            // Empty APDU = reset signal issued by core0 on USB disconnect.
            // Reset in-memory state and reload keys from store.
            //
            // NOTE: must use `reset_in_place` (writes fields through a raw
            // pointer) rather than `*dispatcher = Dispatcher::new()`.  The
            // Dispatcher struct is ~36 KB; in debug builds `Dispatcher::new()`
            // would place the full struct on the Core1 stack before copying
            // it into BSS, risking silent stack overflow on the second USB
            // reconnect in a test session.  reset_in_place also zeroizes the
            // old session's secrets (DKEK, PIN state, cached keys).
            dispatcher.reset_in_place();
            if Core1KeyStore::is_direct_write() {
                // SD card: reload directly on core1.
                let store = unsafe { &mut *store_ptr };
                dispatcher.load_keys_from_store(store);
            } else {
                // QMI flash: ask core0 to reload (it holds the store).
                let _ = Core1KeyStore::on_core0(FlashOp::ReloadKeys);
            }
            blocking_send(&RESP_CHANNEL, heapless::Vec::new());
        } else {
            CORE1_PROGRESS.store(10, core::sync::atomic::Ordering::Relaxed);
            let mut ks = Core1KeyStore::new(store_ptr);
            let response = dispatcher.dispatch_with_store(&apdu_bytes, &mut ks);
            // The command may carry PINs or key material; don't leave it on the stack.
            zeroize::Zeroize::zeroize(&mut apdu_bytes[..]);
            CORE1_PROGRESS.store(60, core::sync::atomic::Ordering::Relaxed);
            blocking_send(&RESP_CHANNEL, response);
            CORE1_PROGRESS.store(0, core::sync::atomic::Ordering::Relaxed);
        }
        KEY_COUNT.store(
            dispatcher.in_memory_key_count(),
            core::sync::atomic::Ordering::Relaxed,
        );
    }
}

// ─── defmt support (ARM only) ─────────────────────────────────────────────────
// defmt requires _defmt_timestamp and _defmt_panic to be defined by the crate.
// defmt-rtt provides the RTT transport; panic_probe provides #[panic_handler]
// but NOT #[defmt::panic_handler] — that must be defined by the application.
#[cfg(target_arch = "arm")]
defmt::timestamp!("{=u64:us}", embassy_time::Instant::now().as_micros());

#[cfg(target_arch = "arm")]
#[defmt::panic_handler]
fn defmt_panic() -> ! {
    panic_probe::hard_fault()
}

// ─── Embassy interrupt binding (ARM only) ─────────────────────────────────────

// Bind the TRNG and USB interrupts so embassy-rp can use them.
// This macro must appear at crate root (in main.rs) exactly once.
#[cfg(target_arch = "arm")]
embassy_rp::bind_interrupts!(struct Irqs {
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<embassy_rp::peripherals::TRNG>;
    USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<embassy_rp::peripherals::USB>;
    // PIO0/DMA_CH0 used by WS2812B; DMA_CH1+CH2 used by async SPI0 (LCD flush).
    // DMA_CH3+CH4 used by async SPI1 (geek board LCD flush on SPI1).
    // Multiple handlers on DMA_IRQ_0 — all DMA channels share this interrupt.
    // Harmless to register on all builds — IRQs only fire when hardware is active.
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<embassy_rp::peripherals::PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH0>,
                 embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH1>,
                 embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH2>,
                 embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH3>,
                 embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH4>;
});

// ─── USB device identity ───────────────────────────────────────────────────────

/// USB Vendor ID (pid.codes shared test VID — replace with assigned VID for
/// production).
const USB_VID: u16 = 0x1209;
/// USB Product ID (pico2hsm — https://pid.codes/1209/27C0/).
const USB_PID: u16 = 0x27C0;

// ─── ARM entry point ──────────────────────────────────────────────────────────

#[cfg(target_arch = "arm")]
#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // ── 1. Initialise RP2350 clocks and peripherals ─────────────────────────
    let p = embassy_rp::init(Default::default());

    // ── RTT probe-rs connect window (debug builds only) ──────────────────────
    // probe-rs sets RTT flags=BLOCK_IF_FULL after the chip resets post-flash.
    // Without a short delay, defmt messages fire before probe-rs enables
    // blocking mode and the data is dropped.
    // Uses a raw cycle loop to avoid any dependency on embassy-time being ready.
    // NOTE: at -O0 (debug build) each iteration is ~12 cycles on Cortex-M33,
    // so 12_500_000 ≈ 1 s at 150 MHz regardless of optimization level.
    #[cfg(debug_assertions)]
    {
        let mut n: u32 = 12_500_000;
        while n > 0 {
            n -= 1;
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    // ── MSPLIM — hardware stack overflow detection for Core0 ──────────────────
    // Core0 stack grows downward from 0x20082000 to _stack_end, which lies
    // above both .bss and .uninit.  (Using __ebss left the 4 KB defmt-rtt
    // buffer in .uninit unprotected.)  Also enable UsageFault so STKOF
    // surfaces cleanly in probe-rs.
    #[cfg(target_arch = "arm")]
    unsafe {
        let stack_end = core::ptr::addr_of!(_stack_end) as u32;
        cortex_m::register::msplim::write(stack_end);

        // Enable UsageFault handler so STKOF fires as UsageFault, not HardFault.
        // SHCSR bit 18 = USGFAULTENA.
        (*cortex_m::peripheral::SCB::PTR)
            .shcsr
            .modify(|v| v | (1 << 18));

        defmt::info!("core0: MSPLIM set to 0x{:08X} (_stack_end)", stack_end);
    }

    defmt::info!("pico2hsm: peripherals initialised");

    // ── Pico 2: security + OTP + board loop ──────────────────────────────────
    #[cfg(feature = "pico2_4m")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!(
            "OTP: provisioned={} production={}",
            otp.is_provisioned(),
            otp.is_production_mode()
        );
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_pico2_board(p).await;
    }

    // ── RP2350-One: security + OTP + board loop ──────────────────────────────
    #[cfg(feature = "rp2350_one_4m")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!(
            "OTP: provisioned={} production={}",
            otp.is_provisioned(),
            otp.is_production_mode()
        );
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_one_board(p).await;
    }

    // ── RP2350-Geek: pass p intact; run_geek_board initialises UART first ────
    #[cfg(any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard",))]
    {
        run_geek_board(p).await;
    }

    // ── Waveshare RP2350-LCD-1.47-B (QMI and single SD variants) ──────────────
    #[cfg(any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
    ))]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!(
            "OTP: provisioned={} production={}",
            otp.is_provisioned(),
            otp.is_production_mode()
        );
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_waveshare_lcd_board(p).await;
    }

    // ── Fallback ─────────────────────────────────────────────────────────────
    #[cfg(not(any(
        feature = "rp2350_one_4m",
        feature = "rp2350_geek_16m",
        feature = "rp2350_geek_sdcard",
        feature = "pico2_4m",
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
    )))]
    {
        defmt::error!("No board feature flag set — spinning forever");
        loop {
            Timer::after_millis(1000).await;
        }
    }
}

// ─── Flash operation handler (core0) ─────────────────────────────────────────

/// Execute a flash operation on core0 where `embassy_rp::flash` is permitted.
///
/// For `ReloadKeys`, the dispatcher pointer is used to reload keys from the
/// store into the freshly-reset dispatcher.  This is safe because core1 is
/// blocked awaiting `FLASH_RESP` and not touching the dispatcher.
#[cfg(target_arch = "arm")]
fn handle_flash_op(
    op: FlashOp,
    store: &mut pico2hsm_firmware::storage::BoardKeyStore,
    dispatcher_ptr: *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher,
) -> Result<(), pico2hsm_core::error::HsmError> {
    use pico2hsm_firmware::storage::KeyStore;
    // Flash work counts as progress for the core1 stall detector.
    WATCHDOG_HEARTBEAT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    match op {
        FlashOp::SaveKey(ptr) => {
            // SAFETY: see `FlashOp::SaveKey` — core1 is blocked until we reply.
            let obj = unsafe { &*ptr };
            let result = store.save_key(obj);
            defmt::info!(
                "FLASH_SVC: save_key 0x{:08x} => {}",
                obj.key_id,
                if result.is_ok() { "ok" } else { "FAIL" }
            );
            result
        }
        FlashOp::EraseKey(kid) => {
            let result = store.erase_key(kid);
            defmt::info!(
                "FLASH_SVC: erase_key 0x{:08x} => {}",
                kid.0,
                if result.is_ok() { "ok" } else { "FAIL" }
            );
            result
        }
        FlashOp::WipeAll => {
            defmt::info!("FLASH_SVC: wipe_all");
            store.wipe_all()
        }
        FlashOp::WipeByOwner(owner) => {
            defmt::info!("FLASH_SVC: wipe_by_owner {:?}", owner as u8);
            store.wipe_by_owner(owner)
        }
        FlashOp::ReloadKeys => {
            defmt::info!("FLASH_SVC: reload_keys");
            // SAFETY: core1 is blocked on FLASH_RESP.receive() and will not
            // touch the dispatcher until we send the response.
            let dispatcher = unsafe { &mut *dispatcher_ptr };
            dispatcher.load_keys_from_store(store);
            KEY_COUNT.store(
                dispatcher.in_memory_key_count(),
                core::sync::atomic::Ordering::Relaxed,
            );
            Ok(())
        }
    }
}

/// Wait for core1's next `RESP_CHANNEL` message while servicing any
/// `FLASH_REQ` it issues first.
///
/// Core1 may need core0 to perform flash operations before it can reply —
/// key writes during a dispatch, or `ReloadKeys` after a USB-reconnect
/// reset on QMI flash boards.  Waiting on `RESP_CHANNEL` alone in those paths
/// deadlocks both cores (core1 blocks on `FLASH_RESP`, core0 on `RESP_CHANNEL`).
#[cfg(target_arch = "arm")]
async fn recv_core1_response(
    store: &mut pico2hsm_firmware::storage::BoardKeyStore,
    dispatcher_ptr: *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher,
) -> heapless::Vec<u8, 4098> {
    use embassy_futures::select::{select, Either};
    loop {
        match select(RESP_CHANNEL.receive(), FLASH_REQ.receive()).await {
            Either::First(r) => return r,
            Either::Second(op) => {
                let result = handle_flash_op(op, store, dispatcher_ptr);
                FLASH_RESP.send(result).await;
                cortex_m::asm::sev(); // wake core1 from WFE
            }
        }
    }
}

/// Wait for core1's response to an APDU, keeping the host and core1 serviced.
///
/// - Services `FLASH_REQ` so core1's flash writes can complete.
/// - Sends a CCID time extension every 1.5 s of wall-clock time.  The deadline
///   is absolute, so a stream of flash ops (which block this executor) cannot
///   push it back; an overdue extension goes out as soon as the op finishes.
/// - Stall detector: if core1's heartbeat doesn't move for
///   `WATCHDOG_STALL_LIMIT` intervals (and `WATCHDOG_SUPPRESS` is clear),
///   returns `None`; the caller must reset the device (see `watchdog_reset`).
///
/// On USB disconnect, drains core1's response and returns an empty Vec so the
/// caller takes its normal disconnect path.
#[cfg(target_arch = "arm")]
async fn await_core1_response<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
    store: &mut pico2hsm_firmware::storage::BoardKeyStore,
    dispatcher_ptr: *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher,
) -> Option<heapless::Vec<u8, 4098>> {
    use core::sync::atomic::Ordering::Relaxed;
    use embassy_futures::select::{select3, Either3};
    use embassy_time::{Duration, Instant};

    const WTX_INTERVAL: Duration = Duration::from_millis(1500);
    let mut deadline = Instant::now() + WTX_INTERVAL;
    let mut stall_count: u32 = 0;
    let mut last_heartbeat = WATCHDOG_HEARTBEAT.load(Relaxed);
    loop {
        match select3(
            RESP_CHANNEL.receive(),
            Timer::at(deadline),
            FLASH_REQ.receive(),
        )
        .await
        {
            Either3::First(r) => return Some(r),
            Either3::Second(()) => {
                deadline = Instant::now() + WTX_INTERVAL;
                let progress = CORE1_PROGRESS.load(Relaxed);
                let heartbeat = WATCHDOG_HEARTBEAT.load(Relaxed);
                if WATCHDOG_SUPPRESS.load(Relaxed) || heartbeat != last_heartbeat {
                    stall_count = 0;
                    last_heartbeat = heartbeat;
                    defmt::warn!(
                        "time ext: core1 progress={} heartbeat={}",
                        progress,
                        heartbeat
                    );
                } else {
                    stall_count += 1;
                    defmt::warn!(
                        "time ext: core1 progress={} heartbeat={} STALL {}/{}",
                        progress,
                        heartbeat,
                        stall_count,
                        WATCHDOG_STALL_LIMIT
                    );
                    if stall_count >= WATCHDOG_STALL_LIMIT {
                        return None;
                    }
                }
                if let Err(pico2hsm_firmware::transport::ccid::CcidError::UsbDisconnected) =
                    ccid.send_time_extension().await
                {
                    let _ = recv_core1_response(store, dispatcher_ptr).await;
                    return Some(heapless::Vec::new());
                }
            }
            Either3::Third(op) => {
                let result = handle_flash_op(op, store, dispatcher_ptr);
                FLASH_RESP.send(result).await;
                cortex_m::asm::sev(); // wake core1 from WFE
            }
        }
    }
}

/// Send a response to the host, then wipe its data: responses can carry
/// secrets (decrypted plaintext, ECDH output, wrapped keys).  Dropped
/// unsent if the host session changed while the command ran.
#[cfg(target_arch = "arm")]
async fn send_and_wipe<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
    response: &mut heapless::Vec<u8, 4098>,
    epoch: u32,
) -> Result<(), pico2hsm_firmware::transport::ccid::CcidError> {
    // A response computed for a previous host session must not be delivered
    // into the new one (it would answer the new session's first command).
    let current = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
    let result = if current == epoch {
        ccid.send_response(response).await
    } else {
        Ok(())
    };
    // Keep the trailing SW (not secret): display boards show status from it.
    let data_len = response.len().saturating_sub(2);
    zeroize::Zeroize::zeroize(&mut response[..data_len]);
    result
}

/// Ends the host session on USB bus reset or deconfiguration (see
/// `SESSION_EPOCH`).  embassy-rp endpoints never report `Disabled`, so this
/// is the only reliable signal that the host went away.
#[cfg(target_arch = "arm")]
struct UsbSessionHandler;

/// The board's USB session handler (one board runner runs per boot).
#[cfg(target_arch = "arm")]
static USB_SESSION_HANDLER: StaticCell<UsbSessionHandler> = StaticCell::new();

#[cfg(target_arch = "arm")]
impl embassy_usb::Handler for UsbSessionHandler {
    fn reset(&mut self) {
        pico2hsm_firmware::bump_session_epoch();
    }

    fn configured(&mut self, configured: bool) {
        if !configured {
            pico2hsm_firmware::bump_session_epoch();
        }
    }
}

/// Core1 is stuck: tell the host (SW 6F00) and reset the whole chip.
///
/// Core1 cannot be safely abandoned — it would still own the dispatcher and
/// its late response would be taken as the answer to the next APDU — so a
/// full reset is the only state that is known to be consistent.
#[cfg(target_arch = "arm")]
async fn watchdog_reset<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
) -> ! {
    defmt::error!("watchdog: core1 stuck — sending 6F00 and resetting");
    let _ = ccid.send_response(&[0x6F, 0x00]).await;
    Timer::after_millis(50).await;
    cortex_m::peripheral::SCB::sys_reset()
}

// ─── RP2350-One main function ─────────────────────────────────────────────────

#[cfg(all(target_arch = "arm", feature = "rp2350_one_4m"))]
async fn run_one_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::rp2350_one::{Rp2350OneBoard, SPI_FREQ_HZ};
    use pico2hsm_firmware::board::{Board, LedController, LedStatus};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: RP2350-One initialising");

    // ── SPI bus initialisation ───────────────────────────────────────────────
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, spi0_cfg);

    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

    let mut board = Rp2350OneBoard::new(spi0, spi1);
    board.led().set_status(LedStatus::Busy);

    // ── Storage initialization (rp2350_one: internal QMI flash) ───────────────
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();

    let qmi_flash = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

    let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    let _ = fs.add_chip(pico2hsm_firmware::storage::AnyChip::SdCard(qmi));
    let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
    let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
    match ks.init() {
        Ok(()) => defmt::info!("KeyStore: initialized (rp2350_one internal flash)"),
        Err(_) => defmt::warn!("KeyStore: init failed — degraded mode (blank flash?)"),
    }
    debug_dump_storage(&ks);
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // ── USB CCID + CDC-ACM serial transport ─────────────────────────────────
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();

    let usb_driver = UsbDriver::new(p.USB, Irqs);

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;

    // USB descriptor buffers — must live for the duration of run_one_board.
    // Bumped to 512 for CDC+CCID.
    let mut config_descriptor_buf = [0u8; 512];
    let mut bos_descriptor_buf = [0u8; 256];
    let mut msos_descriptor_buf = [0u8; 256];
    let mut control_buf = [0u8; 64];

    let mut builder = UsbBuilder::new(
        usb_driver,
        usb_config,
        &mut config_descriptor_buf,
        &mut bos_descriptor_buf,
        &mut msos_descriptor_buf,
        &mut control_buf,
    );

    // Register the CCID class — allocates bulk-OUT, bulk-IN, interrupt-IN
    // endpoints and embeds the 54-byte CCID class descriptor.
    builder.handler(USB_SESSION_HANDLER.init(UsbSessionHandler));
    let mut ccid = CcidTransport::new(&mut builder);

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    // Finalise the USB device descriptor.
    let mut usb = builder.build();

    defmt::info!("pico2hsm (RP2350-One): USB CCID+CDC ready, entering main loop");
    board.led().set_status(LedStatus::Ready);

    // ── Init dispatcher on core0, then spawn core1 ─────────────────────────
    // The Dispatcher is initialized and keys loaded from flash on core0 (where
    // flash reads via XIP are safe).  A raw pointer is passed to core1 which
    // exclusively owns the Dispatcher after this point.
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    KEY_COUNT.store(
        dispatcher_ref.in_memory_key_count(),
        core::sync::atomic::Ordering::Relaxed,
    );
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
            // MSPLIM — hardware stack overflow detection for Core1.
            // MSPLIM at stack base — hardware UsageFault fires at exact boundary.
            // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
            #[cfg(target_arch = "arm")]
            unsafe {
                let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
                cortex_m::register::msplim::write(stack_bottom);
                // SHCSR bit 18 = USGFAULTENA
                (*cortex_m::peripheral::SCB::PTR)
                    .shcsr
                    .modify(|v| v | (1 << 18));
            }

            dispatcher_loop(dispatcher_send);
        },
    );

    // ── Concurrent USB + CCID command loop (core0) ───────────────────────────
    let usb_fut = usb.run();
    let ccid_fut = async {
        loop {
            // Wait for USB host to configure the device and announce card presence.
            ccid.wait_connected().await;

            // Inner loop: forward APDUs to core1 and relay responses.
            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let epoch = pico2hsm_firmware::SESSION_EPOCH
                            .load(core::sync::atomic::Ordering::SeqCst);
                        board.led().set_status(LedStatus::Busy);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let mut response =
                            match await_core1_response(&mut ccid, store, dispatcher_ptr).await {
                                Some(r) => r,
                                None => watchdog_reset(&mut ccid).await,
                            };
                        match send_and_wipe(&mut ccid, &mut response, epoch).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                cortex_m::asm::sev(); // wake core1 from WFE
                                let _ = recv_core1_response(store, dispatcher_ptr).await;
                                break;
                            }
                            Err(_) => {}
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let _ = recv_core1_response(store, dispatcher_ptr).await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    join(usb_fut, ccid_fut).await;
}

// ─── RP2350-Geek main function ────────────────────────────────────────────────

#[cfg(all(
    target_arch = "arm",
    any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard",)
))]
async fn run_geek_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::uart::{Config as UartConfig, Uart};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::rp2350_geek::Rp2350GeekBoard;
    use pico2hsm_firmware::board::{Board, LedController, LedStatus};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    // ── UART first — before security checks so failures are observable ────────
    // WHY EARLY: security_checks() runs a silent infinite spin if
    // check_debugger_attached() returns true (DHCSR C_DEBUGEN set by a prior
    // probe session).  Without serial output we can't distinguish that halt
    // from a clock/flash/allocator failure.
    // Partial field moves from `p` are fine within the owning function.
    // ── UART1 init for serial_debug macros ─────────────────────────────────
    // Must happen before any serial_println!/serial_fmt! calls.
    let _dbg = Uart::new_blocking(p.UART1, p.PIN_4, p.PIN_5, UartConfig::default());
    pico2hsm_firmware::serial_debug::uart1_write_bytes(b"\r\n\r\n");
    serial_println!("=== pico2hsm RP2350-Geek boot ===");
    serial_println!("UART1 GPIO4=TX GPIO5=RX 115200 8N1");

    // ── Security checks ──────────────────────────────────────────────────────
    serial_println!("security_checks()...");
    pico2hsm_firmware::security::boot::security_checks();
    serial_println!("security_checks() ok");

    // ── Allocator ────────────────────────────────────────────────────────────
    serial_println!("allocator init...");
    pico2hsm_firmware::allocator::init();
    serial_println!("allocator ok");

    // ── OTP ──────────────────────────────────────────────────────────────────
    serial_println!("OTP init...");
    let otp = pico2hsm_firmware::security::otp::Otp::new();
    let provisioned = otp.is_provisioned();
    let prod_mode = otp.is_production_mode();
    serial_fmt!(
        "OTP ok: provisioned={} production_mode={}",
        provisioned,
        prod_mode
    );
    defmt::info!(
        "OTP: provisioned={}, production_mode={}",
        provisioned,
        prod_mode
    );

    serial_println!("OTP derive_smk...");
    match pico2hsm_firmware::security::otp::derive_smk() {
        Ok(_) => serial_println!("derive_smk ok"),
        Err(_) => serial_println!("derive_smk failed (unprovisioned — continuing)"),
    }

    // ── CHECKPOINT 0 ─────────────────────────────────────────────────────────
    serial_println!("--- run_geek_board ---");
    defmt::info!("Board: RP2350-Geek initialising");

    // ── CHECKPOINT 1 — SPI buses ─────────────────────────────────────────────

    // SPI1: LCD bus — Async/DMA mode so flush() yields to the executor during
    // the ~17 ms 63 KB framebuffer transfer, keeping USB alive.
    serial_println!("SPI1 init (LCD async DMA)...");
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new(
        p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.DMA_CH3, p.DMA_CH4, Irqs, spi1_cfg,
    );
    serial_println!("SPI1 ok");

    // ── CHECKPOINT 2 — board struct (LCD only, SPI0 not in board) ────────────
    serial_println!("Board init...");
    let mut board = Rp2350GeekBoard::new(spi1);
    board.led().set_status(LedStatus::Busy);
    serial_println!("Board ok");
    // ── CHECKPOINT 3 — USB driver ────────────────────────────────────────────
    serial_println!("USB driver init...");
    let usb_driver = UsbDriver::new(p.USB, Irqs);
    serial_println!("USB driver ok");

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;
    serial_fmt!("USB VID={:#06x} PID={:#06x}", USB_VID, USB_PID);

    // ── CHECKPOINT 3.5 — CDC-ACM state (must be before descriptor buffers) ───
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();

    // ── CHECKPOINT 4 — USB descriptor builder ───────────────────────────────
    serial_println!("USB builder init...");
    let mut config_descriptor_buf = [0u8; 512]; // bump to 512 for CDC+CCID
    let mut bos_descriptor_buf = [0u8; 256];
    let mut msos_descriptor_buf = [0u8; 256];
    let mut control_buf = [0u8; 64];

    let mut builder = UsbBuilder::new(
        usb_driver,
        usb_config,
        &mut config_descriptor_buf,
        &mut bos_descriptor_buf,
        &mut msos_descriptor_buf,
        &mut control_buf,
    );
    serial_println!("USB builder ok");

    // ── CHECKPOINT 5 — CCID class registration ───────────────────────────────
    serial_println!("CCID class register...");
    builder.handler(USB_SESSION_HANDLER.init(UsbSessionHandler));
    let mut ccid = CcidTransport::new(&mut builder);
    serial_println!("CCID class ok");

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    // ── CHECKPOINT 6 — finalise USB device ──────────────────────────────────
    serial_println!("USB device build...");
    let mut usb = builder.build();
    serial_println!("USB device ok");

    board.led().set_status(LedStatus::Ready);

    // ── Storage initialization ──────────────────────────────────────────────
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();

    // rp2350_geek_sdcard: SD card keystore on SPI0 (GPIO18/19/20, CS=GPIO23).
    #[cfg(feature = "rp2350_geek_sdcard")]
    let store: &'static mut _ = {
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::blocking_mutex::Mutex;
        use static_cell::StaticCell;

        serial_println!("SD card init (SPI0 CS=23)...");

        // SPI0 at 400 kHz — SD spec requires ≤400 kHz for card identification.
        let mut spi0_cfg = SpiConfig::default();
        spi0_cfg.frequency = 400_000;
        spi0_cfg.phase = Phase::CaptureOnFirstTransition;
        spi0_cfg.polarity = Polarity::IdleLow;
        let spi0_bus = Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, spi0_cfg);

        // Enable internal pull-up on MISO (GPIO20).  SD cards require a pull-up
        // on DO (MISO) — the card's output is high-impedance until SPI mode.
        embassy_rp::pac::PADS_BANK0
            .gpio(20)
            .modify(|w| w.set_pue(true));

        // Wrap SPI0 in a shared-bus SpiDevice with CS=GPIO23.
        static SPI0_BUS: StaticCell<
            Mutex<
                CriticalSectionRawMutex,
                core::cell::RefCell<
                    Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
                >,
            >,
        > = StaticCell::new();
        let spi0_bus_ref = SPI0_BUS.init(Mutex::new(core::cell::RefCell::new(spi0_bus)));
        let sd_cs = Output::new(p.PIN_23, Level::High);
        let spi_device =
            embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice::new(spi0_bus_ref, sd_cs);

        let delay = embassy_time::Delay;
        let sd_chip = pico2hsm_firmware::storage::sdcard::SdCardFlash::new(spi_device, delay)
            .expect("SD card init failed — is a card inserted?");
        serial_println!("SD card detected");

        // Card identified — raise SPI clock from 400 kHz to 25 MHz for data transfers.
        spi0_bus_ref.lock(|bus| {
            let mut fast_cfg = SpiConfig::default();
            fast_cfg.frequency = 25_000_000;
            fast_cfg.phase = Phase::CaptureOnFirstTransition;
            fast_cfg.polarity = Polarity::IdleLow;
            bus.borrow_mut().set_config(&fast_cfg);
        });
        serial_println!("SPI0 clock raised to 25 MHz");

        let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        fs.add_chip(sd_chip).expect("add SD chip");
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => serial_println!("KeyStore ok (SD card)"),
            Err(_) => serial_println!("KeyStore init failed (SD)"),
        }
        KEYSTORE_CELL.init(ks)
    };

    // rp2350_geek_16m: QMI flash keystore (upper 2 MB of 16 MB QSPI flash).
    #[cfg(feature = "rp2350_geek_16m")]
    let store: &'static mut _ = {
        serial_println!("QMI flash init...");
        let qmi_flash = embassy_rp::flash::Flash::<
            _,
            embassy_rp::flash::Blocking,
            { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
        >::new_blocking(p.FLASH);
        let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

        let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        let _ = fs.add_chip(qmi);
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => serial_println!("KeyStore ok (QMI flash)"),
            Err(_) => serial_println!("KeyStore init failed (QMI)"),
        }
        KEYSTORE_CELL.init(ks)
    };
    serial_println!("KeyStore ready");

    // Set provisioning status for display.
    // (qmi_ok/sd_ok left as None — geek board doesn't track individual store health yet)

    // ── CHECKPOINT 7 — init dispatcher on core0, spawn core1 ──────────────
    serial_println!("Dispatcher init_in_place...");
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    serial_println!("Loading keys...");
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    KEY_COUNT.store(
        dispatcher_ref.in_memory_key_count(),
        core::sync::atomic::Ordering::Relaxed,
    );
    serial_println!("Keys loaded, spawning core1...");
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
            // MSPLIM — hardware stack overflow detection for Core1.
            // MSPLIM at stack base — hardware UsageFault fires at exact boundary.
            // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
            #[cfg(target_arch = "arm")]
            unsafe {
                let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
                cortex_m::register::msplim::write(stack_bottom);
                // SHCSR bit 18 = USGFAULTENA
                (*cortex_m::peripheral::SCB::PTR)
                    .shcsr
                    .modify(|v| v | (1 << 18));
            }

            dispatcher_loop(dispatcher_send);
        },
    );
    serial_println!("Core1 spawned, starting USB+CCID join...");

    let usb_fut = usb.run();

    use pico2hsm_firmware::display::{
        DisplayState, LastOperation, ScreenLayout, ScreensaverState, LAST_OP_DISPLAY_SECS,
        SCREENSAVER_TIMEOUT_SECS,
    };
    let layout = ScreenLayout::geek_240x135();

    let mut display_state = DisplayState::new();
    display_state.status = LedStatus::Ready;
    display_state.provisioned = provisioned;
    display_state.key_count = KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let mut last_activity = embassy_time::Instant::now();
    let mut screensaver = ScreensaverState::Active;

    let ccid_fut = async {
        // Render the full UI at boot (replaces the solid green from set_status).
        serial_println!("Rendering boot UI...");
        pico2hsm_firmware::display::render(board.led(), &display_state, &layout);
        serial_println!("Flushing display...");
        board.led().flush().await;
        serial_println!("Display flushed ok");

        loop {
            serial_println!("waiting for USB connect...");
            ccid.wait_connected().await;
            serial_println!("USB connected");
            display_state.status = LedStatus::Ready;
            pico2hsm_firmware::display::render(board.led(), &display_state, &layout);
            board.led().flush().await;
            last_activity = embassy_time::Instant::now();
            screensaver = ScreensaverState::Active;

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let epoch = pico2hsm_firmware::SESSION_EPOCH
                            .load(core::sync::atomic::Ordering::SeqCst);
                        let now = embassy_time::Instant::now();
                        if screensaver == ScreensaverState::Sleeping {
                            screensaver = ScreensaverState::Active;
                            board.led().backlight_on();
                        }
                        if now.duration_since(last_activity).as_secs()
                            >= SCREENSAVER_TIMEOUT_SECS as u64
                            && screensaver == ScreensaverState::Active
                        {
                            screensaver = ScreensaverState::Sleeping;
                            board.led().backlight_off();
                        }
                        last_activity = now;

                        display_state.status = LedStatus::Busy;
                        pico2hsm_firmware::display::render(board.led(), &display_state, &layout);
                        board.led().flush().await;

                        let apdu_ins = apdu_bytes.get(1).copied().unwrap_or(0);
                        let apdu_p1 = apdu_bytes.get(2).copied().unwrap_or(0);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        cortex_m::asm::sev(); // wake core1 from WFE

                        // Wait for core1 response (with time extensions every 1.5s)
                        let mut response =
                            match await_core1_response(&mut ccid, store, dispatcher_ptr).await {
                                Some(r) => r,
                                None => watchdog_reset(&mut ccid).await,
                            };
                        match send_and_wipe(&mut ccid, &mut response, epoch).await {
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs =
                                    embassy_time::Instant::now().as_secs() as u32;
                                // Update key count from core1 atomic.
                                display_state.key_count =
                                    KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                // Derive last_op and authenticated from APDU INS byte + SW.
                                let sw_ok = response.len() >= 2
                                    && response[response.len() - 2] == 0x90
                                    && response[response.len() - 1] == 0x00;
                                if sw_ok {
                                    match apdu_ins {
                                        0x20 => {
                                            display_state.authenticated = true;
                                            display_state.last_op = Some((
                                                LastOperation::Verify,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x50 => {
                                            // SC-HSM INITIALIZE
                                            display_state.authenticated = false;
                                            display_state.last_op = Some((
                                                LastOperation::Initialize,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x47 | 0x48 => {
                                            // PIV/OpenPGP GENERATE KEYPAIR (0x47) or SC-HSM GENERATE KEY (0x48)
                                            display_state.last_op = Some((
                                                LastOperation::KeyGen,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0xE4 => {
                                            // SC-HSM DELETE FILE
                                            display_state.last_op = Some((
                                                LastOperation::DeleteKey,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x2A => {
                                            // PSO: sign (P1=0x9E) or decrypt (P1=0x80)
                                            if apdu_p1 == 0x9E {
                                                display_state.last_op = Some((
                                                    LastOperation::Sign,
                                                    display_state.uptime_secs,
                                                ));
                                            } else if apdu_p1 == 0x80 {
                                                display_state.last_op = Some((
                                                    LastOperation::Decrypt,
                                                    display_state.uptime_secs,
                                                ));
                                            }
                                        }
                                        0x62 => {
                                            // SC-HSM DERIVE ASYM / ECDH
                                            display_state.last_op = Some((
                                                LastOperation::Ecdh,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        _ => {}
                                    }
                                }
                                // SELECT always resets auth state regardless of SW.
                                if apdu_ins == 0xA4 {
                                    display_state.authenticated = false;
                                }
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time)
                                        >= LAST_OP_DISPLAY_SECS
                                    {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    pico2hsm_firmware::display::render(
                                        board.led(),
                                        &display_state,
                                        &layout,
                                    );
                                    board.led().flush().await;
                                }
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                cortex_m::asm::sev(); // wake core1 from WFE
                                let _ = recv_core1_response(store, dispatcher_ptr).await;
                                display_state.status = LedStatus::Ready;
                                break;
                            }
                            Err(_) => {}
                        }
                    }

                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let _ = recv_core1_response(store, dispatcher_ptr).await;
                        display_state.status = LedStatus::Ready;
                        break;
                    }

                    Err(_) => {}
                }
            }
        }
    };

    join(usb_fut, ccid_fut).await;
}

// ─── Pico 2 main function ─────────────────────────────────────────────────────

#[cfg(all(target_arch = "arm", feature = "pico2_4m"))]
async fn run_pico2_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::pico2::{Pico2Board, SPI_FREQ_HZ};
    use pico2hsm_firmware::board::{Board, LedController, LedStatus};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: Pico 2 initialising");

    // ── SPI bus initialisation ───────────────────────────────────────────────
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, spi0_cfg);

    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

    let mut board = Pico2Board::new(p.PIN_25, spi0, spi1);
    board.led().set_status(LedStatus::Busy);

    // ── Storage initialization (pico2_4m: RP2350 internal QMI flash) ─────────
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();

    let qmi_flash = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

    let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    let _ = fs.add_chip(qmi);
    let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
    let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
    match ks.init() {
        Ok(()) => defmt::info!("KeyStore: initialized (pico2_4m internal flash)"),
        Err(_) => defmt::warn!("KeyStore: init failed — degraded mode (blank flash?)"),
    }
    debug_dump_storage(&ks);
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // ── USB CCID + CDC-ACM serial transport ─────────────────────────────────
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();

    let usb_driver = UsbDriver::new(p.USB, Irqs);

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;

    let mut config_descriptor_buf = [0u8; 512]; // bump to 512 for CDC+CCID
    let mut bos_descriptor_buf = [0u8; 256];
    let mut msos_descriptor_buf = [0u8; 256];
    let mut control_buf = [0u8; 64];

    let mut builder = UsbBuilder::new(
        usb_driver,
        usb_config,
        &mut config_descriptor_buf,
        &mut bos_descriptor_buf,
        &mut msos_descriptor_buf,
        &mut control_buf,
    );

    builder.handler(USB_SESSION_HANDLER.init(UsbSessionHandler));

    let mut ccid = CcidTransport::new(&mut builder);

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    let mut usb = builder.build();

    defmt::info!("pico2hsm (Pico 2): USB CCID+CDC ready, entering main loop");
    board.led().set_status(LedStatus::Ready);

    // ── Init dispatcher on core0, then spawn core1 ─────────────────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    KEY_COUNT.store(
        dispatcher_ref.in_memory_key_count(),
        core::sync::atomic::Ordering::Relaxed,
    );
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    defmt::info!("core0: spawning core1");
    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
            // MSPLIM — hardware stack overflow detection for Core1.
            // MSPLIM at stack base — hardware UsageFault fires at exact boundary.
            // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
            #[cfg(target_arch = "arm")]
            unsafe {
                let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
                cortex_m::register::msplim::write(stack_bottom);
                // SHCSR bit 18 = USGFAULTENA
                (*cortex_m::peripheral::SCB::PTR)
                    .shcsr
                    .modify(|v| v | (1 << 18));
            }

            dispatcher_loop(dispatcher_send);
        },
    );
    defmt::info!("core0: core1 spawned, building usb_fut");

    let usb_fut = usb.run();
    defmt::info!("core0: usb_fut created, building ccid_fut");
    let ccid_fut = async {
        defmt::info!("core0: ccid_fut: starting wait_connected");
        loop {
            ccid.wait_connected().await;
            defmt::info!("core0: USB connected");

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let epoch = pico2hsm_firmware::SESSION_EPOCH
                            .load(core::sync::atomic::Ordering::SeqCst);
                        board.led().set_status(LedStatus::Busy);
                        // No defmt logging here — the RTT buffer fills from trace-level
                        // embassy_rp USB logs; any defmt call here blocks Core0 before
                        // the APDU reaches Core1, causing a permanent hang.
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let mut response =
                            match await_core1_response(&mut ccid, store, dispatcher_ptr).await {
                                Some(r) => r,
                                None => watchdog_reset(&mut ccid).await,
                            };
                        match send_and_wipe(&mut ccid, &mut response, epoch).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                cortex_m::asm::sev(); // wake core1 from WFE
                                let _ = recv_core1_response(store, dispatcher_ptr).await;
                                break;
                            }
                            Err(_) => {}
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let _ = recv_core1_response(store, dispatcher_ptr).await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    join(usb_fut, ccid_fut).await;
}

// ─── Waveshare RP2350-LCD-1.47-B main function ───────────────────────────────

#[cfg(all(
    target_arch = "arm",
    any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
    )
))]
/// Initialise the SD card keystore on SPI1 in its own stack frame.
///
/// All SPI bus setup, SD card probe, CMD0 warmup, and keystore mount happen
/// here.  When this function returns, those temporaries (SPI config, SdCard
/// driver, KeyFilesystem, StorageManager) are freed — reclaiming ~2 KB of
/// stack that would otherwise persist through the entire async main loop.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard"))]
fn init_sd_keystore(
    spi1: embassy_rp::Peri<'static, embassy_rp::peripherals::SPI1>,
    sck: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_10>,
    mosi: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_11>,
    miso: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_12>,
    cs_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_15>,
    smk: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> &'static mut pico2hsm_firmware::storage::BoardKeyStore {
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::blocking_mutex::Mutex;
    use static_cell::StaticCell;

    defmt::info!("SD card init (SPI1, CS=GPIO15)");

    // SPI1 bus at 400 kHz — SD spec requires ≤400 kHz for card identification.
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = 400_000;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let mut spi1_bus = Spi::new_blocking(spi1, sck, mosi, miso, spi1_cfg);

    // Enable internal pull-up on MISO (GPIO12) — SD card DO is high-impedance
    // until SPI mode is entered.
    embassy_rp::pac::PADS_BANK0
        .gpio(12)
        .modify(|w| w.set_pue(true));

    // SD spec requires ≥74 clock cycles with CS high before first command.
    {
        use embedded_hal::spi::SpiBus;
        let _ = spi1_bus.write(&[0xFF; 80]);
    }

    // Wrap SPI1 in a shared-bus SpiDevice with CS + CriticalSectionRawMutex.
    static SPI1_BUS: StaticCell<
        Mutex<
            CriticalSectionRawMutex,
            core::cell::RefCell<
                Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
            >,
        >,
    > = StaticCell::new();
    let spi1_bus_ref = SPI1_BUS.init(Mutex::new(core::cell::RefCell::new(spi1_bus)));
    let sd_cs = Output::new(cs_pin, Level::High);
    let spi_device =
        embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice::new(spi1_bus_ref, sd_cs);

    // SD card probe — CMD0 warmup pre-transitions the card into SPI mode
    // before embedded-sdmmc's acquire() sequence.
    let delay = embassy_time::Delay;
    let card = embedded_sdmmc::SdCard::new(spi_device, delay);
    {
        use embedded_hal::spi::SpiDevice as _;
        card.spi(|spi| {
            let cmd0 = [0x40u8, 0x00, 0x00, 0x00, 0x00, 0x95];
            let _ = spi.write(&cmd0);
            for _ in 0..10u8 {
                let mut resp = [0xFFu8; 1];
                let _ = spi.transfer_in_place(&mut resp);
                if resp[0] != 0xFF {
                    break;
                }
            }
        });
    }

    let sd_chip = match card.num_bytes() {
        Ok(total_bytes) => {
            defmt::info!("SD card: {} MiB", total_bytes / (1024 * 1024));
            let capacity_bytes = total_bytes.saturating_sub(4096);
            pico2hsm_firmware::storage::sdcard::SdCardFlash::from_initialized(card, capacity_bytes)
        }
        Err(_) => {
            defmt::error!("SD card init FAILED — halting");
            loop {
                cortex_m::asm::wfi();
            }
        }
    };

    let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    fs.add_chip(sd_chip).expect("add SD chip");
    let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
    let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
    match ks.init() {
        Ok(()) => defmt::info!("KeyStore: initialized (SD card)"),
        Err(_) => defmt::warn!("KeyStore: init failed — SD card degraded"),
    }
    KEYSTORE_CELL.init(ks)
}

#[cfg(any(
    feature = "waveshare_rp2350_lcd_16m",
    feature = "waveshare_rp2350_lcd_sdcard"
))]
async fn run_waveshare_lcd_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::pio::Pio;
    use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::waveshare_rp2350_lcd::{
        init_lcd, update_status_display, PioWs2812Writer, WaveshareRp2350LcdBoard, SPI_FREQ_HZ,
    };
    use pico2hsm_firmware::board::{Board, LedStatus};
    use pico2hsm_firmware::display::{
        DisplayState, LastOperation, ScreensaverState, LAST_OP_DISPLAY_SECS,
        SCREENSAVER_TIMEOUT_SECS,
    };
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    // ── UART0 init for serial_debug macros (GPIO0=TX, GPIO1=RX, 115200 8N1) ──
    use embassy_rp::uart::{Config as UartConfig, Uart};
    let _dbg = Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, UartConfig::default());
    pico2hsm_firmware::serial_debug::uart1_write_bytes(b"\r\n\r\n");
    serial_println!("=== pico2hsm Waveshare RP2350-LCD-1.47-B boot ===");
    serial_println!("UART0 GPIO0=TX GPIO1=RX 115200 8N1");

    defmt::info!("Board: Waveshare RP2350-LCD-1.47-B initialising");

    // ── SPI0: LCD bus (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO4) ─────────────────
    // Async/DMA mode so flush_display() yields to the executor during the
    // 110 KB framebuffer transfer (~22 ms), keeping USB alive.
    // DMA_CH1=TX, DMA_CH2=RX (RX is unused — LCD is write-only).
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new(
        p.SPI0, p.PIN_18, p.PIN_19, p.PIN_4, p.DMA_CH1, p.DMA_CH2, Irqs, spi0_cfg,
    );

    // ── SPI1: SD card bus (SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12) ─────────────
    // For waveshare_rp2350_lcd_sdcard, SPI1 is consumed by the SD card keystore
    // and is NOT passed to the board struct.
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let spi1 = {
        let mut spi1_cfg = SpiConfig::default();
        spi1_cfg.frequency = SPI_FREQ_HZ;
        spi1_cfg.phase = Phase::CaptureOnFirstTransition;
        spi1_cfg.polarity = Polarity::IdleLow;
        Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg)
    };

    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let mut board = WaveshareRp2350LcdBoard::new(spi0, spi1);

    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let mut board = WaveshareRp2350LcdBoard::new_lcd_only(spi0);

    // ── LCD control GPIO pins ─────────────────────────────────────────────────
    // DC=GPIO16, CS=GPIO17, RST=GPIO20, BL=GPIO21 per board schematic.
    let mut dc = Output::new(p.PIN_16, Level::Low);
    let mut cs = Output::new(p.PIN_17, Level::High);
    let mut rst = Output::new(p.PIN_20, Level::High);
    let mut bl = Output::new(p.PIN_21, Level::Low);

    // ── WS2812B on GPIO22 via PIO0 SM0 / DMA_CH0 ────────────────────────────
    let Pio {
        mut common, sm0, ..
    } = Pio::new(p.PIO0, Irqs);
    let ws2812_program = PioWs2812Program::new(&mut common);
    let ws2812 = PioWs2812::new(&mut common, sm0, p.DMA_CH0, Irqs, p.PIN_22, &ws2812_program);
    let mut ws2812_writer = PioWs2812Writer::new(ws2812);

    // ── LCD hardware init — must happen before USB enumeration ───────────────
    let mut display_state = DisplayState::new();
    display_state.status = LedStatus::Busy;
    init_lcd(&mut board.spi0, &mut dc, &mut cs, &mut rst, &mut bl).await;
    {
        let (disp, spi) = board.led_and_spi0_mut();
        update_status_display(
            disp,
            spi,
            &mut dc,
            &mut cs,
            &mut ws2812_writer,
            &display_state,
        )
        .await;
    }

    // ── Storage initialisation ─────────────────────────────────────────────

    // Common: derive SMK from OTP.
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();

    // waveshare_rp2350_lcd_sdcard: single SD card keystore on SPI1.
    // Extracted to a separate function so SPI1 bus, SdCard driver, and
    // intermediate buffers live in their own stack frame and are freed
    // before USB init begins.
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let store: &'static mut _ =
        init_sd_keystore(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.PIN_15, smk);

    // waveshare_rp2350_lcd_16m: internal QMI flash keystore (upper 2 MB).
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let store: &'static mut _ = {
        let qmi_flash = embassy_rp::flash::Flash::<
            _,
            embassy_rp::flash::Blocking,
            { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
        >::new_blocking(p.FLASH);
        let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

        let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        let _ = fs.add_chip(qmi);
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => {
                defmt::info!("KeyStore: initialized (waveshare_rp2350_lcd_16m internal flash)")
            }
            Err(_) => defmt::warn!("KeyStore: init failed — degraded mode (blank flash?)"),
        }
        KEYSTORE_CELL.init(ks)
    };

    // Set provisioning status for display.
    display_state.provisioned = pico2hsm_firmware::security::otp::Otp::new().is_provisioned();

    // ── USB CCID + CDC-ACM serial transport ─────────────────────────────────
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();

    let usb_driver = UsbDriver::new(p.USB, Irqs);

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;

    let mut config_descriptor_buf = [0u8; 512];
    let mut bos_descriptor_buf = [0u8; 256];
    let mut msos_descriptor_buf = [0u8; 256];
    let mut control_buf = [0u8; 64];

    let mut builder = UsbBuilder::new(
        usb_driver,
        usb_config,
        &mut config_descriptor_buf,
        &mut bos_descriptor_buf,
        &mut msos_descriptor_buf,
        &mut control_buf,
    );

    builder.handler(USB_SESSION_HANDLER.init(UsbSessionHandler));

    let mut ccid = CcidTransport::new(&mut builder);

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    let mut usb = builder.build();

    display_state.status = LedStatus::Ready;
    {
        let (disp, spi) = board.led_and_spi0_mut();
        update_status_display(
            disp,
            spi,
            &mut dc,
            &mut cs,
            &mut ws2812_writer,
            &display_state,
        )
        .await;
    }

    // ── Init dispatcher on core0, then spawn core1 ─────────────────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    KEY_COUNT.store(
        dispatcher_ref.in_memory_key_count(),
        core::sync::atomic::Ordering::Relaxed,
    );
    display_state.key_count = dispatcher_ref.in_memory_key_count();
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
            // MSPLIM — hardware stack overflow detection for Core1.
            // MSPLIM at stack base — hardware UsageFault fires at exact boundary.
            // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
            #[cfg(target_arch = "arm")]
            unsafe {
                let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
                cortex_m::register::msplim::write(stack_bottom);
                // SHCSR bit 18 = USGFAULTENA
                (*cortex_m::peripheral::SCB::PTR)
                    .shcsr
                    .modify(|v| v | (1 << 18));
            }

            dispatcher_loop(dispatcher_send);
        },
    );

    // ── Concurrent USB + CCID command loop (core0) ───────────────────────────
    let usb_fut = usb.run();

    let mut last_activity = embassy_time::Instant::now();
    let mut screensaver = ScreensaverState::Active;

    let ccid_fut = async {
        loop {
            ccid.wait_connected().await;
            defmt::info!("RP2350-LCD-1.47-B: USB connected");
            display_state.status = LedStatus::Ready;
            {
                let (disp, spi) = board.led_and_spi0_mut();
                update_status_display(
                    disp,
                    spi,
                    &mut dc,
                    &mut cs,
                    &mut ws2812_writer,
                    &display_state,
                )
                .await;
            }
            last_activity = embassy_time::Instant::now();
            screensaver = ScreensaverState::Active;

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let epoch = pico2hsm_firmware::SESSION_EPOCH
                            .load(core::sync::atomic::Ordering::SeqCst);
                        let now = embassy_time::Instant::now();
                        if screensaver == ScreensaverState::Sleeping {
                            screensaver = ScreensaverState::Active;
                            display_state.status = LedStatus::Ready;
                            let (disp, spi) = board.led_and_spi0_mut();
                            update_status_display(
                                disp,
                                spi,
                                &mut dc,
                                &mut cs,
                                &mut ws2812_writer,
                                &display_state,
                            )
                            .await;
                        }
                        if now.duration_since(last_activity).as_secs()
                            >= SCREENSAVER_TIMEOUT_SECS as u64
                            && screensaver == ScreensaverState::Active
                        {
                            screensaver = ScreensaverState::Sleeping;
                            use pico2hsm_firmware::board::waveshare_rp2350_lcd::{
                                Grb, Ws2812Writer,
                            };
                            let (disp, spi) = board.led_and_spi0_mut();
                            pico2hsm_firmware::board::waveshare_rp2350_lcd::fill_screen(
                                spi, &mut dc, &mut cs, 0x0000,
                            )
                            .await;
                            ws2812_writer.write_pixel(Grb::OFF).await;
                            let _ = disp;
                        }
                        last_activity = now;
                        display_state.status = LedStatus::Busy;
                        {
                            let (disp, spi) = board.led_and_spi0_mut();
                            update_status_display(
                                disp,
                                spi,
                                &mut dc,
                                &mut cs,
                                &mut ws2812_writer,
                                &display_state,
                            )
                            .await;
                        }
                        let apdu_ins = apdu_bytes.get(1).copied().unwrap_or(0);
                        let apdu_p1 = apdu_bytes.get(2).copied().unwrap_or(0);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                                              // Wait for response with time-extension support.
                        let mut response =
                            match await_core1_response(&mut ccid, store, dispatcher_ptr).await {
                                Some(r) => r,
                                None => watchdog_reset(&mut ccid).await,
                            };
                        match send_and_wipe(&mut ccid, &mut response, epoch).await {
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs =
                                    embassy_time::Instant::now().as_secs() as u32;
                                // Update key count from core1 atomic.
                                display_state.key_count =
                                    KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                // Derive last_op and authenticated from APDU INS byte + SW.
                                let sw_ok = response.len() >= 2
                                    && response[response.len() - 2] == 0x90
                                    && response[response.len() - 1] == 0x00;
                                if sw_ok {
                                    match apdu_ins {
                                        0x20 => {
                                            display_state.authenticated = true;
                                            display_state.last_op = Some((
                                                LastOperation::Verify,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x50 => {
                                            // SC-HSM INITIALIZE
                                            display_state.authenticated = false;
                                            display_state.last_op = Some((
                                                LastOperation::Initialize,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x47 | 0x48 => {
                                            // PIV/OpenPGP GENERATE KEYPAIR (0x47) or SC-HSM GENERATE KEY (0x48)
                                            display_state.last_op = Some((
                                                LastOperation::KeyGen,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0xE4 => {
                                            // SC-HSM DELETE FILE
                                            display_state.last_op = Some((
                                                LastOperation::DeleteKey,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        0x2A => {
                                            // PSO: sign (P1=0x9E) or decrypt (P1=0x80)
                                            if apdu_p1 == 0x9E {
                                                display_state.last_op = Some((
                                                    LastOperation::Sign,
                                                    display_state.uptime_secs,
                                                ));
                                            } else if apdu_p1 == 0x80 {
                                                display_state.last_op = Some((
                                                    LastOperation::Decrypt,
                                                    display_state.uptime_secs,
                                                ));
                                            }
                                        }
                                        0x62 => {
                                            // SC-HSM DERIVE ASYM / ECDH
                                            display_state.last_op = Some((
                                                LastOperation::Ecdh,
                                                display_state.uptime_secs,
                                            ));
                                        }
                                        _ => {}
                                    }
                                }
                                // SELECT always resets auth state regardless of SW.
                                if apdu_ins == 0xA4 {
                                    display_state.authenticated = false;
                                }
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time)
                                        >= LAST_OP_DISPLAY_SECS
                                    {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    let (disp, spi) = board.led_and_spi0_mut();
                                    update_status_display(
                                        disp,
                                        spi,
                                        &mut dc,
                                        &mut cs,
                                        &mut ws2812_writer,
                                        &display_state,
                                    )
                                    .await;
                                }
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                cortex_m::asm::sev(); // wake core1 from WFE
                                let _ = recv_core1_response(store, dispatcher_ptr).await;
                                display_state.status = LedStatus::Ready;
                                break;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        cortex_m::asm::sev(); // wake core1 from WFE
                        let _ = recv_core1_response(store, dispatcher_ptr).await;
                        display_state.status = LedStatus::Ready;
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    join(usb_fut, ccid_fut).await;
}

// ─── Storage namespace debug dump ────────────────────────────────────────────

/// Dump a summary of keystore contents to RTT at startup.
///
/// Logs: total key count, and for each key the u32 ID broken down into
/// partition/applet/proto_ref fields.  Runs on core0 before core1 is spawned,
/// so defmt is safe here.
///
/// This is a debug diagnostic; it never logs raw key material.
#[cfg(target_arch = "arm")]
fn debug_dump_storage(ks: &pico2hsm_firmware::storage::BoardKeyStore) {
    use pico2hsm_firmware::storage::KeyStore;
    let keys = ks.enumerate_keys();
    defmt::info!("=== storage namespace dump: {} key(s) ===", keys.len());
    for kid in keys.iter() {
        let partition = kid.partition();
        let applet = kid.applet_byte();
        let proto = kid.proto_ref();
        defmt::info!(
            "  KeyId(0x{:08X}): partition={} applet={} proto_ref=0x{:02X}",
            kid.0,
            partition,
            applet,
            proto,
        );
    }
    defmt::info!("=== end storage namespace dump ===");
}

// ─── Host stub ────────────────────────────────────────────────────────────────

/// No-op entry point for non-ARM builds (e.g., `cargo test --target x86_64`).
/// The firmware is only meaningful on ARM; this stub allows the binary target
/// to compile without errors during host-side testing.
#[cfg(not(target_arch = "arm"))]
fn main() {}
