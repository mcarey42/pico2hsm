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
//! - `rp2350_one_4m` / `rp2350_one_16m` → `Rp2350OneBoard`
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

#[allow(unused_imports)]
use pico2hsm_firmware::{serial_println, serial_print, serial_fmt};
#[cfg(target_arch = "arm")]
use defmt_rtt as _;
#[cfg(target_arch = "arm")]
use embassy_executor::Spawner;
#[cfg(target_arch = "arm")]
use embassy_time::Timer;
#[cfg(target_arch = "arm")]
use panic_probe as _;

#[cfg(target_arch = "arm")]
use core::ptr::addr_of_mut;
#[cfg(target_arch = "arm")]
extern "C" {
    static __ebss: u8;
}
#[cfg(target_arch = "arm")]
use embassy_rp::multicore::{Stack, spawn_core1};
#[cfg(target_arch = "arm")]
use embassy_rp::spinlock_mutex::SpinlockRawMutex;
#[cfg(target_arch = "arm")]
use embassy_sync::channel::Channel;
#[cfg(target_arch = "arm")]
use static_cell::StaticCell;

// ─── Core1 stack and executor (ARM only) ─────────────────────────────────────

/// Stack for the core1 Embassy executor.  Debug-mode peak usage ~125 KB:
/// ScHsmState holds ~38 KB inline, plus the INITIALIZE handler in debug
/// builds accumulates PBKDF2 intermediates, P-256 keygen temporaries,
/// multiple KeyObject / EcKeyPair / EfEntry copies, and 4 KB response
/// buffers without reusing stack slots (opt-level=1 no NRVO).
/// 160 KB gives ~1.3× headroom; release builds use far less.
/// NOTE: Increasing beyond 160 KB squeezes Core0's stack below 64 KB,
/// which is needed for init_in_place (ScHsm::new ~40 KB temporary).
#[cfg(target_arch = "arm")]
static mut CORE1_STACK: Stack<163840> = Stack::new();
#[cfg(target_arch = "arm")]
static CORE1_EXECUTOR: StaticCell<embassy_executor::Executor> = StaticCell::new();

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
/// asserts `core_id == 0`).  Instead, the dispatcher queues flash ops and
/// sends them to core0 via `FLASH_REQ` after each APDU dispatch completes.
#[cfg(target_arch = "arm")]
enum FlashOp {
    /// Encrypt and persist a key object to flash.
    SaveKey(pico2hsm_firmware::security::key_management::KeyObject),
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

/// A `KeyStore` implementation that queues flash operations instead of
/// executing them immediately.  Used by the core1 dispatcher to collect
/// flash ops during APDU processing, then drain them to core0 afterwards.
#[cfg(target_arch = "arm")]
struct FlashQueueKeyStore {
    ops: heapless::Vec<FlashOp, 8>,
}

#[cfg(target_arch = "arm")]
impl FlashQueueKeyStore {
    fn new() -> Self {
        FlashQueueKeyStore {
            ops: heapless::Vec::new(),
        }
    }

    fn drain(&mut self) -> heapless::Vec<FlashOp, 8> {
        core::mem::replace(&mut self.ops, heapless::Vec::new())
    }
}

#[cfg(target_arch = "arm")]
impl pico2hsm_firmware::storage::KeyStore for FlashQueueKeyStore {
    fn save_key(
        &mut self,
        obj: &pico2hsm_firmware::security::key_management::KeyObject,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        CORE1_PROGRESS.store(70, core::sync::atomic::Ordering::Relaxed);
        // Clone the KeyObject by reconstructing it field by field.
        let mut copy = pico2hsm_firmware::security::key_management::KeyObject::new(
            obj.key_type,
            obj.key_id,
            obj.owner,
            obj.algorithm,
        );
        CORE1_PROGRESS.store(71, core::sync::atomic::Ordering::Relaxed);
        copy.key_domain = obj.key_domain;
        copy.key_flags = obj.key_flags;
        copy.use_count = obj.use_count;
        copy.generation = obj.generation;
        copy.timestamp_ms = obj.timestamp_ms;
        let _ = copy.private_key.extend_from_slice(&obj.private_key);
        let _ = copy.public_key.extend_from_slice(&obj.public_key);
        CORE1_PROGRESS.store(72, core::sync::atomic::Ordering::Relaxed);
        let _ = self.ops.push(FlashOp::SaveKey(copy));
        CORE1_PROGRESS.store(73, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn fetch_key(
        &mut self,
        _key_id: pico2hsm_core::key::KeyId,
    ) -> Result<Option<pico2hsm_firmware::security::key_management::KeyObject>, pico2hsm_core::error::HsmError>
    {
        // Keys are already in the Dispatcher's in-memory state.
        Ok(None)
    }

    fn erase_key(
        &mut self,
        key_id: pico2hsm_core::key::KeyId,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        let _ = self.ops.push(FlashOp::EraseKey(key_id));
        Ok(())
    }

    fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
        let _ = self.ops.push(FlashOp::WipeAll);
        Ok(())
    }

    fn wipe_by_owner(
        &mut self,
        owner: pico2hsm_core::key::AppletId,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        let _ = self.ops.push(FlashOp::WipeByOwner(owner));
        Ok(())
    }

    fn enumerate_keys(&self) -> heapless::Vec<pico2hsm_core::key::KeyId, 64> {
        // In-memory state is authoritative; flash enumeration not needed.
        heapless::Vec::new()
    }
    fn for_each_key(&self, _f: &mut dyn FnMut(pico2hsm_core::key::KeyId)) {
        // In-memory state is authoritative; flash enumeration not needed.
    }
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
use pico2hsm_firmware::{WATCHDOG_HEARTBEAT, WATCHDOG_STALL_LIMIT};

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
struct DispatcherPtr(*mut pico2hsm_firmware::apdu::dispatcher::Dispatcher);
#[cfg(target_arch = "arm")]
unsafe impl Send for DispatcherPtr {}

/// APDU dispatcher task — runs on core1 so that blocking ECC crypto does not
/// starve the USB driver which runs cooperatively on core0.
///
/// Takes a raw pointer to the `Dispatcher` which was initialized and loaded
/// from the keystore by core0 before spawning core1.  Core0 never touches the
/// Dispatcher after this point, so the mutable reference is exclusive.
///
/// Flash writes are delegated to core0 via `FLASH_REQ`/`FLASH_RESP` channels
/// because `embassy_rp::flash` asserts `core_id == 0`.
#[cfg(target_arch = "arm")]
#[embassy_executor::task]
async fn dispatcher_task(
    ptr_wrapper: DispatcherPtr,
) {
    let dispatcher_ptr = ptr_wrapper.0;
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

    loop {
        let apdu_bytes = APDU_CHANNEL.receive().await;
        // No defmt logging inside the receive loop.  All embassy_rp TRACE logs
        // from Core0 fill the RTT buffer rapidly; any defmt write from Core1
        // here would block on BLOCK_IF_FULL mode and deadlock both cores.
        if apdu_bytes.is_empty() {
            // Empty APDU = reset signal issued by core0 on USB disconnect.
            // Reset in-memory state and ask core0 to reload keys from flash.
            *dispatcher = pico2hsm_firmware::apdu::dispatcher::Dispatcher::new();
            // Signal core0 to reload keys from store into the fresh dispatcher.
            // Core0 will call dispatcher.load_keys_from_store(store) via the raw
            // pointer.  This is safe because core1 is awaiting FLASH_RESP and
            // not touching the dispatcher.
            FLASH_REQ.send(FlashOp::ReloadKeys).await;
            let _ = FLASH_RESP.receive().await;
            let _ = RESP_CHANNEL.send(heapless::Vec::new()).await;
        } else {
            CORE1_PROGRESS.store(10, core::sync::atomic::Ordering::Relaxed);
            let mut q = FlashQueueKeyStore::new();
            let response = dispatcher.dispatch_with_store(&apdu_bytes, &mut q);
            CORE1_PROGRESS.store(40, core::sync::atomic::Ordering::Relaxed);
            // Drain queued flash ops BEFORE sending the response back to core0.
            // Core0 is in its select loop awaiting RESP_CHANNEL, so it will
            // process FLASH_REQ messages during that wait.
            for op in q.drain() {
                CORE1_PROGRESS.store(50, core::sync::atomic::Ordering::Relaxed);
                FLASH_REQ.send(op).await;
                let _ = FLASH_RESP.receive().await;
            }
            CORE1_PROGRESS.store(60, core::sync::atomic::Ordering::Relaxed);
            let _ = RESP_CHANNEL.send(response).await;
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
    // Core0 stack grows downward from 0x20082000; BSS ends at _ebss.  Set the
    // limit 16 KB above _ebss so any overflow is caught well before it corrupts
    // BSS.  Also enable UsageFault so STKOF surfaces cleanly in probe-rs.
    #[cfg(target_arch = "arm")]
    unsafe {
        let ebss = core::ptr::addr_of!(__ebss) as u32;
        // Core0 stack occupies the gap between __ebss and 0x20082000 (520 KB SRAM end).
        // Guard zone: 4 KB above BSS — any stack overflow past this fires UsageFault.
        // With 160 KB Core1 stack: __ebss ≈ 0x2006CA00, giving ~84 KB Core0 stack
        // minus 4 KB guard = 80 KB usable.  Embassy USB + CCID + init_in_place need ~60 KB.
        cortex_m::register::msplim::write(ebss + 4096);

        // Enable UsageFault handler so STKOF fires as UsageFault, not HardFault.
        // SHCSR bit 18 = USGFAULTENA.
        (*cortex_m::peripheral::SCB::PTR)
            .shcsr
            .modify(|v| v | (1 << 18));

        defmt::info!("core0: MSPLIM set to 0x{:08X} (__ebss=0x{:08X})",
            ebss + 4096, ebss);
    }

    defmt::info!("pico2hsm: peripherals initialised");

    // ── Pico 2: security + OTP + board loop ──────────────────────────────────
    #[cfg(feature = "pico2_4m")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_pico2_board(p).await;
    }

    // ── RP2350-One: security + OTP + board loop ──────────────────────────────
    #[cfg(any(feature = "rp2350_one_4m", feature = "rp2350_one_16m"))]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_one_board(p).await;
    }

    // ── RP2350-Geek: pass p intact; run_geek_board initialises UART first ────
    #[cfg(any(
        feature = "rp2350_geek_16m",
        feature = "rp2350_geek_sdcard",
    ))]
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
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_waveshare_lcd_board(p).await;
    }

    // ── Fallback ─────────────────────────────────────────────────────────────
    #[cfg(not(any(
        feature = "rp2350_one_4m",
        feature = "rp2350_one_16m",
        feature = "rp2350_geek_16m",
        feature = "rp2350_geek_sdcard",
        feature = "pico2_4m",
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
    )))]
    {
        defmt::error!("No board feature flag set — spinning forever");
        loop { Timer::after_millis(1000).await; }
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
    match op {
        FlashOp::SaveKey(ref obj) => {
            let result = store.save_key(obj);
            defmt::info!("FLASH_SVC: save_key 0x{:08x} => {}", obj.key_id,
                if result.is_ok() { "ok" } else { "FAIL" });
            result
        }
        FlashOp::EraseKey(kid) => {
            let result = store.erase_key(kid);
            defmt::info!("FLASH_SVC: erase_key 0x{:08x} => {}", kid.0,
                if result.is_ok() { "ok" } else { "FAIL" });
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
            Ok(())
        }
    }
}

// ─── RP2350-One main function ─────────────────────────────────────────────────

#[cfg(all(target_arch = "arm", any(feature = "rp2350_one_4m", feature = "rp2350_one_16m")))]
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
    // TODO (board-storage wiring): SPI0/SPI1 external flash (RAID-1) requires
    // board struct refactor to separate LED from SPI ownership.  For now, use
    // the RP2350 internal QMI flash (upper 2 MB partition) via the AnyChip::SdCard
    // slot (third type parameter is QmiFlash).
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);

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
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr);

    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        // MSPLIM — hardware stack overflow detection for Core1.
        // CORE1_STACK is 192 KB; set limit 8 KB above bottom for early warning.
        // Also enable UsageFault so STKOF surfaces as UsageFault, not HardFault.
        // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
        #[cfg(target_arch = "arm")]
        unsafe {
            let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
            cortex_m::register::msplim::write(stack_bottom + 8192);
            // SHCSR bit 18 = USGFAULTENA
            (*cortex_m::peripheral::SCB::PTR)
                .shcsr
                .modify(|v| v | (1 << 18));
        }

        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(dispatcher_send).expect("dispatcher task")));
    });

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
                        board.led().set_status(LedStatus::Busy);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select3, Either3};
                            let mut stall_count: u32 = 0;
                            let mut last_heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                            loop {
                                match select3(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500), FLASH_REQ.receive()).await {
                                    Either3::First(r) => break r,
                                    Either3::Second(_) => {
                                        let progress = CORE1_PROGRESS.load(core::sync::atomic::Ordering::Relaxed);
                                        let heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                                        if heartbeat == last_heartbeat {
                                            stall_count += 1;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={} STALL {}/{}", progress, heartbeat, stall_count, WATCHDOG_STALL_LIMIT);
                                            if stall_count >= WATCHDOG_STALL_LIMIT {
                                                defmt::error!("watchdog: core1 stuck — aborting APDU");
                                                // Return SW 6F00 (internal error) to unblock the host.
                                                let mut err_resp = heapless::Vec::<u8, 4098>::new();
                                                let _ = err_resp.push(0x6F);
                                                let _ = err_resp.push(0x00);
                                                break err_resp;
                                            }
                                        } else {
                                            stall_count = 0;
                                            last_heartbeat = heartbeat;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={}", progress, heartbeat);
                                        }
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                    Either3::Third(op) => {
                                        let result = handle_flash_op(op, store, dispatcher_ptr);
                                        FLASH_RESP.send(result).await;
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {}
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
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

#[cfg(all(target_arch = "arm", any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
)))]
async fn run_geek_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::uart::{Config as UartConfig, Uart};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::rp2350_geek::{Rp2350GeekBoard, SPI_FREQ_HZ};
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
    serial_fmt!("OTP ok: provisioned={} production_mode={}", provisioned, prod_mode);
    defmt::info!("OTP: provisioned={}, production_mode={}", provisioned, prod_mode);

    serial_println!("OTP derive_smk...");
    match pico2hsm_firmware::security::otp::derive_smk() {
        Ok(_) => serial_println!("derive_smk ok"),
        Err(_) => serial_println!("derive_smk failed (unprovisioned — continuing)"),
    }

    // ── CHECKPOINT 0 ─────────────────────────────────────────────────────────
    serial_println!("--- run_geek_board ---");
    defmt::info!("Board: RP2350-Geek initialising");

    // ── CHECKPOINT 1 — SPI buses ─────────────────────────────────────────────
    serial_println!("SPI0 init (SCK=18 MOSI=19 MISO=20)...");
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, spi0_cfg);
    serial_fmt!("SPI0 ok @ {} Hz", SPI_FREQ_HZ);

    // SPI1 LCD bus — Async/DMA mode so flush() yields to the executor during
    // the ~17 ms 63 KB framebuffer transfer, keeping USB alive.
    // DMA_CH3=TX, DMA_CH4=RX (RX is unused — LCD is write-only).
    serial_println!("SPI1 init (SCK=10 MOSI=11 MISO=12, async DMA)...");
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.DMA_CH3, p.DMA_CH4, Irqs, spi1_cfg);
    serial_fmt!("SPI1 ok @ {} Hz (async DMA)", pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ);

    // ── CHECKPOINT 2 — board struct ──────────────────────────────────────────
    serial_println!("Board struct init...");
    let mut board = Rp2350GeekBoard::new(spi0, spi1);
    board.led().set_status(LedStatus::Busy);
    serial_println!("Board ok, LED=Busy");

    #[cfg(feature = "rp2350_geek_sdcard")]
    {
        serial_fmt!("SDCard slot active CS=GPIO{}", pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS);
        defmt::info!("SDCard slot active — CS on GPIO {}", pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS);
    }
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
    let mut config_descriptor_buf = [0u8; 512];  // bump to 512 for CDC+CCID
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
    serial_println!("LED=Ready — entering main loop");
    defmt::info!("pico2hsm (RP2350-Geek): USB CCID ready, entering main loop");

    // ── Storage initialization (rp2350_geek: internal QMI flash) ──────────────
    // TODO (board-storage wiring): SPI0/SPI1 external flash (RAID-1) requires
    // board struct refactor to separate LED from SPI ownership.  For now, use
    // the RP2350 internal QMI flash (upper 2 MB partition) via the AnyChip::SdCard
    // slot (third type parameter is QmiFlash).
    serial_println!("KeyStore init (QMI internal flash)...");
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);

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
        Ok(()) => serial_println!("KeyStore ok (QMI internal flash)"),
        Err(_) => serial_println!("KeyStore init failed — degraded mode"),
    }
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // Set provisioning status for display.
    // (qmi_ok/sd_ok left as None — geek board doesn't track individual store health yet)

    // ── CHECKPOINT 7 — init dispatcher on core0, spawn core1 ──────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr);

    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        // MSPLIM — hardware stack overflow detection for Core1.
        // CORE1_STACK is 192 KB; set limit 8 KB above bottom for early warning.
        // Also enable UsageFault so STKOF surfaces as UsageFault, not HardFault.
        // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
        #[cfg(target_arch = "arm")]
        unsafe {
            let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
            cortex_m::register::msplim::write(stack_bottom + 8192);
            // SHCSR bit 18 = USGFAULTENA
            (*cortex_m::peripheral::SCB::PTR)
                .shcsr
                .modify(|v| v | (1 << 18));
        }

        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(dispatcher_send).expect("dispatcher task")));
    });

    let usb_fut = usb.run();

    use pico2hsm_firmware::display::{DisplayState, LastOperation, ScreenLayout, ScreensaverState, SCREENSAVER_TIMEOUT_SECS, LAST_OP_DISPLAY_SECS};
    let layout = ScreenLayout::geek_240x135();

    let mut display_state = DisplayState::new();
    display_state.status = LedStatus::Ready;
    display_state.provisioned = provisioned;
    let mut last_activity = embassy_time::Instant::now();
    let mut screensaver = ScreensaverState::Active;

    let ccid_fut = async {
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
                        let now = embassy_time::Instant::now();
                        if screensaver == ScreensaverState::Sleeping {
                            screensaver = ScreensaverState::Active;
                            board.led().backlight_on();
                        }
                        if now.duration_since(last_activity).as_secs() >= SCREENSAVER_TIMEOUT_SECS as u64
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
                        let apdu_p1  = apdu_bytes.get(2).copied().unwrap_or(0);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;

                        // Wait for core1 response (with time extensions every 1.5s)
                        let response = {
                            use embassy_futures::select::{select3, Either3};
                            let mut stall_count: u32 = 0;
                            let mut last_heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                            loop {
                                match select3(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500), FLASH_REQ.receive()).await {
                                    Either3::First(r) => break r,
                                    Either3::Second(_) => {
                                        let progress = CORE1_PROGRESS.load(core::sync::atomic::Ordering::Relaxed);
                                        let heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                                        if heartbeat == last_heartbeat {
                                            stall_count += 1;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={} STALL {}/{}", progress, heartbeat, stall_count, WATCHDOG_STALL_LIMIT);
                                            if stall_count >= WATCHDOG_STALL_LIMIT {
                                                defmt::error!("watchdog: core1 stuck — aborting APDU");
                                                // Return SW 6F00 (internal error) to unblock the host.
                                                let mut err_resp = heapless::Vec::<u8, 4098>::new();
                                                let _ = err_resp.push(0x6F);
                                                let _ = err_resp.push(0x00);
                                                break err_resp;
                                            }
                                        } else {
                                            stall_count = 0;
                                            last_heartbeat = heartbeat;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={}", progress, heartbeat);
                                        }
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                    Either3::Third(op) => {
                                        let result = handle_flash_op(op, store, dispatcher_ptr);
                                        FLASH_RESP.send(result).await;
                                    }
                                }
                            }
                        };

                        match ccid.send_response(&response).await {
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs = embassy_time::Instant::now().as_secs() as u32;
                                // Update key count from core1 atomic.
                                display_state.key_count = KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                // Derive last_op and authenticated from APDU INS byte + SW.
                                let sw_ok = response.len() >= 2
                                    && response[response.len() - 2] == 0x90
                                    && response[response.len() - 1] == 0x00;
                                if sw_ok {
                                    match apdu_ins {
                                        0x20 => {
                                            display_state.authenticated = true;
                                            display_state.last_op = Some((LastOperation::Verify, display_state.uptime_secs));
                                        }
                                        0x50 => { // SC-HSM INITIALIZE
                                            display_state.authenticated = false;
                                            display_state.last_op = Some((LastOperation::Initialize, display_state.uptime_secs));
                                        }
                                        0x47 | 0x48 => { // PIV/OpenPGP GENERATE KEYPAIR (0x47) or SC-HSM GENERATE KEY (0x48)
                                            display_state.last_op = Some((LastOperation::KeyGen, display_state.uptime_secs));
                                        }
                                        0xE4 => { // SC-HSM DELETE FILE
                                            display_state.last_op = Some((LastOperation::DeleteKey, display_state.uptime_secs));
                                        }
                                        0x2A => { // PSO: sign (P1=0x9E) or decrypt (P1=0x80)
                                            if apdu_p1 == 0x9E {
                                                display_state.last_op = Some((LastOperation::Sign, display_state.uptime_secs));
                                            } else if apdu_p1 == 0x80 {
                                                display_state.last_op = Some((LastOperation::Decrypt, display_state.uptime_secs));
                                            }
                                        }
                                        0x62 => { // SC-HSM DERIVE ASYM / ECDH
                                            display_state.last_op = Some((LastOperation::Ecdh, display_state.uptime_secs));
                                        }
                                        _ => {}
                                    }
                                }
                                // SELECT always resets auth state regardless of SW.
                                if apdu_ins == 0xA4 {
                                    display_state.authenticated = false;
                                }
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time) >= LAST_OP_DISPLAY_SECS {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    pico2hsm_firmware::display::render(board.led(), &display_state, &layout);
                                    board.led().flush().await;
                                }
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                display_state.status = LedStatus::Ready;
                                break;
                            }
                            Err(_) => {}
                        }
                    }

                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
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
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]); // degraded mode if OTP unprovisioned
    let smk = zeroize::Zeroizing::new(smk_bytes);

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

    let mut config_descriptor_buf = [0u8; 512];  // bump to 512 for CDC+CCID
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
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr);

    defmt::info!("core0: spawning core1");
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        // MSPLIM — hardware stack overflow detection for Core1.
        // CORE1_STACK is 192 KB; set limit 8 KB above bottom for early warning.
        // Also enable UsageFault so STKOF surfaces as UsageFault, not HardFault.
        // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
        #[cfg(target_arch = "arm")]
        unsafe {
            let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
            cortex_m::register::msplim::write(stack_bottom + 8192);
            // SHCSR bit 18 = USGFAULTENA
            (*cortex_m::peripheral::SCB::PTR)
                .shcsr
                .modify(|v| v | (1 << 18));
        }

        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(dispatcher_send).expect("dispatcher task")));
    });
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
                        board.led().set_status(LedStatus::Busy);
                        // No defmt logging here — the RTT buffer fills from trace-level
                        // embassy_rp USB logs; any defmt call here blocks Core0 before
                        // the APDU reaches Core1, causing a permanent hang.
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select3, Either3};
                            let mut stall_count: u32 = 0;
                            let mut last_heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                            loop {
                                match select3(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500), FLASH_REQ.receive()).await {
                                    Either3::First(r) => break r,
                                    Either3::Second(_) => {
                                        let progress = CORE1_PROGRESS.load(core::sync::atomic::Ordering::Relaxed);
                                        let heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                                        if heartbeat == last_heartbeat {
                                            stall_count += 1;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={} STALL {}/{}", progress, heartbeat, stall_count, WATCHDOG_STALL_LIMIT);
                                            if stall_count >= WATCHDOG_STALL_LIMIT {
                                                defmt::error!("watchdog: core1 stuck — aborting APDU");
                                                // Return SW 6F00 (internal error) to unblock the host.
                                                let mut err_resp = heapless::Vec::<u8, 4098>::new();
                                                let _ = err_resp.push(0x6F);
                                                let _ = err_resp.push(0x00);
                                                break err_resp;
                                            }
                                        } else {
                                            stall_count = 0;
                                            last_heartbeat = heartbeat;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={}", progress, heartbeat);
                                        }
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                    Either3::Third(op) => {
                                        let result = handle_flash_op(op, store, dispatcher_ptr);
                                        FLASH_RESP.send(result).await;
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {}
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
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

#[cfg(all(target_arch = "arm", any(
    feature = "waveshare_rp2350_lcd_16m",
    feature = "waveshare_rp2350_lcd_sdcard",
)))]
async fn run_waveshare_lcd_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::pio::Pio;
    use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::waveshare_rp2350_lcd::{
        WaveshareRp2350LcdBoard, SPI_FREQ_HZ,
        init_lcd, update_status_display, PioWs2812Writer,
    };
    use pico2hsm_firmware::board::{Board, LedStatus};
    use pico2hsm_firmware::display::{DisplayState, LastOperation, ScreensaverState, SCREENSAVER_TIMEOUT_SECS, LAST_OP_DISPLAY_SECS};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: Waveshare RP2350-LCD-1.47-B initialising");

    // ── SPI0: LCD bus (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO4) ─────────────────
    // Async/DMA mode so flush_display() yields to the executor during the
    // 110 KB framebuffer transfer (~22 ms), keeping USB alive.
    // DMA_CH1=TX, DMA_CH2=RX (RX is unused — LCD is write-only).
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_4, p.DMA_CH1, p.DMA_CH2, Irqs, spi0_cfg);

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
    let mut dc  = Output::new(p.PIN_16, Level::Low);
    let mut cs  = Output::new(p.PIN_17, Level::High);
    let mut rst = Output::new(p.PIN_20, Level::High);
    let mut bl  = Output::new(p.PIN_21, Level::Low);

    // ── WS2812B on GPIO22 via PIO0 SM0 / DMA_CH0 ────────────────────────────
    let Pio { mut common, sm0, .. } = Pio::new(p.PIO0, Irqs);
    let ws2812_program = PioWs2812Program::new(&mut common);
    let ws2812 = PioWs2812::new(
        &mut common, sm0, p.DMA_CH0, Irqs, p.PIN_22, &ws2812_program,
    );
    let mut ws2812_writer = PioWs2812Writer::new(ws2812);

    // ── LCD hardware init — must happen before USB enumeration ───────────────
    let mut display_state = DisplayState::new();
    display_state.status = LedStatus::Busy;
    init_lcd(&mut board.spi0, &mut dc, &mut cs, &mut rst, &mut bl).await;
    {
        let (disp, spi) = board.led_and_spi0_mut();
        update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
    }

    // ── Storage initialisation ─────────────────────────────────────────────

    // Common: derive SMK from OTP.
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);

    // waveshare_rp2350_lcd_sdcard: single SD card keystore on SPI1.
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let store: &'static mut _ = {
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::blocking_mutex::Mutex;
        use static_cell::StaticCell;

        // SPI1 bus at 400 kHz for SD card — SD spec requires ≤400 kHz for card identification.
        // embedded-sdmmc does not negotiate clock speed, so the host must supply ≤400 kHz.
        let mut spi1_cfg = SpiConfig::default();
        spi1_cfg.frequency = 400_000;
        spi1_cfg.phase = Phase::CaptureOnFirstTransition;
        spi1_cfg.polarity = Polarity::IdleLow;
        let spi1_bus = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

        // Wrap SPI1 bus in a shared-bus SpiDevice with CS=GPIO15.
        // The shared_bus SpiDevice wrapper requires Mutex<M, RefCell<BUS>>.
        static SPI1_BUS: StaticCell<
            Mutex<
                CriticalSectionRawMutex,
                core::cell::RefCell<
                    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
                >,
            >,
        > = StaticCell::new();
        let spi1_bus_ref = SPI1_BUS.init(Mutex::new(core::cell::RefCell::new(spi1_bus)));
        let sd_cs = Output::new(p.PIN_15, Level::High);
        let spi_device = embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice::new(
            spi1_bus_ref, sd_cs,
        );

        // Construct SdCardFlash and add to filesystem.
        let delay = embassy_time::Delay;
        let sd_chip = pico2hsm_firmware::storage::sdcard::SdCardFlash::new(spi_device, delay)
            .expect("SD card init failed");

        let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        fs.add_chip(sd_chip).expect("add SD chip");
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => defmt::info!("KeyStore: initialized (waveshare_rp2350_lcd — SD card)"),
            Err(_) => defmt::warn!("KeyStore: init failed — SD card degraded"),
        }
        KEYSTORE_CELL.init(ks)
    };

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
            Ok(()) => defmt::info!("KeyStore: initialized (waveshare_rp2350_lcd_16m internal flash)"),
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

    let mut config_descriptor_buf = [0u8; 512];  // bump to 512 for CDC+CCID
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

    let mut ccid = CcidTransport::new(&mut builder);

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    let mut usb = builder.build();

    defmt::info!("pico2hsm (RP2350-LCD-1.47-B): USB CCID+CDC ready, entering main loop");
    display_state.status = LedStatus::Ready;
    {
        let (disp, spi) = board.led_and_spi0_mut();
        update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
    }

    // ── Init dispatcher on core0, then spawn core1 ─────────────────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        dispatcher_ref.load_keys_from_store(store);
    }
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr);

    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        // MSPLIM — hardware stack overflow detection for Core1.
        // CORE1_STACK is 192 KB; set limit 8 KB above bottom for early warning.
        // Also enable UsageFault so STKOF surfaces as UsageFault, not HardFault.
        // No defmt here — Core1 defmt contends on Spinlock31 with Core0 USB.
        #[cfg(target_arch = "arm")]
        unsafe {
            let stack_bottom = core::ptr::addr_of!(CORE1_STACK) as u32;
            cortex_m::register::msplim::write(stack_bottom + 8192);
            // SHCSR bit 18 = USGFAULTENA
            (*cortex_m::peripheral::SCB::PTR)
                .shcsr
                .modify(|v| v | (1 << 18));
        }

        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(dispatcher_send).expect("dispatcher task")));
    });

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
                update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
            }
            last_activity = embassy_time::Instant::now();
            screensaver = ScreensaverState::Active;

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let now = embassy_time::Instant::now();
                        if screensaver == ScreensaverState::Sleeping {
                            screensaver = ScreensaverState::Active;
                            display_state.status = LedStatus::Ready;
                            let (disp, spi) = board.led_and_spi0_mut();
                            update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                        }
                        if now.duration_since(last_activity).as_secs() >= SCREENSAVER_TIMEOUT_SECS as u64
                            && screensaver == ScreensaverState::Active
                        {
                            screensaver = ScreensaverState::Sleeping;
                            use pico2hsm_firmware::board::waveshare_rp2350_lcd::{Grb, Ws2812Writer};
                            let (disp, spi) = board.led_and_spi0_mut();
                            pico2hsm_firmware::board::waveshare_rp2350_lcd::fill_screen(
                                spi, &mut dc, &mut cs, 0x0000,
                            ).await;
                            ws2812_writer.write_pixel(Grb::OFF).await;
                            let _ = disp;
                        }
                        last_activity = now;
                        display_state.status = LedStatus::Busy;
                        {
                            let (disp, spi) = board.led_and_spi0_mut();
                            update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                        }
                        let apdu_ins = apdu_bytes.get(1).copied().unwrap_or(0);
                        let apdu_p1  = apdu_bytes.get(2).copied().unwrap_or(0);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        // Wait for response with time-extension support.
                        let response = {
                            use embassy_futures::select::{select3, Either3};
                            let mut stall_count: u32 = 0;
                            let mut last_heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                            loop {
                                match select3(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500), FLASH_REQ.receive()).await {
                                    Either3::First(r) => break r,
                                    Either3::Second(_) => {
                                        let progress = CORE1_PROGRESS.load(core::sync::atomic::Ordering::Relaxed);
                                        let heartbeat = WATCHDOG_HEARTBEAT.load(core::sync::atomic::Ordering::Relaxed);
                                        if heartbeat == last_heartbeat {
                                            stall_count += 1;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={} STALL {}/{}", progress, heartbeat, stall_count, WATCHDOG_STALL_LIMIT);
                                            if stall_count >= WATCHDOG_STALL_LIMIT {
                                                defmt::error!("watchdog: core1 stuck — aborting APDU");
                                                // Return SW 6F00 (internal error) to unblock the host.
                                                let mut err_resp = heapless::Vec::<u8, 4098>::new();
                                                let _ = err_resp.push(0x6F);
                                                let _ = err_resp.push(0x00);
                                                break err_resp;
                                            }
                                        } else {
                                            stall_count = 0;
                                            last_heartbeat = heartbeat;
                                            defmt::warn!("time ext: core1 progress={} heartbeat={}", progress, heartbeat);
                                        }
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                    Either3::Third(op) => {
                                        let result = handle_flash_op(op, store, dispatcher_ptr);
                                        FLASH_RESP.send(result).await;
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs = embassy_time::Instant::now().as_secs() as u32;
                                // Update key count from core1 atomic.
                                display_state.key_count = KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                // Derive last_op and authenticated from APDU INS byte + SW.
                                let sw_ok = response.len() >= 2
                                    && response[response.len() - 2] == 0x90
                                    && response[response.len() - 1] == 0x00;
                                if sw_ok {
                                    match apdu_ins {
                                        0x20 => {
                                            display_state.authenticated = true;
                                            display_state.last_op = Some((LastOperation::Verify, display_state.uptime_secs));
                                        }
                                        0x50 => { // SC-HSM INITIALIZE
                                            display_state.authenticated = false;
                                            display_state.last_op = Some((LastOperation::Initialize, display_state.uptime_secs));
                                        }
                                        0x47 | 0x48 => { // PIV/OpenPGP GENERATE KEYPAIR (0x47) or SC-HSM GENERATE KEY (0x48)
                                            display_state.last_op = Some((LastOperation::KeyGen, display_state.uptime_secs));
                                        }
                                        0xE4 => { // SC-HSM DELETE FILE
                                            display_state.last_op = Some((LastOperation::DeleteKey, display_state.uptime_secs));
                                        }
                                        0x2A => { // PSO: sign (P1=0x9E) or decrypt (P1=0x80)
                                            if apdu_p1 == 0x9E {
                                                display_state.last_op = Some((LastOperation::Sign, display_state.uptime_secs));
                                            } else if apdu_p1 == 0x80 {
                                                display_state.last_op = Some((LastOperation::Decrypt, display_state.uptime_secs));
                                            }
                                        }
                                        0x62 => { // SC-HSM DERIVE ASYM / ECDH
                                            display_state.last_op = Some((LastOperation::Ecdh, display_state.uptime_secs));
                                        }
                                        _ => {}
                                    }
                                }
                                // SELECT always resets auth state regardless of SW.
                                if apdu_ins == 0xA4 {
                                    display_state.authenticated = false;
                                }
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time) >= LAST_OP_DISPLAY_SECS {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    let (disp, spi) = board.led_and_spi0_mut();
                                    update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                                }
                                for _ in 0..16 {
                                    pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                display_state.status = LedStatus::Ready;
                                break;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
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
fn debug_dump_storage(
    ks: &pico2hsm_firmware::storage::BoardKeyStore,
) {
    use pico2hsm_firmware::storage::KeyStore;
    let keys = ks.enumerate_keys();
    defmt::info!("=== storage namespace dump: {} key(s) ===", keys.len());
    for kid in keys.iter() {
        let partition = kid.partition();
        let applet   = kid.applet_byte();
        let proto    = kid.proto_ref();
        defmt::info!(
            "  KeyId(0x{:08X}): partition={} applet={} proto_ref=0x{:02X}",
            kid.0, partition, applet, proto,
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
