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

/// Stack for core1.  Measured on hardware (2026-10-12, full hardware suite,
/// debug build, painted stack, see `core1_stack_high_water`): 60.5 KB peak
/// on pico2_4m after the core0/core1 mailboxes (81 KB before them), 62.9 KB
/// on waveshare_rp2350_lcd_sdcard, where storage I/O runs on core1.  The
/// older static estimate of the deepest path (PIV PUT DATA on an SD-card
/// board) was ~89 KB before the mailboxes removed ~20 KB of it.  96 KB
/// keeps well over the 15 KB margin; MSPLIM turns an overflow into a fault
/// (core1 stops, the watchdog resets the chip) rather than corruption.
/// Re-measure (the boot log prints the high water) before going lower.
///
/// Core1 runs a synchronous dispatch loop (no Embassy executor) — the
/// whole stack is call-stack, with no async state machine overhead.
#[cfg(target_arch = "arm")]
const CORE1_STACK_SIZE: usize = 96 * 1024;
#[cfg(target_arch = "arm")]
static mut CORE1_STACK: Stack<CORE1_STACK_SIZE> = Stack::new();

/// Fill pattern for the unused part of the core1 stack.
#[cfg(target_arch = "arm")]
const CORE1_STACK_PAINT: u32 = 0xC1C1_C1C1;

/// Paint the whole core1 stack, so `core1_stack_high_water` can measure the
/// deepest use.  Called first thing in `main`, before the watchdog feeder
/// (which reads the high water) runs: on SD-card boards the keystore mount
/// takes long enough that the feeder used to read an unpainted stack.
#[cfg(target_arch = "arm")]
fn paint_core1_stack() {
    let base = addr_of_mut!(CORE1_STACK) as *mut u32;
    for i in 0..CORE1_STACK_SIZE / 4 {
        // SAFETY: core1 has not started; nothing else uses this memory.
        unsafe { base.add(i).write_volatile(CORE1_STACK_PAINT) };
    }
}

/// Deepest core1 stack use so far, in bytes: the stack grows down from the
/// top, so count from the base up to the first word that is not the paint.
#[cfg(target_arch = "arm")]
fn core1_stack_high_water() -> usize {
    let base = core::ptr::addr_of!(CORE1_STACK) as *const u32;
    let words = CORE1_STACK_SIZE / 4;
    // SAFETY: plain reads of a static; a racing write by core1 only makes
    // the answer one word stale.
    let untouched = (0..words)
        .take_while(|&i| unsafe { base.add(i).read_volatile() } == CORE1_STACK_PAINT)
        .count();
    (words - untouched) * 4
}

/// Core0 → Core1: raw APDU bytes, filled and read in place (no copies on
/// either core's stack; wiped when core1 is done).  Empty = reset-dispatcher
/// signal.  Core0 `sev`s after filling it to wake core1.
#[cfg(target_arch = "arm")]
static APDU_BOX: pico2hsm_firmware::mailbox::Mailbox<4096> =
    pico2hsm_firmware::mailbox::Mailbox::new();
/// Core1 → Core0: serialised response bytes (data + SW1 SW2), written in
/// place by the dispatcher; wiped once core0 has sent them.
#[cfg(target_arch = "arm")]
static RESP_BOX: pico2hsm_firmware::mailbox::Mailbox<4098> =
    pico2hsm_firmware::mailbox::Mailbox::new();
/// Core1 → Core0: "`RESP_BOX` is ready" (wakes core0's async receiver).
/// Uses RP2350 hardware spinlock 30.
#[cfg(target_arch = "arm")]
static RESP_READY: Channel<SpinlockRawMutex<30>, (), 1> = Channel::new();

/// A response taken from `RESP_BOX`; wiped and released when dropped.
#[cfg(target_arch = "arm")]
type Response = pico2hsm_firmware::mailbox::Taken<'static, 4098>;

/// Core1 → Core0: flash operation requests.
/// Uses RP2350 hardware spinlock 27.
#[cfg(target_arch = "arm")]
static FLASH_REQ: Channel<SpinlockRawMutex<27>, FlashOp, 1> = Channel::new();

/// Objects erased per `FlashOp::WipeByOwnerStep` (~50 ms each on QMI flash).
#[cfg(target_arch = "arm")]
const WIPE_STEP_KEYS: usize = 4;

/// Set by core0 after a `WipeByOwnerStep`: more of the applet's objects remain.
#[cfg(target_arch = "arm")]
static WIPE_MORE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
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
    /// Erase a few of the applet's objects (see `WIPE_STEP_KEYS`); sets
    /// `WIPE_MORE` if any remain.  Core1 loops on it so core0 gets back to
    /// its loop — and its CCID time extensions — between steps.
    WipeByOwnerStep(pico2hsm_core::key::AppletId),
    /// Reload keys from flash into the dispatcher (USB reconnect / reset).
    /// Core0 calls `dispatcher.load_keys_from_store(store)` via the raw
    /// pointer while core1 is awaiting the response.
    ReloadKeys,
    /// Append a credential's retry-counter state to the counter log on
    /// internal flash.  Always on core0, on every board: the log is never
    /// on the SD card.
    PutCounter(
        pico2hsm_firmware::storage::retry_counter::Credential,
        pico2hsm_firmware::storage::retry_counter::CounterState,
    ),
    /// Append the domain Lamport counter to the same log (internal flash,
    /// core0 only, every board).
    PutLamport(u64),
    /// Append a device value (RSA pool clock / config / sequence) to the
    /// same log.
    PutValue(pico2hsm_firmware::storage::retry_counter::ValueId, u64),
    /// Bring the Storage V2 anchor forward in the same log (SD boards: the
    /// key write ran on core1).
    PutAnchor(pico2hsm_firmware::storage::retry_counter::Anchor),
    /// FORMAT STORE (QMI boards; SD boards format on core1); the flag is
    /// "the SO-PIN was verified".
    FormatStore(bool),
    /// One erase or program of the binding ring for core1 (SD boards'
    /// formats and wipes).  The data points into core1's buffer, which
    /// outlives the op for the same reason as `SaveKey`'s.
    BindingWrite {
        erase: bool,
        offset: u32,
        data: *const u8,
        len: usize,
    },
    /// Encrypt a generated key and write it to an RSA pool slot (internal
    /// flash, every board).  Points at core1's `KeyObject`, which outlives
    /// the op for the same reason as `SaveKey`'s.
    #[cfg(feature = "rsa")]
    PoolPut {
        slot: u8,
        class: pico2hsm_firmware::storage::rsa_pool::SizeClass,
        birth: u32,
        seq: u32,
        obj: *const pico2hsm_firmware::security::key_management::KeyObject,
    },
    /// Mark an RSA pool slot taken (before its key is handed out).
    #[cfg(feature = "rsa")]
    PoolTake(u8),
    /// Erase an RSA pool slot.
    #[cfg(feature = "rsa")]
    PoolErase(u8),
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
            // SD: here on core1, so core0 keeps the time extensions going
            // through seconds of SD writes; the binding writes go to core0.
            return self.direct().wipe_all();
        }
        Self::on_core0(FlashOp::WipeAll)
    }

    fn wipe_by_owner(
        &mut self,
        owner: pico2hsm_core::key::AppletId,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            // SD: the wipe runs here on core1.  In steps, each counting as
            // progress (as does every SD block write), so a slow card can't
            // trip the 30 s stall reset halfway through.
            while self.direct().wipe_by_owner_step(owner, WIPE_STEP_KEYS)? {
                pico2hsm_firmware::watchdog::progress();
            }
            return Ok(());
        }
        // In bounded steps: one long flash op would starve core0's time
        // extensions and let pcscd time out a large INITIALIZE.
        loop {
            Self::on_core0(FlashOp::WipeByOwnerStep(owner))?;
            if !WIPE_MORE.load(core::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
        }
    }

    fn enumerate_keys(&self) -> heapless::Vec<pico2hsm_core::key::KeyId, 64> {
        heapless::Vec::new()
    }
    fn for_each_key(&self, _f: &mut dyn FnMut(pico2hsm_core::key::KeyId)) {}

    fn retry_counters(
        &mut self,
    ) -> Option<&mut dyn pico2hsm_firmware::storage::retry_counter::RetryCounterBackend> {
        Some(self)
    }

    fn format_store(
        &mut self,
        so_pin_verified: bool,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        if Self::is_direct_write() {
            // As `wipe_all`: the ring erase is 512 SD block writes.
            let r = self.direct().format_store(so_pin_verified);
            pico2hsm_firmware::cdc_log!(
                "FORMAT STORE {}",
                if r.is_ok() { "done" } else { "refused" }
            );
            r?;
        } else {
            Self::on_core0(FlashOp::FormatStore(so_pin_verified))?;
        }
        // Every applet's RAM state describes the old store.
        pico2hsm_firmware::RELOAD_AFTER_APDU.store(true, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn pico2hsm_firmware::storage::rsa_pool::PoolBackend> {
        use pico2hsm_firmware::storage::KeyStore as _;
        // Only when the keystore has a pool (and a storage key for it).
        self.direct().rsa_pool()?;
        Some(self)
    }
}

/// The RSA key pool lives on internal flash on every board: reads are XIP
/// (direct, from core1), every write / take / erase is a `FlashOp` on core0.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
impl pico2hsm_firmware::storage::rsa_pool::PoolBackend for Core1KeyStore {
    fn pool_slots(
        &mut self,
    ) -> Result<
        [pico2hsm_firmware::storage::rsa_pool::SlotState;
            pico2hsm_firmware::storage::rsa_pool::POOL_SLOTS],
        pico2hsm_core::error::StorageError,
    > {
        use pico2hsm_firmware::storage::KeyStore as _;
        match self.direct().rsa_pool() {
            Some(p) => p.pool_slots(),
            None => Err(pico2hsm_core::error::StorageError::NotFormatted),
        }
    }

    fn pool_put(
        &mut self,
        slot: u8,
        class: pico2hsm_firmware::storage::rsa_pool::SizeClass,
        birth: u32,
        seq: u32,
        obj: &pico2hsm_firmware::security::key_management::KeyObject,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        Self::on_core0(FlashOp::PoolPut {
            slot,
            class,
            birth,
            seq,
            obj,
        })
    }

    fn pool_get(
        &mut self,
        slot: u8,
    ) -> Result<
        pico2hsm_firmware::security::key_management::KeyObject,
        pico2hsm_core::error::HsmError,
    > {
        use pico2hsm_firmware::storage::KeyStore as _;
        match self.direct().rsa_pool() {
            Some(p) => p.pool_get(slot),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        }
    }

    fn pool_take(&mut self, slot: u8) -> Result<(), pico2hsm_core::error::HsmError> {
        Self::on_core0(FlashOp::PoolTake(slot))
    }

    fn pool_erase(&mut self, slot: u8) -> Result<(), pico2hsm_core::error::HsmError> {
        Self::on_core0(FlashOp::PoolErase(slot))
    }
}

/// Counter reads come from core0's in-RAM index (core0 only changes it
/// while core1 is blocked in `on_core0`); every write is a
/// `FlashOp::PutCounter` on core0 — on the SD boards too, since the log is
/// on internal flash, which only core0 may program.
#[cfg(target_arch = "arm")]
impl pico2hsm_firmware::storage::retry_counter::RetryCounterBackend for Core1KeyStore {
    fn get(
        &mut self,
        cred: pico2hsm_firmware::storage::retry_counter::Credential,
    ) -> Result<
        Option<pico2hsm_firmware::storage::retry_counter::CounterState>,
        pico2hsm_core::error::StorageError,
    > {
        use pico2hsm_firmware::storage::KeyStore as _;
        match self.direct().retry_counters() {
            Some(log) => log.get(cred),
            None => Err(pico2hsm_core::error::StorageError::NotFormatted),
        }
    }

    fn put(
        &mut self,
        cred: pico2hsm_firmware::storage::retry_counter::Credential,
        state: pico2hsm_firmware::storage::retry_counter::CounterState,
    ) -> Result<(), pico2hsm_core::error::StorageError> {
        match Self::on_core0(FlashOp::PutCounter(cred, state)) {
            Ok(()) => Ok(()),
            Err(pico2hsm_core::error::HsmError::Storage(e)) => Err(e),
            Err(_) => Err(pico2hsm_core::error::StorageError::WriteError),
        }
    }

    fn needs_migration(&mut self) -> bool {
        use pico2hsm_firmware::storage::KeyStore as _;
        self.direct()
            .retry_counters()
            .is_some_and(|log| log.needs_migration())
    }

    fn format(
        &mut self,
        _: &[(
            pico2hsm_firmware::storage::retry_counter::Credential,
            pico2hsm_firmware::storage::retry_counter::CounterState,
        )],
    ) -> Result<(), pico2hsm_core::error::StorageError> {
        // Migration runs at boot on core0 only (`init_retry_counters`).
        Err(pico2hsm_core::error::StorageError::WriteError)
    }

    fn lamport(&mut self) -> Result<u64, pico2hsm_core::error::StorageError> {
        use pico2hsm_firmware::storage::KeyStore as _;
        match self.direct().retry_counters() {
            Some(log) => log.lamport(),
            None => Err(pico2hsm_core::error::StorageError::NotFormatted),
        }
    }

    fn put_lamport(&mut self, value: u64) -> Result<(), pico2hsm_core::error::StorageError> {
        match Self::on_core0(FlashOp::PutLamport(value)) {
            Ok(()) => Ok(()),
            Err(pico2hsm_core::error::HsmError::Storage(e)) => Err(e),
            Err(_) => Err(pico2hsm_core::error::StorageError::WriteError),
        }
    }

    fn value(
        &mut self,
        id: pico2hsm_firmware::storage::retry_counter::ValueId,
    ) -> Result<Option<u64>, pico2hsm_core::error::StorageError> {
        use pico2hsm_firmware::storage::KeyStore as _;
        match self.direct().retry_counters() {
            Some(log) => log.value(id),
            None => Err(pico2hsm_core::error::StorageError::NotFormatted),
        }
    }

    fn put_value(
        &mut self,
        id: pico2hsm_firmware::storage::retry_counter::ValueId,
        value: u64,
    ) -> Result<(), pico2hsm_core::error::StorageError> {
        match Self::on_core0(FlashOp::PutValue(id, value)) {
            Ok(()) => Ok(()),
            Err(pico2hsm_core::error::HsmError::Storage(e)) => Err(e),
            Err(_) => Err(pico2hsm_core::error::StorageError::WriteError),
        }
    }
}

/// Build the Storage V2 key store over `chip` (boot, core0): attach the
/// counter log (moving a version-1 log into the version-2 region once) and
/// the binding ring on internal flash, then mount — formatting only a
/// first-boot device (STORAGE_V2 §8.3).
#[cfg(target_arch = "arm")]
fn new_keystore(
    chip: pico2hsm_firmware::storage::BoardStoreChip,
    smk: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> (
    pico2hsm_firmware::storage::BoardKeyStore,
    Result<(), pico2hsm_core::error::StorageError>,
) {
    use pico2hsm_firmware::storage::{
        flash_chip::{
            QmiBindingFlash, QmiCounterFlash, QmiLegacyCounterFlash, RoutedBindingFlash,
            QMI_FLASH_SIZE,
        },
        flash_layout::{BINDING_SECTORS, LEGACY_COUNTER_SECTORS, RETRY_COUNTER_SECTORS},
        keystore_v2::{Hooks, StoreStatus},
        retry_counter::CounterLog,
    };
    // SAFETY: on the QMI boards the keystore's `QmiFlash` owns `p.FLASH`.
    // The blocking driver holds no state, and all these drivers are used
    // only from core0, one operation at a time, so more handles are sound.
    let handle = || {
        embassy_rp::flash::Flash::<_, embassy_rp::flash::Blocking, QMI_FLASH_SIZE>::new_blocking(
            unsafe { embassy_rp::peripherals::FLASH::steal() },
        )
    };
    let mut ks = pico2hsm_firmware::storage::BoardKeyStore::new(chip, smk);
    let mut legacy = QmiLegacyCounterFlash::new(handle());
    let log = CounterLog::open_migrating(
        QmiCounterFlash::new(handle()),
        RETRY_COUNTER_SECTORS,
        &mut legacy,
        LEGACY_COUNTER_SECTORS,
    );
    if log.migrated_v1() {
        defmt::info!("retry counters: version-1 log moved to the version-2 region");
    }
    ks.attach_retry_counters(log);
    if ks
        .attach_binding(
            RoutedBindingFlash::new(QmiBindingFlash::new(handle()), binding_write_from_core1),
            BINDING_SECTORS,
        )
        .is_err()
    {
        defmt::error!("storage: binding block unreadable");
    }
    ks.set_hooks(Hooks {
        put_anchor: put_anchor_from_core1,
    });
    let r = ks.init();
    match ks.status() {
        StoreStatus::Up => defmt::info!("storage: Storage V2 store mounted"),
        StoreStatus::NeedsFormat => defmt::warn!(
            "storage: the keystore region holds no 2.0 store (a 1.x keystore?) — FORMAT STORE needed"
        ),
        s => defmt::error!("storage: store refused: {}", defmt::Debug2Format(&s)),
    }
    (ks, r)
}

/// `Hooks::put_anchor` for core1 (SD boards): the counter log is on
/// internal flash, which only core0 can write.
#[cfg(target_arch = "arm")]
fn put_anchor_from_core1(
    a: pico2hsm_firmware::storage::retry_counter::Anchor,
) -> Result<(), pico2hsm_core::error::StorageError> {
    Core1KeyStore::on_core0(FlashOp::PutAnchor(a)).map_err(|e| match e {
        pico2hsm_core::error::HsmError::Storage(s) => s,
        _ => pico2hsm_core::error::StorageError::WriteError,
    })
}

/// `RoutedBindingFlash`'s route for core1 (SD boards): the binding ring is
/// on internal flash, which only core0 can write.
#[cfg(target_arch = "arm")]
fn binding_write_from_core1(
    w: pico2hsm_firmware::storage::flash_chip::BindingWrite<'_>,
) -> Result<(), pico2hsm_core::error::StorageError> {
    use pico2hsm_firmware::storage::flash_chip::BindingWrite;
    let op = match w {
        BindingWrite::Erase(sector) => FlashOp::BindingWrite {
            erase: true,
            offset: sector,
            data: core::ptr::null(),
            len: 0,
        },
        BindingWrite::Program(offset, data) => FlashOp::BindingWrite {
            erase: false,
            offset,
            data: data.as_ptr(),
            len: data.len(),
        },
    };
    Core1KeyStore::on_core0(op).map_err(|e| match e {
        pico2hsm_core::error::HsmError::Storage(s) => s,
        _ => pico2hsm_core::error::StorageError::WriteError,
    })
}

/// Seed the counter log from the PIN records if it is new (one-time
/// migration).  Boot only, on core0, before the first key load.
#[cfg(target_arch = "arm")]
fn init_retry_counters(store: &mut pico2hsm_firmware::storage::BoardKeyStore) {
    match pico2hsm_firmware::apdu::dispatcher::Dispatcher::migrate_retry_counters(store) {
        Ok(true) => defmt::info!("retry counters: migrated from the PIN records"),
        Ok(false) => {}
        // Fail closed: credentials load blocked; retried at the next boot.
        Err(_) => defmt::error!("retry counters: migration FAILED — credentials blocked"),
    }
}

/// Attach the RSA key pool region on internal flash (boot, core0, every
/// board).  The slot scan reads each pooled key's header and CRC.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
fn init_rsa_pool(store: &mut pico2hsm_firmware::storage::BoardKeyStore) {
    use pico2hsm_firmware::storage::{
        flash_chip::{QmiPoolFlash, QMI_FLASH_SIZE},
        rsa_pool::PoolRegion,
    };
    // SAFETY: as in `init_retry_counters` — a stateless blocking driver,
    // used only from core0, one operation at a time.
    let flash =
        embassy_rp::flash::Flash::<_, embassy_rp::flash::Blocking, QMI_FLASH_SIZE>::new_blocking(
            unsafe { embassy_rp::peripherals::FLASH::steal() },
        );
    store.attach_rsa_pool(PoolRegion::open(QmiPoolFlash::new(flash)));
}

/// USB serial number: the RP2350's 64-bit chip ID in hex, so every board
/// gets its own stable PC/SC reader name (with one shared serial, hosts
/// can tell identical boards apart only by enumeration order, which
/// changes whenever one re-enumerates).  `0001` if OTP cannot be read.
#[cfg(target_arch = "arm")]
fn usb_serial() -> &'static str {
    static SERIAL: StaticCell<[u8; 16]> = StaticCell::new();
    let Ok(id) = embassy_rp::otp::get_chipid() else {
        return "0001";
    };
    let buf = SERIAL.init([0; 16]);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = b"0123456789ABCDEF"[((id >> (60 - 4 * i)) & 0xF) as usize];
    }
    core::str::from_utf8(buf).unwrap_or("0001")
}

/// One-time initialised key store — lives for the duration of the firmware.
/// Owned by core0 for flash writes; core1 accesses via FLASH_REQ/FLASH_RESP.
#[cfg(target_arch = "arm")]
static KEYSTORE_CELL: StaticCell<pico2hsm_firmware::storage::BoardKeyStore> = StaticCell::new();

/// Health facts known at boot (`display_snapshot::health` bits).
#[cfg(target_arch = "arm")]
fn boot_health(
    ks_ok: bool,
    smk_present: bool,
    store: &pico2hsm_firmware::storage::BoardKeyStore,
) -> u8 {
    use pico2hsm_firmware::display_snapshot::health;
    use pico2hsm_firmware::storage::keystore_v2::StoreStatus;
    let mut f = 0;
    if store.status() == StoreStatus::NeedsFormat {
        // Not damage: the routine 1.x → 2.0 upgrade step.
        f |= health::NEEDS_FORMAT;
    } else if !ks_ok {
        f |= health::KS_INIT_FAILED;
    }
    if !smk_present {
        f |= health::SMK_MISSING;
    }
    if pico2hsm_firmware::security::otp::Otp::new().is_provisioned() {
        f |= health::PROVISIONED;
    }
    f
}

/// Seed the display snapshot from core0 before core1 starts (core1 is its
/// only writer afterwards).  Harmless on the LED-only boards.
#[cfg(target_arch = "arm")]
fn publish_boot_snapshot(d: &mut pico2hsm_firmware::apdu::dispatcher::Dispatcher, health: u8) {
    d.set_boot_health(health);
    d.note_session(pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst));
    pico2hsm_firmware::display_snapshot::publish(&d.display_snapshot());
}

/// Re-export for convenient access in this binary crate.
#[cfg(target_arch = "arm")]
use pico2hsm_firmware::CORE1_PROGRESS;

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
/// attempts.  Core0 issues `sev` after each `APDU_BOX` fill and
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

/// Longest background slice of idle-time work (RSA key pool), µs.  A slice
/// also ends as soon as an APDU is waiting; see `pool_slice`.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
const POOL_SLICE_US: u64 = 20_000;

/// Budget of one background slice: stop when an APDU is waiting (checked
/// before every unit of work, so an APDU waits at most one unit — about a
/// millisecond) or after `POOL_SLICE_US`.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
struct SliceBudget {
    deadline: embassy_time::Instant,
}

#[cfg(all(target_arch = "arm", feature = "rsa"))]
impl pico2hsm_firmware::crypto::rsa_keygen::Budget for SliceBudget {
    fn should_yield(&mut self) -> bool {
        APDU_BOX.is_full() || embassy_time::Instant::now() >= self.deadline
    }
}

/// One slice of idle-time RSA key pool work; `true` if there was any.
/// Bumps the watchdog heartbeat (no stall suppression is ever used).
#[cfg(all(target_arch = "arm", feature = "rsa"))]
fn pool_slice(store_ptr: *mut pico2hsm_firmware::storage::BoardKeyStore) -> bool {
    let mut ks = Core1KeyStore::new(store_ptr);
    let mut budget = SliceBudget {
        deadline: embassy_time::Instant::now() + embassy_time::Duration::from_micros(POOL_SLICE_US),
    };
    let act = pico2hsm_firmware::rsa_pool::background(&mut ks, &mut budget);
    pico2hsm_firmware::WATCHDOG_HEARTBEAT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    act == pico2hsm_firmware::rsa_pool::Activity::Worked
}

/// Core1: write a response into `RESP_BOX` with `f`.  Core0 releases the
/// previous one before it sends the next APDU, so the wait is only for the
/// moment core0 takes to drop it.  Core0 isn't told until `post_response`.
#[cfg(target_arch = "arm")]
fn fill_response(f: impl FnOnce(&mut heapless::Vec<u8, 4098>)) {
    while RESP_BOX.is_full() {
        core::hint::spin_loop();
    }
    let _ = RESP_BOX.try_fill(f);
}

/// Core1: tell core0 that `RESP_BOX` holds the response.
#[cfg(target_arch = "arm")]
fn post_response() {
    blocking_send(&RESP_READY, ());
}

/// Wait for the next APDU (or reset signal), doing idle-time work while
/// none is waiting.
///
/// Core0 `sev`s after every `APDU_BOX` fill.  The mailbox is checked
/// before every slice, and a slice checks it before every unit of work, so
/// an APDU is picked up within one unit.  With no work left core1 sleeps
/// in `wfe` exactly as before; a `sev` that lands between the check and
/// the `wfe` is latched in the event register, so the `wfe` returns at once.
#[cfg(target_arch = "arm")]
fn next_apdu(
    store_ptr: *mut pico2hsm_firmware::storage::BoardKeyStore,
) -> pico2hsm_firmware::mailbox::Taken<'static, 4096> {
    let _ = store_ptr;
    loop {
        if let Some(apdu) = APDU_BOX.try_take() {
            return apdu;
        }
        #[cfg(feature = "rsa")]
        if pool_slice(store_ptr) {
            continue;
        }
        cortex_m::asm::wfe();
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
    // Background RSA key generation starts only if this boot-time health
    // check of the TRNG (and the reseed) succeeded.
    let rng_ok = pico2hsm_firmware::crypto::rng::reseed().is_ok();
    #[cfg(feature = "rsa")]
    pico2hsm_firmware::rsa_pool::with_engine(|e| e.set_rng_ok(rng_ok));
    let _ = rng_ok;

    // SAFETY: dispatcher_ptr was initialized on core0 and core0 never accesses
    // the Dispatcher after spawning core1.  The pointer is valid for the
    // lifetime of the firmware (backed by StaticCell in BSS).
    let dispatcher = unsafe { &mut *dispatcher_ptr };
    // Core1 is the only writer of the display snapshot from here on.
    use pico2hsm_firmware::display_snapshot::publish;

    let mut session = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
    loop {
        let apdu_bytes = next_apdu(store_ptr);
        // A new host session (USB reset/deconfigure or card power cycle)
        // must not inherit PIN/key authentication from the previous one.
        // Key off the session the APDU was *sent in*, not the current one:
        // a command queued before a reset belongs to the old session.
        let tag = pico2hsm_firmware::APDU_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
        if tag != session {
            dispatcher.clear_session();
            session = tag;
            dispatcher.note_session(session);
            publish(&dispatcher.display_snapshot());
        }
        let stale = !apdu_bytes.is_empty()
            && pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst) != tag;
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
            publish(&dispatcher.display_snapshot());
            drop(apdu_bytes);
            fill_response(|_| {});
            post_response();
        } else if stale {
            // Its session ended while it was queued: never run it.  Core0
            // drops the reply (tagged with the old epoch) as well.
            drop(apdu_bytes); // wipes it
            fill_response(|out| {
                let _ = out.extend_from_slice(&[0x6F, 0x00]);
            });
            post_response();
        } else {
            CORE1_PROGRESS.store(10, core::sync::atomic::Ordering::Relaxed);
            // Display: the operation is in progress (only tracked ops).
            if dispatcher.display_begin(&apdu_bytes) {
                publish(&dispatcher.display_snapshot());
            }
            let mut ks = Core1KeyStore::new(store_ptr);
            fill_response(|out| {
                dispatcher.dispatch_into(&apdu_bytes, &mut ks, out);
                dispatcher.display_end(out, &mut ks);
            });
            // The command may carry PINs or key material: dropping it wipes it.
            drop(apdu_bytes);
            // A reset during the command: whatever it authenticated belonged
            // to the session that just ended.
            let now = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
            if now != session {
                dispatcher.clear_session();
                session = now;
                dispatcher.note_session(session);
            }
            // Display: the outcome, before the host can see the response.
            publish(&dispatcher.display_snapshot());
            CORE1_PROGRESS.store(60, core::sync::atomic::Ordering::Relaxed);
            post_response();
            // The store was replaced (FORMAT STORE): drop every applet's
            // state and reload it, as after a USB reset — after the
            // response, never under the running command.
            if pico2hsm_firmware::RELOAD_AFTER_APDU
                .swap(false, core::sync::atomic::Ordering::SeqCst)
            {
                dispatcher.reset_in_place();
                dispatcher.note_store_formatted();
                let _ = Core1KeyStore::on_core0(FlashOp::ReloadKeys);
                publish(&dispatcher.display_snapshot());
            }
            CORE1_PROGRESS.store(0, core::sync::atomic::Ordering::Relaxed);
        }
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
async fn main(spawner: Spawner) {
    // Before any task can read it (see `paint_core1_stack`).
    paint_core1_stack();

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

    // ── Hardware watchdog ────────────────────────────────────────────────────
    // Armed before anything that can hang (security checks, OTP, storage,
    // SD card, LCD, USB).  Boot code below runs synchronously until the
    // first await, so it is kept fed by `watchdog::progress()` in every
    // sector write/erase and key load; from the first await on, the feeder
    // task does it.  Paused while a debugger halts either core.
    let boot_report = pico2hsm_firmware::watchdog::boot_init();
    log_boot_report(&boot_report);
    spawner.spawn(watchdog_feeder().expect("watchdog feeder task"));

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
        run_geek_board(p, boot_report).await;
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

        run_waveshare_lcd_board(p, boot_report).await;
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
    // Flash work counts as progress for the core1 stall detector, and feeds
    // the hardware watchdog (this blocks core0's executor; every sector
    // erase/program inside feeds again).
    pico2hsm_firmware::watchdog::progress();
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
        FlashOp::WipeByOwnerStep(owner) => {
            let more = store.wipe_by_owner_step(owner, WIPE_STEP_KEYS);
            WIPE_MORE.store(
                matches!(more, Ok(true)),
                core::sync::atomic::Ordering::Release,
            );
            more.map(|_| ())
        }
        FlashOp::ReloadKeys => {
            defmt::info!("FLASH_SVC: reload_keys");
            // SAFETY: core1 is blocked on FLASH_RESP.receive() and will not
            // touch the dispatcher until we send the response.
            let dispatcher = unsafe { &mut *dispatcher_ptr };
            dispatcher.load_keys_from_store(store);
            Ok(())
        }
        FlashOp::FormatStore(so_pin_verified) => {
            defmt::warn!("FLASH_SVC: FORMAT STORE");
            let r = store.format_store_now(so_pin_verified);
            pico2hsm_firmware::cdc_log!(
                "FORMAT STORE {}",
                if r.is_ok() { "done" } else { "refused" }
            );
            r
        }
        FlashOp::BindingWrite {
            erase,
            offset,
            data,
            len,
        } => {
            use pico2hsm_firmware::storage::flash_chip::{
                BindingWrite, QmiBindingFlash, QMI_FLASH_SIZE,
            };
            // SAFETY: the blocking driver holds no state (see
            // `new_keystore`); core1 is parked in `on_core0`.
            let mut flash = QmiBindingFlash::new(embassy_rp::flash::Flash::<
                _,
                embassy_rp::flash::Blocking,
                QMI_FLASH_SIZE,
            >::new_blocking(unsafe {
                embassy_rp::peripherals::FLASH::steal()
            }));
            let w = if erase {
                BindingWrite::Erase(offset)
            } else {
                // SAFETY: see `FlashOp::BindingWrite` — core1 is blocked
                // until we reply, so its buffer is live and unchanged.
                BindingWrite::Program(offset, unsafe { core::slice::from_raw_parts(data, len) })
            };
            w.apply(&mut flash)
                .map_err(pico2hsm_core::error::HsmError::Storage)
        }
        FlashOp::PutAnchor(a) => match store.counter_log() {
            Some(log) => log
                .put_anchor(a)
                .map_err(pico2hsm_core::error::HsmError::Storage),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
        FlashOp::PutCounter(cred, state) => match store.retry_counters() {
            Some(log) => log
                .put(cred, state)
                .map_err(pico2hsm_core::error::HsmError::Storage),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
        FlashOp::PutLamport(value) => match store.retry_counters() {
            Some(log) => log
                .put_lamport(value)
                .map_err(pico2hsm_core::error::HsmError::Storage),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
        FlashOp::PutValue(id, value) => match store.retry_counters() {
            Some(log) => log
                .put_value(id, value)
                .map_err(pico2hsm_core::error::HsmError::Storage),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
        #[cfg(feature = "rsa")]
        FlashOp::PoolPut {
            slot,
            class,
            birth,
            seq,
            obj,
        } => {
            // SAFETY: see `FlashOp::PoolPut` — core1 is blocked until we reply.
            let obj = unsafe { &*obj };
            match store.rsa_pool() {
                Some(p) => p.pool_put(slot, class, birth, seq, obj),
                None => Err(pico2hsm_core::error::HsmError::Storage(
                    pico2hsm_core::error::StorageError::NotFormatted,
                )),
            }
        }
        #[cfg(feature = "rsa")]
        FlashOp::PoolTake(slot) => match store.rsa_pool() {
            Some(p) => p.pool_take(slot),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
        #[cfg(feature = "rsa")]
        FlashOp::PoolErase(slot) => match store.rsa_pool() {
            Some(p) => p.pool_erase(slot),
            None => Err(pico2hsm_core::error::HsmError::Storage(
                pico2hsm_core::error::StorageError::NotFormatted,
            )),
        },
    }
}

/// Core0's flash service: runs every `FlashOp` core1 sends, whenever it
/// sends it — during an APDU (key writes, retry counters) and between
/// APDUs (the RSA key pool's background writes).  Joined with the USB and
/// CCID futures in every board runner; the only core0 code that touches
/// the keystore after boot.
#[cfg(target_arch = "arm")]
async fn flash_service(
    store: &'static mut pico2hsm_firmware::storage::BoardKeyStore,
    dispatcher_ptr: *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher,
) {
    loop {
        let op = FLASH_REQ.receive().await;
        let result = handle_flash_op(op, store, dispatcher_ptr);
        FLASH_RESP.send(result).await;
        cortex_m::asm::sev(); // wake core1 from WFE
    }
}

/// Wait for core1's next response (`RESP_READY`, then `RESP_BOX`).
///
/// Unbounded by design: a wedged core1 is caught by the hardware-watchdog
/// feeder, which stops feeding after 30 s without progress.  Any flash
/// operation core1 needs first (key writes, `ReloadKeys` after a
/// USB-reconnect reset) runs in `flash_service`, which is always polled.
#[cfg(target_arch = "arm")]
async fn recv_core1_response() -> Response {
    RESP_READY.receive().await;
    pico2hsm_firmware::watchdog::note_core1_response();
    take_response()
}

/// The response core1 announced on `RESP_READY` (always filled first).
#[cfg(target_arch = "arm")]
fn take_response() -> Response {
    RESP_BOX.try_take().expect("RESP_READY without a response")
}

/// Wait for core1's response to an APDU, keeping the host and core1 serviced.
///
/// - Core1's flash writes are serviced by `flash_service`, polled
///   alongside.
/// - Sends a CCID time extension every 1.5 s of wall-clock time.  The deadline
///   is absolute, so a stream of flash ops (which block this executor) cannot
///   push it back; an overdue extension goes out as soon as the op finishes.
/// - Stall detector: if core1's heartbeat doesn't move for 30 s
///   (`watchdog::Core1Monitor`, and stall detection is not suppressed),
///   returns `None`; the caller must reset the device (see `watchdog_reset`).
///
/// On USB disconnect, waits for core1's response and returns it; sending
/// it fails, so the caller takes its normal disconnect path.  That drain (like the reset
/// drains in the board loops) has no stall detector of its own: if core1 is
/// wedged, the watchdog feeder stops feeding and the hardware watchdog
/// resets the chip.
#[cfg(target_arch = "arm")]
async fn await_core1_response<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
) -> Option<Response> {
    use core::sync::atomic::Ordering::Relaxed;
    use embassy_futures::select::{select, Either};
    use embassy_time::{Duration, Instant};

    use pico2hsm_firmware::watchdog::{Core1Activity, Core1Health, Core1Monitor};

    const WTX_INTERVAL: Duration = Duration::from_millis(1500);
    let mut deadline = Instant::now() + WTX_INTERVAL;
    // Same stall rule as the hardware-watchdog feeder (30 s without
    // heartbeat or reply); here it gets a 6F00 out before the reset.
    let mut monitor = Core1Monitor::new(Instant::now().as_millis(), Core1Activity::sample());
    loop {
        match select(RESP_READY.receive(), Timer::at(deadline)).await {
            Either::First(()) => {
                pico2hsm_firmware::watchdog::note_core1_response();
                return Some(take_response());
            }
            Either::Second(()) => {
                deadline = Instant::now() + WTX_INTERVAL;
                let progress = CORE1_PROGRESS.load(Relaxed);
                let activity = Core1Activity::sample();
                let health = monitor.observe(Instant::now().as_millis(), activity);
                defmt::warn!(
                    "time ext: core1 progress={} heartbeat={} health={}",
                    progress,
                    activity.heartbeat,
                    defmt::Debug2Format(&health)
                );
                if health == Core1Health::Stalled {
                    return None;
                }
                if let Err(pico2hsm_firmware::transport::ccid::CcidError::UsbDisconnected) =
                    ccid.send_time_extension().await
                {
                    // Sending it fails the same way (and a new session's
                    // epoch would drop it): the caller takes its disconnect path.
                    return Some(recv_core1_response().await);
                }
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
    response: Response,
    epoch: u32,
) -> Result<(), pico2hsm_firmware::transport::ccid::CcidError> {
    // A response computed for a previous host session must not be delivered
    // into the new one (it would answer the new session's first command).
    let current = pico2hsm_firmware::SESSION_EPOCH.load(core::sync::atomic::Ordering::SeqCst);
    let result = if current == epoch {
        ccid.send_response(&response).await
    } else {
        Ok(())
    };
    // Watchdog test hook (debug builds): block core0's executor for good.
    #[cfg(feature = "debug")]
    if pico2hsm_firmware::watchdog::DEBUG_WEDGE_CORE0.load(core::sync::atomic::Ordering::SeqCst) {
        loop {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
    // Dropping the response wipes it and frees `RESP_BOX` for core1.
    drop(response);
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
        note_usb_configured(false);
    }

    fn configured(&mut self, configured: bool) {
        if !configured {
            pico2hsm_firmware::bump_session_epoch();
        }
        note_usb_configured(configured);
    }
}

/// Tell the display whether a host has configured USB.
#[cfg(target_arch = "arm")]
fn note_usb_configured(configured: bool) {
    pico2hsm_firmware::display_snapshot::USB_CONFIGURED
        .store(configured, core::sync::atomic::Ordering::Release);
    pico2hsm_firmware::display::task::kick();
}

/// Core1 is stuck: tell the host (SW 6F00) and reset the whole chip.
///
/// Core1 cannot be safely abandoned — it would still own the dispatcher and
/// its late response would be taken as the answer to the next APDU — so a
/// full reset is the only state that is known to be consistent.
///
/// Feeding stops first, so if the 6F00 can't be sent (host gone, endpoint
/// stuck) the hardware watchdog still fires within its timeout.  The reset
/// itself is a watchdog trigger: both cores, USB and all peripherals.
#[cfg(target_arch = "arm")]
async fn watchdog_reset<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
) -> ! {
    use pico2hsm_firmware::watchdog::{reset_now, starve, ResetCause};
    starve(ResetCause::Core1Stall);
    defmt::error!("watchdog: core1 stuck — sending 6F00 and resetting");
    let _ = ccid.send_response(&[0x6F, 0x00]).await;
    Timer::after_millis(50).await;
    reset_now(ResetCause::Core1Stall)
}

/// Hand core1 a request (an APDU, or an empty Vec = reset signal) and wake
/// it.  Counted for the watchdog feeder before the send, so a core1 that
/// never takes the request is caught as well.
#[cfg(target_arch = "arm")]
async fn send_to_core1(apdu: &mut heapless::Vec<u8, 4096>) {
    post_apdu(|b| {
        let _ = b.extend_from_slice(apdu);
    })
    .await;
    // Core0's copy may carry PINs or key material.
    zeroize::Zeroize::zeroize(apdu.as_mut_slice());
    apdu.clear();
}

/// Tell core1 to reset the dispatcher (USB disconnect): an empty APDU.
#[cfg(target_arch = "arm")]
async fn send_reset_to_core1() {
    post_apdu(|_| {}).await;
}

/// Fill `APDU_BOX` with `f` and wake core1.  Counted for the watchdog
/// feeder first, so a core1 that never takes the request is caught too.
#[cfg(target_arch = "arm")]
async fn post_apdu(f: impl FnOnce(&mut heapless::Vec<u8, 4096>)) {
    pico2hsm_firmware::watchdog::note_core1_request();
    // Core1 releases the previous APDU before it answers it, so the
    // mailbox is free by now; wait out the rare overlap all the same.
    while APDU_BOX.is_full() {
        Timer::after_micros(50).await;
    }
    let _ = APDU_BOX.try_fill(f);
    cortex_m::asm::sev(); // wake core1 from WFE
}

/// Feeds the hardware watchdog while the system is healthy (see the
/// `watchdog` module).  That this task runs at all shows core0's executor
/// is alive; it stops feeding once core1 has been stuck on a request for
/// 30 s — on any path, including the USB-disconnect drain, which has no
/// stall detector of its own.
#[cfg(target_arch = "arm")]
#[embassy_executor::task]
async fn watchdog_feeder() {
    use embassy_time::Instant;
    use pico2hsm_firmware::watchdog::{
        feed, reset_pending, should_feed, starve, Core1Activity, Core1Health, Core1Monitor,
        ResetCause, FEED_INTERVAL_MS,
    };
    let mut monitor = Core1Monitor::new(Instant::now().as_millis(), Core1Activity::sample());
    let mut stack_peak = 0;
    loop {
        let peak = core1_stack_high_water();
        if peak > stack_peak + 1024 {
            stack_peak = peak;
            defmt::info!(
                "core1 stack high water: {} of {} bytes",
                peak,
                CORE1_STACK_SIZE
            );
            pico2hsm_firmware::cdc_log!(
                "core1 stack high water: {} of {} bytes",
                peak,
                CORE1_STACK_SIZE
            );
        }
        let health = monitor.observe(Instant::now().as_millis(), Core1Activity::sample());
        if should_feed(health, reset_pending()) {
            feed();
        } else if health == Core1Health::Stalled && !reset_pending() {
            defmt::error!(
                "watchdog: core1 stuck on a request for 30 s — stop feeding, reset follows"
            );
            pico2hsm_firmware::cdc_error!("watchdog: core1 stuck, resetting");
            starve(ResetCause::FeederCore1Stall);
        }
        Timer::after_millis(FEED_INTERVAL_MS).await;
    }
}

/// Log why the previous run ended (defmt and the CDC log).
#[cfg(target_arch = "arm")]
fn log_boot_report(r: &pico2hsm_firmware::watchdog::BootReport) {
    use pico2hsm_firmware::watchdog::{describe, LastReset};
    let what = describe(r.last);
    if r.last == LastReset::Other {
        defmt::info!("reset: {} (CHIP_RESET=0x{:08X})", what, r.chip_reset);
        pico2hsm_firmware::cdc_log!("reset: {} (CHIP_RESET=0x{:08X})", what, r.chip_reset);
    } else {
        defmt::warn!(
            "reset: {} — watchdog resets in a row: {} (CHIP_RESET=0x{:08X})",
            what,
            r.wdt_resets,
            r.chip_reset
        );
        pico2hsm_firmware::cdc_warn!(
            "reset: {} - watchdog resets in a row: {} (CHIP_RESET=0x{:08X})",
            what,
            r.wdt_resets,
            r.chip_reset
        );
    }
}

// ─── RP2350-One main function ─────────────────────────────────────────────────

#[cfg(all(target_arch = "arm", feature = "rp2350_one_4m"))]
async fn run_one_board(p: embassy_rp::Peripherals) {
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
    let smk_present = smk.is_some();

    let qmi_flash = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

    let (ks, ks_init) = new_keystore(qmi, smk);
    let ks_ok = ks_init.is_ok();
    match ks_init {
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
    usb_config.serial_number = Some(usb_serial());
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
        init_retry_counters(store);
        #[cfg(feature = "rsa")]
        init_rsa_pool(store);
        dispatcher_ref.load_keys_from_store(store);
        dispatcher_ref.migrate_domain(store);
    }
    publish_boot_snapshot(dispatcher_ref, boot_health(ks_ok, smk_present, store));
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
                    Ok(mut apdu_bytes) => {
                        let epoch = ccid.apdu_epoch();
                        pico2hsm_firmware::APDU_EPOCH
                            .store(epoch, core::sync::atomic::Ordering::SeqCst);
                        board.led().set_status(LedStatus::Busy);
                        send_to_core1(&mut apdu_bytes).await;
                        let response = match await_core1_response(&mut ccid).await {
                            Some(r) => r,
                            None => watchdog_reset(&mut ccid).await,
                        };
                        match send_and_wipe(&mut ccid, response, epoch).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    if !pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                send_reset_to_core1().await;
                                let _ = recv_core1_response().await;
                                break;
                            }
                            Err(e) => defmt::error!(
                                "CCID: response not sent: {:?}",
                                defmt::Debug2Format(&e)
                            ),
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        send_reset_to_core1().await;
                        let _ = recv_core1_response().await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    embassy_futures::join::join3(usb_fut, ccid_fut, flash_service(store, dispatcher_ptr)).await;
}

// ─── Display boards: shared pieces ────────────────────────────────────────────

/// Band buffer for the display (16 full-width rows; no framebuffer).
#[cfg(all(
    target_arch = "arm",
    any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard")
))]
static DISPLAY_BAND: static_cell::ConstStaticCell<
    [u8; pico2hsm_firmware::display::band::band_bytes(
        240,
        pico2hsm_firmware::display::band::BAND_ROWS,
    )],
> = static_cell::ConstStaticCell::new(
    [0; pico2hsm_firmware::display::band::band_bytes(
        240,
        pico2hsm_firmware::display::band::BAND_ROWS,
    )],
);

/// Band buffer for the display (16 full-width rows; no framebuffer).
#[cfg(all(
    target_arch = "arm",
    any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard"
    )
))]
static DISPLAY_BAND: static_cell::ConstStaticCell<
    [u8; pico2hsm_firmware::display::band::band_bytes(
        320,
        pico2hsm_firmware::display::band::BAND_ROWS,
    )],
> = static_cell::ConstStaticCell::new(
    [0; pico2hsm_firmware::display::band::band_bytes(
        320,
        pico2hsm_firmware::display::band::BAND_ROWS,
    )],
);

/// Show E10 (no SD card) and wait for the hardware watchdog: nothing feeds
/// it while this spins, so the chip restarts within ~8 s and retries.
#[cfg(all(
    target_arch = "arm",
    any(
        feature = "rp2350_geek_sdcard",
        feature = "waveshare_rp2350_lcd_sdcard"
    )
))]
async fn halt_no_sd_card<P: pico2hsm_firmware::display::Panel>(
    screen: &mut pico2hsm_firmware::display::ScreenDriver<'_, P>,
    report: &pico2hsm_firmware::watchdog::BootReport,
) -> ! {
    use pico2hsm_firmware::display::view::{ErrorCode, ErrorView, FooterView, Screen, StorageLine};
    defmt::error!("SD card init FAILED — waiting for the watchdog to retry");
    let attempt = report.wdt_resets.saturating_add(1);
    screen
        .show(&Screen::Error(ErrorView {
            code: ErrorCode::E10NoSdCard { attempt },
            footer: FooterView::Normal {
                uptime: embassy_time::Instant::now().as_secs() as u32,
                storage: StorageLine::SdMissing,
                reset: None,
            },
        }))
        .await;
    loop {
        cortex_m::asm::wfi();
    }
}

/// The CCID command loop of the display boards.  It never renders: it hands
/// each APDU to core1 first, then records the start time and kicks the
/// display task, which shows WORKING only after 300 ms.
#[cfg(all(
    target_arch = "arm",
    any(
        feature = "rp2350_geek_16m",
        feature = "rp2350_geek_sdcard",
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard"
    )
))]
async fn display_board_ccid_loop<'d, D: embassy_usb::driver::Driver<'d>>(
    ccid: &mut pico2hsm_firmware::transport::CcidTransport<'d, D>,
    cdc_sender: &mut embassy_usb::class::cdc_acm::Sender<'d, D>,
) -> ! {
    use pico2hsm_firmware::display::task::kick;
    use pico2hsm_firmware::display_snapshot::set_apdu_started;
    use pico2hsm_firmware::transport::ccid::CcidError;
    loop {
        ccid.wait_connected().await;
        defmt::info!("USB connected");
        loop {
            match ccid.recv_apdu().await {
                Ok(mut apdu_bytes) => {
                    let epoch = ccid.apdu_epoch();
                    pico2hsm_firmware::APDU_EPOCH
                        .store(epoch, core::sync::atomic::Ordering::SeqCst);
                    send_to_core1(&mut apdu_bytes).await;
                    set_apdu_started(Some(embassy_time::Instant::now().as_millis() as u32));
                    kick();
                    let response = match await_core1_response(ccid).await {
                        Some(r) => r,
                        None => watchdog_reset(ccid).await,
                    };
                    set_apdu_started(None);
                    kick();
                    match send_and_wipe(ccid, response, epoch).await {
                        Ok(()) => {
                            for _ in 0..16 {
                                if !pico2hsm_firmware::transport::cdc_serial::drain_one(cdc_sender)
                                    .await
                                {
                                    break;
                                }
                            }
                        }
                        Err(CcidError::UsbDisconnected) => {
                            send_reset_to_core1().await;
                            let _ = recv_core1_response().await;
                            break;
                        }
                        Err(e) => {
                            defmt::error!("CCID: response not sent: {:?}", defmt::Debug2Format(&e))
                        }
                    }
                }
                Err(CcidError::UsbDisconnected) => {
                    send_reset_to_core1().await;
                    let _ = recv_core1_response().await;
                    break;
                }
                Err(_) => {}
            }
        }
    }
}

// ─── RP2350-Geek main function ────────────────────────────────────────────────

#[cfg(all(
    target_arch = "arm",
    any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard",)
))]
async fn run_geek_board(
    p: embassy_rp::Peripherals,
    boot_report: pico2hsm_firmware::watchdog::BootReport,
) {
    use embassy_futures::join::join4;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::uart::{Config as UartConfig, Uart};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::rp2350_geek::Rp2350GeekBoard;
    use pico2hsm_firmware::display::model::{reset_info, StaticInfo, StorageKind};
    use pico2hsm_firmware::display::view::{BootStep, Screen, SplashView};
    use pico2hsm_firmware::display::{ScreenDriver, DETAIL, GEEK_240X135};
    use pico2hsm_firmware::transport::CcidTransport;

    // ── UART first — before security checks so failures are observable ────────
    // WHY EARLY: security_checks() runs a silent infinite spin if
    // check_debugger_attached() returns true (DHCSR C_DEBUGEN set by a prior
    // probe session).  Without serial output we can't distinguish that halt
    // from a clock/flash/allocator failure.
    let _dbg = Uart::new_blocking(p.UART1, p.PIN_4, p.PIN_5, UartConfig::default());
    pico2hsm_firmware::serial_debug::uart1_write_bytes(b"\r\n\r\n");
    serial_println!("=== pico2hsm RP2350-Geek boot ===");
    serial_println!("UART1 GPIO4=TX GPIO5=RX 115200 8N1");

    serial_println!("security_checks()...");
    pico2hsm_firmware::security::boot::security_checks();
    serial_println!("security_checks() ok");

    serial_println!("allocator init...");
    pico2hsm_firmware::allocator::init();

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
    match pico2hsm_firmware::security::otp::derive_smk() {
        Ok(_) => serial_println!("derive_smk ok"),
        Err(_) => serial_println!("derive_smk failed (unprovisioned — continuing)"),
    }
    defmt::info!("Board: RP2350-Geek initialising");

    // ── LCD (SPI1, async DMA) and the boot splash ────────────────────────────
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new(
        p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.DMA_CH3, p.DMA_CH4, Irqs, spi1_cfg,
    );
    let mut panel = Rp2350GeekBoard::new(spi1).into_display();
    let band: &'static mut [u8] = DISPLAY_BAND.take();
    panel.init(band).await;
    let mut screen = ScreenDriver::new(panel, &GEEK_240X135, band);
    let reset = reset_info(&boot_report);
    let mut splash = SplashView {
        step: BootStep::Storage,
        reset,
        border: DETAIL,
        board: "RP2350-Geek",
    };
    screen.show(&Screen::Splash(splash)).await;
    serial_println!("LCD ok");

    // ── Storage ──────────────────────────────────────────────────────────────
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();
    let smk_present = smk.is_some();

    // rp2350_geek_sdcard: SD card keystore on SPI0 (GPIO18/19/20, CS=GPIO23).
    #[cfg(feature = "rp2350_geek_sdcard")]
    let (store, ks_ok): (&'static mut _, bool) = {
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
        // SD cards need a pull-up on DO (MISO) until SPI mode is entered.
        embassy_rp::pac::PADS_BANK0
            .gpio(20)
            .modify(|w| w.set_pue(true));

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

        // Card identification can take seconds at 400 kHz: start it with a
        // full watchdog period.
        pico2hsm_firmware::watchdog::feed();
        let sd_chip = match pico2hsm_firmware::storage::sdcard::SdCardFlash::new(
            spi_device,
            embassy_time::Delay,
        ) {
            Ok(chip) => chip,
            Err(_) => halt_no_sd_card(&mut screen, &boot_report).await,
        };
        pico2hsm_firmware::watchdog::feed();
        serial_println!("SD card detected");

        // Card identified — raise SPI clock from 400 kHz to 25 MHz.
        spi0_bus_ref.lock(|bus| {
            let mut fast_cfg = SpiConfig::default();
            fast_cfg.frequency = pico2hsm_firmware::board::rp2350_geek::SD_SPI_FREQ_HZ;
            fast_cfg.phase = Phase::CaptureOnFirstTransition;
            fast_cfg.polarity = Polarity::IdleLow;
            bus.borrow_mut().set_config(&fast_cfg);
        });

        let (ks, ks_init) = new_keystore(sd_chip, smk);
        let ks_ok = ks_init.is_ok();
        if ks_ok {
            serial_println!("KeyStore ok (SD card)");
        } else {
            serial_println!("KeyStore init failed (SD)");
        }
        (KEYSTORE_CELL.init(ks), ks_ok)
    };

    // rp2350_geek_16m: QMI flash keystore (upper 2 MB of 16 MB QSPI flash).
    #[cfg(feature = "rp2350_geek_16m")]
    let (store, ks_ok): (&'static mut _, bool) = {
        let qmi_flash = embassy_rp::flash::Flash::<
            _,
            embassy_rp::flash::Blocking,
            { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
        >::new_blocking(p.FLASH);
        let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);
        let (ks, ks_init) = new_keystore(qmi, smk);
        let ks_ok = ks_init.is_ok();
        if ks_ok {
            serial_println!("KeyStore ok (QMI flash)");
        } else {
            serial_println!("KeyStore init failed (QMI)");
        }
        (KEYSTORE_CELL.init(ks), ks_ok)
    };

    // ── Dispatcher on core0, keys loaded, then core1 ─────────────────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        init_retry_counters(store);
        #[cfg(feature = "rsa")]
        init_rsa_pool(store);
        dispatcher_ref.load_keys_from_store(store);
        dispatcher_ref.migrate_domain(store);
    }
    publish_boot_snapshot(dispatcher_ref, boot_health(ks_ok, smk_present, store));
    {
        let inv = dispatcher_ref.display_snapshot().inventory;
        let keys = u16::from(inv.keys_hsm) + u16::from(inv.keys_piv) + u16::from(inv.keys_pgp);
        splash.step = BootStep::Keys(keys);
        screen.show(&Screen::Splash(splash)).await;
    }
    serial_println!("Keys loaded, spawning core1...");
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
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

    // ── USB ──────────────────────────────────────────────────────────────────
    splash.step = BootStep::Usb;
    screen.show(&Screen::Splash(splash)).await;
    let usb_driver = UsbDriver::new(p.USB, Irqs);
    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some(usb_serial());
    usb_config.max_power = 100;

    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();
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
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();
    let mut usb = builder.build();
    serial_println!("USB device ok, entering main loop");

    #[cfg(feature = "rp2350_geek_sdcard")]
    let storage = StorageKind::Sd;
    #[cfg(not(feature = "rp2350_geek_sdcard"))]
    let storage = StorageKind::Qmi;
    let info = StaticInfo {
        storage,
        detail: DETAIL,
        reset,
        board: splash.board,
    };

    join4(
        usb.run(),
        display_board_ccid_loop(&mut ccid, &mut cdc_sender),
        pico2hsm_firmware::display::task::run(screen, info),
        flash_service(store, dispatcher_ptr),
    )
    .await;
}

// ─── Pico 2 main function ─────────────────────────────────────────────────────

#[cfg(all(target_arch = "arm", feature = "pico2_4m"))]
async fn run_pico2_board(p: embassy_rp::Peripherals) {
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
    let smk_present = smk.is_some();

    let qmi_flash = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);

    let (ks, ks_init) = new_keystore(qmi, smk);
    let ks_ok = ks_init.is_ok();
    match ks_init {
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
    usb_config.serial_number = Some(usb_serial());
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
        init_retry_counters(store);
        #[cfg(feature = "rsa")]
        init_rsa_pool(store);
        dispatcher_ref.load_keys_from_store(store);
        dispatcher_ref.migrate_domain(store);
    }
    publish_boot_snapshot(dispatcher_ref, boot_health(ks_ok, smk_present, store));
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
                    Ok(mut apdu_bytes) => {
                        let epoch = ccid.apdu_epoch();
                        pico2hsm_firmware::APDU_EPOCH
                            .store(epoch, core::sync::atomic::Ordering::SeqCst);
                        board.led().set_status(LedStatus::Busy);
                        // No defmt logging here — the RTT buffer fills from trace-level
                        // embassy_rp USB logs; any defmt call here blocks Core0 before
                        // the APDU reaches Core1, causing a permanent hang.
                        send_to_core1(&mut apdu_bytes).await;
                        let response = match await_core1_response(&mut ccid).await {
                            Some(r) => r,
                            None => watchdog_reset(&mut ccid).await,
                        };
                        match send_and_wipe(&mut ccid, response, epoch).await {
                            Ok(()) => {
                                for _ in 0..16 {
                                    if !pico2hsm_firmware::transport::cdc_serial::drain_one(
                                        &mut cdc_sender,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                }
                            }
                            Err(CcidError::UsbDisconnected) => {
                                send_reset_to_core1().await;
                                let _ = recv_core1_response().await;
                                break;
                            }
                            Err(e) => defmt::error!(
                                "CCID: response not sent: {:?}",
                                defmt::Debug2Format(&e)
                            ),
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        send_reset_to_core1().await;
                        let _ = recv_core1_response().await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    embassy_futures::join::join3(usb_fut, ccid_fut, flash_service(store, dispatcher_ptr)).await;
}

// ─── Waveshare RP2350-LCD-1.47-B main function ───────────────────────────────

/// Initialise the SD card keystore on SPI1 in its own stack frame.
///
/// All SPI bus setup, SD card probe, CMD0 warmup, and keystore mount happen
/// here.  When this function returns, those temporaries (SPI config, SdCard
/// driver, KeyFilesystem, StorageManager) are freed — reclaiming ~2 KB of
/// stack that would otherwise persist through the entire async main loop.
///
/// `None` if no card answers (the caller shows E10 and waits for the
/// watchdog); otherwise the store and whether it initialised.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard"))]
fn init_sd_keystore(
    spi1: embassy_rp::Peri<'static, embassy_rp::peripherals::SPI1>,
    sck: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_10>,
    mosi: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_11>,
    miso: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_12>,
    cs_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_15>,
    smk: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Option<(&'static mut pico2hsm_firmware::storage::BoardKeyStore, bool)> {
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
    // before embedded-sdmmc's acquire() sequence.  Card identification can
    // take seconds at 400 kHz: start it with a full watchdog period.
    pico2hsm_firmware::watchdog::feed();
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

    let total_bytes = card.num_bytes().ok()?;
    defmt::info!("SD card: {} MiB", total_bytes / (1024 * 1024));
    let capacity_bytes = total_bytes.saturating_sub(4096);
    let sd_chip =
        pico2hsm_firmware::storage::sdcard::SdCardFlash::from_initialized(card, capacity_bytes);

    let (ks, ks_init) = new_keystore(sd_chip, smk);
    let ks_ok = ks_init.is_ok();
    if ks_ok {
        defmt::info!("KeyStore: initialized (SD card)");
    } else {
        defmt::warn!("KeyStore: init failed — SD card degraded");
    }
    Some((KEYSTORE_CELL.init(ks), ks_ok))
}

#[cfg(all(
    target_arch = "arm",
    any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard"
    )
))]
async fn run_waveshare_lcd_board(
    p: embassy_rp::Peripherals,
    boot_report: pico2hsm_firmware::watchdog::BootReport,
) {
    use embassy_futures::join::join4;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::pio::Pio;
    use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::waveshare_rp2350_lcd::{
        PioWs2812Writer, WavesharePanel, WaveshareRp2350LcdBoard, SPI_FREQ_HZ,
    };
    use pico2hsm_firmware::display::model::{reset_info, StaticInfo, StorageKind};
    use pico2hsm_firmware::display::view::{BootStep, Screen, SplashView};
    use pico2hsm_firmware::display::{ScreenDriver, DETAIL, WAVESHARE_320X172};
    use pico2hsm_firmware::transport::CcidTransport;

    // ── UART0 init for serial_debug macros (GPIO0=TX, GPIO1=RX, 115200 8N1) ──
    use embassy_rp::uart::{Config as UartConfig, Uart};
    let _dbg = Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, UartConfig::default());
    pico2hsm_firmware::serial_debug::uart1_write_bytes(b"\r\n\r\n");
    serial_println!("=== pico2hsm Waveshare RP2350-LCD-1.47-B boot ===");
    serial_println!("UART0 GPIO0=TX GPIO1=RX 115200 8N1");

    defmt::info!("Board: Waveshare RP2350-LCD-1.47-B initialising");

    // ── SPI0: LCD bus (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO4) ─────────────────
    // Async/DMA so band transfers yield to the executor.
    // DMA_CH1=TX, DMA_CH2=RX (RX is unused — LCD is write-only).
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new(
        p.SPI0, p.PIN_18, p.PIN_19, p.PIN_4, p.DMA_CH1, p.DMA_CH2, Irqs, spi0_cfg,
    );

    // ── SPI1: SD card bus (16m variant: unused but kept configured) ──────────
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let board = {
        let mut spi1_cfg = SpiConfig::default();
        spi1_cfg.frequency = SPI_FREQ_HZ;
        spi1_cfg.phase = Phase::CaptureOnFirstTransition;
        spi1_cfg.polarity = Polarity::IdleLow;
        let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);
        WaveshareRp2350LcdBoard::new(spi0, spi1)
    };
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let board = WaveshareRp2350LcdBoard::new_lcd_only(spi0);

    // ── LCD control pins (DC=16, CS=17, RST=20, BL=21) and the WS2812B ───────
    let dc = Output::new(p.PIN_16, Level::Low);
    let cs = Output::new(p.PIN_17, Level::High);
    let rst = Output::new(p.PIN_20, Level::High);
    let bl = Output::new(p.PIN_21, Level::Low);
    let Pio {
        mut common, sm0, ..
    } = Pio::new(p.PIO0, Irqs);
    let ws2812_program = PioWs2812Program::new(&mut common);
    let ws2812 = PioWs2812::new(&mut common, sm0, p.DMA_CH0, Irqs, p.PIN_22, &ws2812_program);

    let mut panel = WavesharePanel::new(
        board.into_spi0(),
        dc,
        cs,
        rst,
        bl,
        PioWs2812Writer::new(ws2812),
    );
    let band: &'static mut [u8] = DISPLAY_BAND.take();
    panel.init(band).await;
    let mut screen = ScreenDriver::new(panel, &WAVESHARE_320X172, band);
    let reset = reset_info(&boot_report);
    let mut splash = SplashView {
        step: BootStep::Storage,
        reset,
        border: DETAIL,
        board: "RP2350-LCD-1.47",
    };
    screen.show(&Screen::Splash(splash)).await;

    // ── Storage ──────────────────────────────────────────────────────────────
    // None on an unprovisioned release build: the keystore then refuses
    // to store keys rather than use a public key (see otp::boot_storage_master_key).
    let smk = pico2hsm_firmware::security::otp::boot_storage_master_key();
    let smk_present = smk.is_some();

    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let (store, ks_ok): (&'static mut _, bool) =
        match init_sd_keystore(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.PIN_15, smk) {
            Some(s) => s,
            None => halt_no_sd_card(&mut screen, &boot_report).await,
        };

    // waveshare_rp2350_lcd_16m: internal QMI flash keystore (upper 2 MB).
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let (store, ks_ok): (&'static mut _, bool) = {
        let qmi_flash = embassy_rp::flash::Flash::<
            _,
            embassy_rp::flash::Blocking,
            { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
        >::new_blocking(p.FLASH);
        let qmi = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_flash);
        let (ks, ks_init) = new_keystore(qmi, smk);
        let ks_ok = ks_init.is_ok();
        if ks_ok {
            defmt::info!("KeyStore: initialized (waveshare_rp2350_lcd_16m internal flash)");
        } else {
            defmt::warn!("KeyStore: init failed");
        }
        (KEYSTORE_CELL.init(ks), ks_ok)
    };

    // ── Dispatcher on core0, keys loaded, then core1 ─────────────────────────
    let dispatcher_ref: &'static mut pico2hsm_firmware::apdu::dispatcher::Dispatcher =
        pico2hsm_firmware::apdu::dispatcher::Dispatcher::init_in_place(DISPATCHER_CELL.uninit());
    {
        use pico2hsm_firmware::storage::KeyStore as _;
        init_retry_counters(store);
        #[cfg(feature = "rsa")]
        init_rsa_pool(store);
        dispatcher_ref.load_keys_from_store(store);
        dispatcher_ref.migrate_domain(store);
    }
    publish_boot_snapshot(dispatcher_ref, boot_health(ks_ok, smk_present, store));
    {
        let inv = dispatcher_ref.display_snapshot().inventory;
        let keys = u16::from(inv.keys_hsm) + u16::from(inv.keys_piv) + u16::from(inv.keys_pgp);
        splash.step = BootStep::Keys(keys);
        screen.show(&Screen::Splash(splash)).await;
    }
    let dispatcher_ptr = dispatcher_ref as *mut pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let dispatcher_send = DispatcherPtr(dispatcher_ptr, store as *mut _);

    spawn_core1(
        p.CORE1,
        unsafe { &mut *addr_of_mut!(CORE1_STACK) },
        move || {
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

    // ── USB CCID + CDC-ACM serial transport ─────────────────────────────────
    splash.step = BootStep::Usb;
    screen.show(&Screen::Splash(splash)).await;
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();
    let usb_driver = UsbDriver::new(p.USB, Irqs);
    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some(usb_serial());
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

    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    let storage = StorageKind::Sd;
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let storage = StorageKind::Qmi;
    let info = StaticInfo {
        storage,
        detail: DETAIL,
        reset,
        board: splash.board,
    };

    join4(
        usb.run(),
        display_board_ccid_loop(&mut ccid, &mut cdc_sender),
        pico2hsm_firmware::display::task::run(screen, info),
        flash_service(store, dispatcher_ptr),
    )
    .await;
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
