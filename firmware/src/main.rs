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
use embassy_rp::multicore::{Stack, spawn_core1};
#[cfg(target_arch = "arm")]
use embassy_rp::spinlock_mutex::SpinlockRawMutex;
#[cfg(target_arch = "arm")]
use embassy_sync::channel::Channel;
#[cfg(target_arch = "arm")]
use static_cell::StaticCell;

// ─── Core1 stack and executor (ARM only) ─────────────────────────────────────

/// Stack for the core1 Embassy executor.  128 KB needed: ScHsmState holds
/// 16 × 2 KB EF entries inline, plus multiple 4 KB response Vec<u8, 4096>
/// temporaries across the dispatch call chain.
#[cfg(target_arch = "arm")]
static mut CORE1_STACK: Stack<262144> = Stack::new();
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

/// One-time initialised key store — lives for the duration of the firmware.
/// Owned by core1 dispatcher task; initialised by the board run function before
/// spawning core1.
#[cfg(target_arch = "arm")]
static KEYSTORE_CELL: StaticCell<
    pico2hsm_firmware::storage::FlashKeyStore<pico2hsm_firmware::storage::BoardChip>
> = StaticCell::new();

/// Dispatcher — stored in BSS outside the async task state machine so that
/// the `dispatcher_task` pool does not need to hold the full 50 KB Dispatcher
/// struct (which would overflow when combined with the 4 KB APDU/response
/// buffers that are also live at each await point).
#[cfg(target_arch = "arm")]
static DISPATCHER_CELL: StaticCell<pico2hsm_firmware::apdu::dispatcher::Dispatcher> =
    StaticCell::new();

/// APDU dispatcher task — runs on core1 so that blocking ECC crypto does not
/// starve the USB driver which runs cooperatively on core0.
///
/// `store` is the persistent key store initialised by the board run function.
#[cfg(target_arch = "arm")]
#[embassy_executor::task]
async fn dispatcher_task(
    store: &'static mut pico2hsm_firmware::storage::FlashKeyStore<
        pico2hsm_firmware::storage::BoardChip,
    >,
) {
    use pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    // Core1 must not call defmt: embassy-rp's critical_section uses Spinlock31; if Core1
    // holds it while spinning for RTT buffer space, Core0 blocks with interrupts disabled
    // and USB processing stalls entirely.
    let dispatcher: &'static mut Dispatcher = DISPATCHER_CELL.init(Dispatcher::new());
    dispatcher.load_keys_from_store(store);
    loop {
        let apdu_bytes = APDU_CHANNEL.receive().await;
        // No defmt logging inside the receive loop.  All embassy_rp TRACE logs
        // from Core0 fill the RTT buffer rapidly; any defmt write from Core1
        // here would block on BLOCK_IF_FULL mode and deadlock both cores.
        if apdu_bytes.is_empty() {
            // Empty APDU = reset signal issued by core0 on USB disconnect.
            *dispatcher = Dispatcher::new();
            dispatcher.load_keys_from_store(store);
            let _ = RESP_CHANNEL.send(heapless::Vec::new()).await;
        } else {
            let response = dispatcher.dispatch_with_store(&apdu_bytes, store);
            let _ = RESP_CHANNEL.send(response).await;
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
        feature = "rp2350_geek_sdcard_dual",
    ))]
    {
        run_geek_board(p).await;
    }

    // ── Fallback ─────────────────────────────────────────────────────────────
    #[cfg(not(any(
        feature = "rp2350_one_4m",
        feature = "rp2350_one_16m",
        feature = "rp2350_geek_16m",
        feature = "rp2350_geek_sdcard",
        feature = "rp2350_geek_sdcard_dual",
        feature = "rp2354_embedded",
        feature = "pico2_4m",
    )))]
    {
        defmt::error!("No board feature flag set — spinning forever");
        loop { Timer::after_millis(1000).await; }
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

    // ── Storage initialization (rp2350_one: RAID-1 SPI flash pair) ───────────
    // TODO (board-storage wiring): The SPI buses spi0/spi1 are consumed by
    // Rp2350OneBoard::new() above and stored as board.spi0/board.spi1.  To use
    // them for SpiFlash storage, the board struct would need to be refactored
    // so that SPI buses are either:
    //   a) consumed into SpiFlash before board construction (requires a LED-only
    //      board constructor), or
    //   b) extracted from the board struct (partial move; incompatible with
    //      subsequent board.led() calls in the CCID loop).
    // For now we initialise the keystore with AnyChip::Empty (no physical chips)
    // so that the storage infrastructure compiles and the dispatcher_task()
    // parameter is wired in.  Real SPI flash wiring will be added once the board
    // struct is refactored.
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);
    let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    // No chips added — degraded mode (all key operations will fail gracefully).
    let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
    let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
    match ks.init() {
        Ok(()) => defmt::info!("KeyStore: initialized (rp2350_one — degraded, no chips)"),
        Err(_) => defmt::warn!("KeyStore: init failed — degraded mode"),
    }
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // ── USB CCID transport ───────────────────────────────────────────────────
    let usb_driver = UsbDriver::new(p.USB, Irqs);

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;

    // USB descriptor buffers — must live for the duration of run_one_board.
    let mut config_descriptor_buf = [0u8; 256];
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

    // Finalise the USB device descriptor.
    let mut usb = builder.build();

    defmt::info!("pico2hsm (RP2350-One): USB CCID ready, entering main loop");
    board.led().set_status(LedStatus::Ready);

    // ── Spawn APDU dispatcher on core1 ───────────────────────────────────────
    // Blocking ECC crypto (P-384 sign ≈ 2–3 s) must not starve the USB driver.
    // By running the dispatcher on core1 and awaiting the response channel on
    // core0, the Embassy executor on core0 continues to poll `usb.run()` while
    // core1 computes.
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
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
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {}
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
    feature = "rp2350_geek_sdcard_dual",
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
    let mut dbg = Uart::new_blocking(p.UART1, p.PIN_4, p.PIN_5, UartConfig::default());

    // ── Serial helper macros ─────────────────────────────────────────────────
    macro_rules! serial_ln {
        ($msg:literal) => {{
            let _ = dbg.blocking_write(b"[GEEK] ");
            let _ = dbg.blocking_write($msg.as_bytes());
            let _ = dbg.blocking_write(b"\r\n");
        }};
    }
    macro_rules! serial_fmt {
        ($($arg:tt)*) => {{
            use core::fmt::Write as _;
            let mut _buf = heapless::String::<256>::new();
            let _ = core::write!(_buf, "[GEEK] {}\r\n", core::format_args!($($arg)*));
            let _ = dbg.blocking_write(_buf.as_bytes());
        }};
    }

    let _ = dbg.blocking_write(b"\r\n\r\n");
    serial_ln!("=== pico2hsm RP2350-Geek boot ===");
    serial_ln!("UART1 GPIO4=TX GPIO5=RX 115200 8N1");

    // ── Security checks ──────────────────────────────────────────────────────
    serial_ln!("security_checks()...");
    pico2hsm_firmware::security::boot::security_checks();
    serial_ln!("security_checks() ok");

    // ── Allocator ────────────────────────────────────────────────────────────
    serial_ln!("allocator init...");
    pico2hsm_firmware::allocator::init();
    serial_ln!("allocator ok");

    // ── OTP ──────────────────────────────────────────────────────────────────
    serial_ln!("OTP init...");
    let otp = pico2hsm_firmware::security::otp::Otp::new();
    let provisioned = otp.is_provisioned();
    let prod_mode = otp.is_production_mode();
    serial_fmt!("OTP ok: provisioned={} production_mode={}", provisioned, prod_mode);
    defmt::info!("OTP: provisioned={}, production_mode={}", provisioned, prod_mode);

    serial_ln!("OTP derive_smk...");
    match pico2hsm_firmware::security::otp::derive_smk() {
        Ok(_) => serial_ln!("derive_smk ok"),
        Err(_) => serial_ln!("derive_smk failed (unprovisioned — continuing)"),
    }

    // ── CHECKPOINT 0 ─────────────────────────────────────────────────────────
    serial_ln!("--- run_geek_board ---");
    defmt::info!("Board: RP2350-Geek initialising");

    // ── CHECKPOINT 1 — SPI buses ─────────────────────────────────────────────
    serial_ln!("SPI0 init (SCK=18 MOSI=19 MISO=20)...");
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let spi0 = Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, spi0_cfg);
    serial_fmt!("SPI0 ok @ {} Hz", SPI_FREQ_HZ);

    serial_ln!("SPI1 init (SCK=10 MOSI=11 MISO=12)...");
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);
    serial_fmt!("SPI1 ok @ {} Hz", SPI_FREQ_HZ);

    // ── CHECKPOINT 2 — board struct ──────────────────────────────────────────
    serial_ln!("Board struct init...");
    let mut board = Rp2350GeekBoard::new(spi0, spi1);
    board.led().set_status(LedStatus::Busy);
    serial_ln!("Board ok, LED=Busy");

    #[cfg(feature = "rp2350_geek_sdcard")]
    {
        serial_fmt!("SDCard slot active CS=GPIO{}", pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS);
        defmt::info!("SDCard slot active — CS on GPIO {}", pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS);
    }
    #[cfg(feature = "rp2350_geek_sdcard_dual")]
    {
        serial_fmt!("Dual SDCard CS0=GPIO{} CS1=GPIO{}",
            pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS,
            pico2hsm_firmware::board::rp2350_geek::SDCARD1_CS);
        defmt::info!("Dual SDCard active — CS0=GPIO {}, CS1=GPIO {}",
            pico2hsm_firmware::board::rp2350_geek::SDCARD0_CS,
            pico2hsm_firmware::board::rp2350_geek::SDCARD1_CS);
    }

    // ── CHECKPOINT 3 — USB driver ────────────────────────────────────────────
    serial_ln!("USB driver init...");
    let usb_driver = UsbDriver::new(p.USB, Irqs);
    serial_ln!("USB driver ok");

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;
    serial_fmt!("USB VID={:#06x} PID={:#06x}", USB_VID, USB_PID);

    // ── CHECKPOINT 4 — USB descriptor builder ───────────────────────────────
    serial_ln!("USB builder init...");
    let mut config_descriptor_buf = [0u8; 256];
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
    serial_ln!("USB builder ok");

    // ── CHECKPOINT 5 — CCID class registration ───────────────────────────────
    serial_ln!("CCID class register...");
    let mut ccid = CcidTransport::new(&mut builder);
    serial_ln!("CCID class ok");

    // ── CHECKPOINT 6 — finalise USB device ──────────────────────────────────
    serial_ln!("USB device build...");
    let mut usb = builder.build();
    serial_ln!("USB device ok");

    board.led().set_status(LedStatus::Ready);
    serial_ln!("LED=Ready — entering main loop");
    defmt::info!("pico2hsm (RP2350-Geek): USB CCID ready, entering main loop");

    // ── Storage initialization (rp2350_geek: RAID-1 SPI flash pair) ──────────
    // TODO (board-storage wiring): Same constraint as rp2350_one — spi0/spi1
    // are owned by Rp2350GeekBoard.  Real SPI flash wiring requires a board
    // struct refactor (separate LED from SPI ownership) so that the buses can
    // be consumed into SpiFlash instances.  For now, initialise with no chips
    // (AnyChip::Empty) so the storage plumbing compiles and the store parameter
    // is wired to the dispatcher.
    serial_ln!("KeyStore init (degraded — no chips)...");
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);
    let fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
    let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
    match ks.init() {
        Ok(()) => serial_ln!("KeyStore ok (degraded — no chips)"),
        Err(_) => serial_ln!("KeyStore init failed"),
    }
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // ── CHECKPOINT 7 — spawn core1 dispatcher, then run USB + CCID on core0 ──
    // NOTE: CORE1_STACK and CORE1_EXECUTOR are module-level statics shared by
    // all board variants; only one board function runs per firmware build.
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
    });

    let usb_fut = usb.run();
    let ccid_fut = async {
        let mut apdu_count: u32 = 0;
        loop {
            serial_ln!("waiting for USB connect...");
            ccid.wait_connected().await;
            serial_ln!("USB connected");

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        apdu_count += 1;
                        board.led().set_status(LedStatus::Busy);
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {}
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
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);

    // ── USB CCID transport ───────────────────────────────────────────────────
    let usb_driver = UsbDriver::new(p.USB, Irqs);

    let mut usb_config = UsbConfig::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("pico2hsm");
    usb_config.product = Some("pico2hsm SC-HSM");
    usb_config.serial_number = Some("0001");
    usb_config.max_power = 100;

    let mut config_descriptor_buf = [0u8; 256];
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
    let mut usb = builder.build();

    defmt::info!("pico2hsm (Pico 2): USB CCID ready, entering main loop");
    board.led().set_status(LedStatus::Ready);

    defmt::info!("core0: spawning core1");
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
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
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        match ccid.send_response(&response).await {
                            Ok(()) => {}
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

// ─── Host stub ────────────────────────────────────────────────────────────────

/// No-op entry point for non-ARM builds (e.g., `cargo test --target x86_64`).
/// The firmware is only meaningful on ARM; this stub allows the binary target
/// to compile without errors during host-side testing.
#[cfg(not(target_arch = "arm"))]
fn main() {}
