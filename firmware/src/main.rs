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
static mut CORE1_STACK: Stack<131072> = Stack::new();
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

/// APDU dispatcher task — runs on core1 so that blocking ECC crypto does not
/// starve the USB driver which runs cooperatively on core0.
#[cfg(target_arch = "arm")]
#[embassy_executor::task]
async fn dispatcher_task() {
    use pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    let mut dispatcher = Dispatcher::new();
    loop {
        let apdu_bytes = APDU_CHANNEL.receive().await;
        if apdu_bytes.is_empty() {
            // Empty APDU = reset signal issued by core0 on USB disconnect.
            defmt::info!("Dispatcher: session reset (USB disconnect)");
            dispatcher = Dispatcher::new();
            // Ack so core0 knows the reset completed.
            let _ = RESP_CHANNEL.send(heapless::Vec::new()).await;
        } else {
            let response = dispatcher.dispatch(&apdu_bytes);
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

    // Sentinel A: firmware reached this point (before defmt).
    // Read addr 0x20004000; if 0xDEAD_A000 the firmware reached here.
    #[cfg(debug_assertions)]
    unsafe { core::ptr::write_volatile(0x20004000 as *mut u32, 0xDEAD_A000_u32); }

    defmt::info!("pico2hsm: peripherals initialised");

    // Sentinel B: firmware returned from defmt::info! (defmt did not block/panic).
    // Read addr 0x20004004; if 0xDEAD_B000 the defmt call returned normally.
    #[cfg(debug_assertions)]
    unsafe { core::ptr::write_volatile(0x20004004 as *mut u32, 0xDEAD_B000_u32); }


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
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task().unwrap()));
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
                        if apdu_bytes.len() >= 4 { defmt::info!("APDU {:02X} {:02X} {:02X} {:02X} len={}", apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3], apdu_bytes.len()); } else { defmt::trace!("APDU: {} bytes", apdu_bytes.len()); }

                        // Send APDU to core1. While core1 computes (P-384/P-521 ECC
                        // can exceed pcscd's ~2.5 s timeout), send CCID time extension
                        // packets every 1.5 s so the host resets its countdown.
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        defmt::debug!("CCID: time extension sent");
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            // USB dropped while sending the extension.
                                            // Drain the eventual core1 response so the
                                            // channel is empty, then treat as disconnect.
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        if response.len() >= 2 { defmt::info!("  SW {:02X}{:02X}", response[response.len()-2], response[response.len()-1]); }

                        match ccid.send_response(&response).await {
                            Ok(()) => {}
                            Err(CcidError::UsbDisconnected) => {
                                defmt::info!("CCID: disconnected mid-response");
                                // Signal core1 to reset its session state.
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break; // re-enter outer loop → wait_connected()
                            }
                            Err(_) => {
                                defmt::warn!("CCID: send_response error");
                            }
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        defmt::info!("CCID: USB disconnected — resetting session state");
                        // Signal core1 to reset its session state.
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
                        board.led().set_status(LedStatus::Ready);
                        break; // re-enter outer loop → wait_connected()
                    }
                    Err(_) => {
                        defmt::warn!("CCID: protocol error, recovering");
                    }
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

    // ── CHECKPOINT 7 — spawn core1 dispatcher, then run USB + CCID on core0 ──
    // NOTE: CORE1_STACK and CORE1_EXECUTOR are module-level statics shared by
    // all board variants; only one board function runs per firmware build.
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task().unwrap()));
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
                        serial_fmt!("APDU #{} len={}", apdu_count, apdu_bytes.len());
                        if apdu_bytes.len() >= 4 { defmt::info!("APDU {:02X} {:02X} {:02X} {:02X} len={}", apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3], apdu_bytes.len()); } else { defmt::trace!("APDU: {} bytes", apdu_bytes.len()); }

                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        serial_ln!("CCID: time extension sent");
                                        defmt::debug!("CCID: time extension sent");
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        if response.len() >= 2 { defmt::info!("  SW {:02X}{:02X}", response[response.len()-2], response[response.len()-1]); }
                        serial_fmt!("response len={}", response.len());

                        match ccid.send_response(&response).await {
                            Ok(()) => {
                                serial_ln!("response sent ok");
                            }
                            Err(CcidError::UsbDisconnected) => {
                                serial_ln!("USB disconnected mid-response; session reset");
                                defmt::info!("CCID: disconnected mid-response");
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {
                                serial_ln!("send_response error");
                                defmt::warn!("CCID: send_response error");
                            }
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        serial_ln!("USB disconnected; session reset");
                        defmt::info!("CCID: USB disconnected — resetting session state");
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {
                        serial_ln!("CCID protocol error, recovering");
                        defmt::warn!("CCID: protocol error, recovering");
                    }
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

    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task().unwrap()));
    });

    let usb_fut = usb.run();
    let ccid_fut = async {
        loop {
            ccid.wait_connected().await;

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        board.led().set_status(LedStatus::Busy);
                        if apdu_bytes.len() >= 4 { defmt::info!("APDU {:02X} {:02X} {:02X} {:02X} len={}", apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3], apdu_bytes.len()); } else { defmt::trace!("APDU: {} bytes", apdu_bytes.len()); }

                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        let response = {
                            use embassy_futures::select::{select, Either};
                            loop {
                                match select(RESP_CHANNEL.receive(), embassy_time::Timer::after_millis(1500)).await {
                                    Either::First(r) => break r,
                                    Either::Second(_) => {
                                        defmt::debug!("CCID: time extension sent");
                                        if let Err(CcidError::UsbDisconnected) = ccid.send_time_extension().await {
                                            let _ = RESP_CHANNEL.receive().await;
                                            break heapless::Vec::new();
                                        }
                                    }
                                }
                            }
                        };
                        if response.len() >= 2 { defmt::info!("  SW {:02X}{:02X}", response[response.len()-2], response[response.len()-1]); }

                        match ccid.send_response(&response).await {
                            Ok(()) => {}
                            Err(CcidError::UsbDisconnected) => {
                                defmt::info!("CCID: disconnected mid-response");
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {
                                defmt::warn!("CCID: send_response error");
                            }
                        }
                        board.led().set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        defmt::info!("CCID: USB disconnected — resetting session state");
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
                        board.led().set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {
                        defmt::warn!("CCID: protocol error, recovering");
                    }
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
