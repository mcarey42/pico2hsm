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

/// Stack for the core1 Embassy executor.  Peak usage ~65 KB: ScHsmState holds
/// 16 × 2 KB EF entries inline (~38 KB total state) plus multiple 4 KB response
/// Vec<u8, 4096> temporaries across the dispatch call chain (~16 KB peak).
/// 128 KB gives ~2× headroom over measured peak usage.
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

/// One-time initialised key store — lives for the duration of the firmware.
/// Owned by core1 dispatcher task; initialised by the board run function before
/// spawning core1.
#[cfg(target_arch = "arm")]
static KEYSTORE_CELL: StaticCell<pico2hsm_firmware::storage::BoardKeyStore> = StaticCell::new();

/// Hybrid keystore health status — cross-core atomic flags read by core0 for
/// LED status, written by core1 after each APDU dispatch.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
static HYBRID_DEGRADED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
static HYBRID_FLASH_ERROR: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Key count — updated by core1 dispatcher after each APDU dispatch.
/// Read by core0 board runners to display key count on LCD.
#[cfg(target_arch = "arm")]
static KEY_COUNT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

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
    store: &'static mut pico2hsm_firmware::storage::BoardKeyStore,
) {
    use pico2hsm_firmware::apdu::dispatcher::Dispatcher;
    use pico2hsm_firmware::storage::KeyStore;
    // Core1 must not call defmt: embassy-rp's critical_section uses Spinlock31; if Core1
    // holds it while spinning for RTT buffer space, Core0 blocks with interrupts disabled
    // and USB processing stalls entirely.

    // Seed the software CSPRNG from hardware TRNG before any crypto operations.
    // reseed() does not call defmt, so it is safe to call here on Core1.
    let _ = pico2hsm_firmware::crypto::rng::reseed();

    let dispatcher: &'static mut Dispatcher = DISPATCHER_CELL.init(Dispatcher::new());
    dispatcher.load_keys_from_store(store);

    // ── Hybrid variant: poll_recovery on 5-second timer between APDUs ────────
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard_hybrid")]
    {
        use embassy_futures::select::{select, Either};
        use embassy_time::Timer;
        loop {
            match select(APDU_CHANNEL.receive(), Timer::after_secs(5)).await {
                Either::First(apdu_bytes) => {
                    if apdu_bytes.is_empty() {
                        *dispatcher = Dispatcher::new();
                        dispatcher.load_keys_from_store(store);
                        let _ = RESP_CHANNEL.send(heapless::Vec::new()).await;
                    } else {
                        let response = dispatcher.dispatch_with_store(&apdu_bytes, store);
                        let _ = RESP_CHANNEL.send(response).await;
                    }
                    // Update cross-core health status atomics.
                    HYBRID_DEGRADED.store(
                        store.is_degraded(),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                    HYBRID_FLASH_ERROR.store(
                        !store.is_flash_healthy(),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                    KEY_COUNT.store(
                        store.enumerate_keys().len().min(255) as u8,
                        core::sync::atomic::Ordering::Relaxed,
                    );
                }
                Either::Second(_) => {
                    if store.is_degraded() {
                        let _ = store.poll_recovery();
                        HYBRID_DEGRADED.store(
                            store.is_degraded(),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
            }
        }
    }

    // ── Non-hybrid variants: plain receive loop ──────────────────────────────
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
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
        KEY_COUNT.store(
            store.enumerate_keys().len().min(255) as u8,
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

    // ── Pico 2 hybrid RAID-1 (QMI flash + SD card): security + OTP + board loop
    #[cfg(feature = "pico2_4m_sdcard_hybrid")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_pico2_sdcard_hybrid_board(p).await;
    }

    // ── Pico 2 with SD card keystore: security + OTP + board loop ────────────
    #[cfg(feature = "pico2_4m_sdcard")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_pico2_sdcard_board(p).await;
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

    // ── Waveshare RP2350-LCD-1.47-B (QMI, single SD, and dual-SD variants) ──
    #[cfg(any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
        feature = "waveshare_rp2350_lcd_sdcard_dual",
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

    // ── Waveshare RP2350-LCD-1.47-B hybrid RAID-1 (QMI flash + SD card) ─────
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard_hybrid")]
    {
        pico2hsm_firmware::security::boot::security_checks();
        pico2hsm_firmware::allocator::init();

        let otp = pico2hsm_firmware::security::otp::Otp::new();
        defmt::info!("OTP: provisioned={} production={}", otp.is_provisioned(), otp.is_production_mode());
        match pico2hsm_firmware::security::otp::derive_smk() {
            Ok(_) => defmt::info!("OTP: SMK derived"),
            Err(_) => defmt::warn!("OTP: derive_smk failed — unprovisioned?"),
        }

        run_waveshare_lcd_hybrid_board(p).await;
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
        feature = "pico2_4m_sdcard",
        feature = "pico2_4m_sdcard_hybrid",
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard",
        feature = "waveshare_rp2350_lcd_sdcard_dual",
        feature = "waveshare_rp2350_lcd_sdcard_hybrid",
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
                            Ok(()) => {
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
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

    // SPI1 LCD bus — Async/DMA mode so flush() yields to the executor during
    // the ~17 ms 63 KB framebuffer transfer, keeping USB alive.
    // DMA_CH3=TX, DMA_CH4=RX (RX is unused — LCD is write-only).
    serial_ln!("SPI1 init (SCK=10 MOSI=11 MISO=12, async DMA)...");
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.DMA_CH3, p.DMA_CH4, Irqs, spi1_cfg);
    serial_fmt!("SPI1 ok @ {} Hz (async DMA)", pico2hsm_firmware::board::rp2350_geek::LCD_SPI_FREQ_HZ);

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

    // ── CHECKPOINT 3.5 — CDC-ACM state (must be before descriptor buffers) ───
    // cdc_state must be declared before the builder and descriptor buffers so
    // that it is dropped AFTER them (Rust drops in reverse declaration order).
    use pico2hsm_firmware::transport::cdc_serial::{CdcAcmClass, CdcAcmState};
    let mut cdc_state = CdcAcmState::new();

    // ── CHECKPOINT 4 — USB descriptor builder ───────────────────────────────
    serial_ln!("USB builder init...");
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
    serial_ln!("USB builder ok");

    // ── CHECKPOINT 5 — CCID class registration ───────────────────────────────
    serial_ln!("CCID class register...");
    let mut ccid = CcidTransport::new(&mut builder);
    serial_ln!("CCID class ok");

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

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

    // Set provisioning status for display.
    // (qmi_ok/sd_ok left as None — geek board doesn't track individual store health yet)

    // ── CHECKPOINT 7 — spawn core1 dispatcher, then run USB + CCID on core0 ──
    // NOTE: CORE1_STACK and CORE1_EXECUTOR are module-level statics shared by
    // all board variants; only one board function runs per firmware build.
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
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
            serial_ln!("waiting for USB connect...");
            ccid.wait_connected().await;
            serial_ln!("USB connected");
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

                        let _ = APDU_CHANNEL.send(apdu_bytes).await;

                        // Wait for core1 response (with time extensions every 1.5s)
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
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs = embassy_time::Instant::now().as_secs() as u32;
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time) >= LAST_OP_DISPLAY_SECS {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    pico2hsm_firmware::display::render(board.led(), &display_state, &layout);
                                    board.led().flush().await;
                                }
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
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
                            Ok(()) => {
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
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

// ─── Pico 2 + SD card keystore main function ─────────────────────────────────

#[cfg(all(target_arch = "arm", feature = "pico2_4m_sdcard"))]
async fn run_pico2_sdcard_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::pico2::GpioLed;
    use pico2hsm_firmware::board::{LedController, LedStatus};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: Pico 2 + SD card initialising");

    // ── LED (GPIO25 onboard LED) ──────────────────────────────────────────────
    let mut led = GpioLed::new(p.PIN_25);
    led.set_status(LedStatus::Busy);

    // ── Storage initialisation: SD card on SPI1 (GPIO10/11/12, CS=GPIO15) ────
    // Same pin assignment as the Waveshare RP2350-LCD-1.47-B built-in SD slot.
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);

    let store: &'static mut _ = {
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::blocking_mutex::Mutex;
        use static_cell::StaticCell;

        // SPI1 at 400 kHz — SD spec requires ≤400 kHz for card identification.
        // embedded-sdmmc does NOT change the bus speed after init; the host
        // must supply the correct initialization clock.  Jumper-wire runs are
        // more sensitive than PCB traces; 400 kHz is the safe universal value.
        let mut spi1_cfg = SpiConfig::default();
        spi1_cfg.frequency = 400_000;
        spi1_cfg.phase = Phase::CaptureOnFirstTransition;
        spi1_cfg.polarity = Polarity::IdleLow;
        let spi1_bus = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

        // Wrap SPI1 in a shared-bus SpiDevice with CS=GPIO15.
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

        let delay = embassy_time::Delay;
        let sd_chip = pico2hsm_firmware::storage::sdcard::SdCardFlash::new(spi_device, delay)
            .expect("SD card init failed");

        let mut fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        fs.add_chip(sd_chip).expect("add SD chip");
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => defmt::info!("KeyStore: initialized (pico2_4m_sdcard — SD card)"),
            Err(_) => defmt::warn!("KeyStore: init failed — SD card degraded"),
        }
        debug_dump_storage(&ks);
        KEYSTORE_CELL.init(ks)
    };

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

    let mut ccid = CcidTransport::new(&mut builder);

    // CDC-ACM serial logger — /dev/ttyACMx for daemon diagnostics + debug.
    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    let mut usb = builder.build();

    defmt::info!("pico2hsm (Pico 2 + SD card): USB CCID+CDC ready, entering main loop");
    led.set_status(LedStatus::Ready);

    defmt::info!("core0: spawning core1");
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
    });
    defmt::info!("core0: core1 spawned, building usb_fut");

    let usb_fut = usb.run();
    let ccid_fut = async {
        defmt::info!("core0: ccid_fut: starting wait_connected");
        loop {
            ccid.wait_connected().await;
            defmt::info!("core0: USB connected");

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        led.set_status(LedStatus::Busy);
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
                            Ok(()) => {
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {}
                        }
                        led.set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
                        led.set_status(LedStatus::Ready);
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    };

    join(usb_fut, ccid_fut).await;
}

// ─── Pico 2 hybrid RAID-1 (QMI flash + SD card) main function ───────────────
//
// This variant is functionally identical to waveshare_rp2350_lcd_sdcard_hybrid
// but targets the stock Pico 2 (no LCD, no WS2812B).  It exists specifically
// to allow hybrid RAID-1 init debugging via probe-rs RTT on a board that has
// a CMSIS-DAP debug probe attached.  Every init step emits a defmt trace line
// so that exact failure points are visible in the RTT log.

#[cfg(all(target_arch = "arm", feature = "pico2_4m_sdcard_hybrid"))]
async fn run_pico2_sdcard_hybrid_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};
    use embedded_sdmmc::SdCard;
    use static_cell::StaticCell;

    use pico2hsm_firmware::board::pico2::GpioLed;
    use pico2hsm_firmware::board::{LedController, LedStatus};
    use pico2hsm_firmware::storage::sdcard::{
        check_sd_signature, write_sd_signature, SdCardCheckResult,
    };
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: Pico 2 hybrid (QMI flash + SD card) initialising");

    // ── LED ──────────────────────────────────────────────────────────────────
    let mut led = GpioLed::new(p.PIN_25);
    led.set_status(LedStatus::Busy);

    // ── SPI1: SD card bus at 400 kHz (SD spec requires ≤400 kHz for init) ───
    defmt::trace!("HYBRID [1/12] SPI1 init @ 400 kHz");
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = 400_000;
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::blocking_mutex::Mutex;
    static SPI1_BUS: StaticCell<Mutex<CriticalSectionRawMutex, core::cell::RefCell<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
    >>> = StaticCell::new();
    let spi1_bus = SPI1_BUS.init(Mutex::new(core::cell::RefCell::new(spi1)));
    let sd_cs = Output::new(p.PIN_15, Level::High);
    let spi_device = embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice::new(
        spi1_bus, sd_cs,
    );
    defmt::trace!("HYBRID [1/12] SPI1 + shared-bus SpiDevice ready");

    // ── Device fingerprint from OTP CHIPID ───────────────────────────────────
    defmt::trace!("HYBRID [2/12] reading OTP CHIPID for device fingerprint");
    let device_id: [u8; 8] = {
        let otp = unsafe { embassy_rp::pac::OTP_DATA_RAW };
        let mut id = [0u8; 8];
        let c0 = otp.chipid0().read() as u16;
        let c1 = otp.chipid1().read() as u16;
        let c2 = otp.chipid2().read() as u16;
        let c3 = otp.chipid3().read() as u16;
        id[0..2].copy_from_slice(&c0.to_le_bytes());
        id[2..4].copy_from_slice(&c1.to_le_bytes());
        id[4..6].copy_from_slice(&c2.to_le_bytes());
        id[6..8].copy_from_slice(&c3.to_le_bytes());
        id
    };
    let our_fingerprint = pico2hsm_firmware::storage::sdcard::compute_device_fingerprint(&device_id);
    defmt::trace!("HYBRID [2/12] fingerprint computed, chip ID = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        device_id[0], device_id[1], device_id[2], device_id[3],
        device_id[4], device_id[5], device_id[6], device_id[7]);

    // ── SMK derivation ────────────────────────────────────────────────────────
    defmt::trace!("HYBRID [3/12] derive SMK");
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);
    defmt::trace!("HYBRID [3/12] SMK ready");

    // ── Primary storage: QMI flash ────────────────────────────────────────────
    defmt::trace!("HYBRID [4/12] init QMI flash");
    let qmi_raw = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi_flash = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_raw);
    let mut qmi_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    let _ = qmi_fs.add_chip(qmi_flash);
    let qmi_sm = pico2hsm_firmware::storage::StorageManager::new(qmi_fs);
    let flash_ks = pico2hsm_firmware::storage::FlashKeyStore::new(qmi_sm, smk.clone());
    defmt::trace!("HYBRID [4/12] QMI flash store built");

    // ── SD card init + signature check ────────────────────────────────────────
    defmt::trace!("HYBRID [5/12] SdCard::new + num_bytes()");
    let sd_card = SdCard::new(spi_device, embassy_time::Delay);
    let sd_init_result = sd_card.num_bytes();
    defmt::trace!("HYBRID [5/12] num_bytes result: {}", sd_init_result.is_ok());

    let hybrid_degraded_at_init;
    let sd_ks = match sd_init_result {
        Ok(capacity) => {
            defmt::info!("HYBRID SD card capacity: {} B ({} MiB)", capacity, capacity / (1024 * 1024));
            defmt::trace!("HYBRID [6/12] check_sd_signature");
            let check_result = check_sd_signature(&sd_card, &our_fingerprint);
            match check_result {
                SdCardCheckResult::Matched => {
                    defmt::info!("HYBRID [6/12] signature matched — card recognized");
                    hybrid_degraded_at_init = false;
                    defmt::trace!("HYBRID [7/12] SdCardFlash::from_card");
                    let sd_flash = pico2hsm_firmware::storage::sdcard::SdCardFlash::from_card(sd_card, capacity);
                    let mut sd_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let _ = sd_fs.add_chip(sd_flash);
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    defmt::trace!("HYBRID [7/12] SD KeyFilesystem built");
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
                SdCardCheckResult::Blank | SdCardCheckResult::Corrupt => {
                    defmt::info!("HYBRID [6/12] SD blank/corrupt — auto-adopting");
                    defmt::trace!("HYBRID [6/12] write_sd_signature");
                    let sig_result = write_sd_signature(&sd_card, &our_fingerprint);
                    defmt::info!("HYBRID [6/12] write_sd_signature result: {}", sig_result.is_ok());
                    hybrid_degraded_at_init = false;
                    defmt::trace!("HYBRID [7/12] SdCardFlash::from_card");
                    let sd_flash = pico2hsm_firmware::storage::sdcard::SdCardFlash::from_card(sd_card, capacity);
                    let mut sd_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let _ = sd_fs.add_chip(sd_flash);
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    defmt::trace!("HYBRID [7/12] SD KeyFilesystem built");
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
                SdCardCheckResult::Foreign => {
                    defmt::warn!("HYBRID [6/12] SD card from different device — degraded");
                    hybrid_degraded_at_init = true;
                    let sd_fs: pico2hsm_firmware::storage::filesystem::KeyFilesystem<
                        pico2hsm_firmware::storage::board_chips::HybridSdChip,
                    > = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
            }
        }
        Err(_) => {
            defmt::warn!("HYBRID [5/12] SD card num_bytes() failed — degraded (check wiring/speed)");
            hybrid_degraded_at_init = true;
            let sd_fs: pico2hsm_firmware::storage::filesystem::KeyFilesystem<
                pico2hsm_firmware::storage::board_chips::HybridSdChip,
            > = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
            let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
            pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
        }
    };

    // ── Build HybridKeyStore ──────────────────────────────────────────────────
    defmt::trace!("HYBRID [8/12] HybridKeyStore::new");
    let mut ks = pico2hsm_firmware::storage::HybridKeyStore::new(flash_ks, sd_ks);

    defmt::trace!("HYBRID [9/12] primary (QMI flash) keystore init");
    match ks.primary_mut().init() {
        Ok(()) => defmt::info!("HYBRID [9/12] QMI flash keystore OK"),
        Err(_) => defmt::warn!("HYBRID [9/12] QMI flash keystore init FAILED"),
    }

    defmt::trace!("HYBRID [10/12] secondary (SD card) keystore init");
    match ks.secondary_mut().init() {
        Ok(()) => defmt::info!("HYBRID [10/12] SD card keystore OK"),
        Err(_) => defmt::warn!("HYBRID [10/12] SD card keystore init FAILED (non-fatal)"),
    }

    defmt::trace!("HYBRID [11/12] initial resync flash → SD");
    if !hybrid_degraded_at_init {
        match ks.resync() {
            Ok(()) => defmt::info!("HYBRID [11/12] resync OK"),
            Err(_) => defmt::warn!("HYBRID [11/12] resync FAILED"),
        }
    } else {
        defmt::warn!("HYBRID [11/12] skipping resync — degraded at init");
    }

    debug_dump_storage_hybrid(&ks);

    defmt::trace!("HYBRID [12/12] KEYSTORE_CELL.init");
    let store: &'static mut _ = KEYSTORE_CELL.init(ks);
    defmt::info!("HYBRID init complete — degraded_at_init={}", hybrid_degraded_at_init);

    // ── USB CCID + CDC-ACM serial transport ──────────────────────────────────
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

    let mut ccid = CcidTransport::new(&mut builder);

    let cdc_class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let (mut cdc_sender, _) = cdc_class.split();

    let mut usb = builder.build();

    defmt::info!("pico2hsm (Pico 2 hybrid): USB CCID+CDC ready, entering main loop");
    led.set_status(LedStatus::Ready);

    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
    });

    let usb_fut = usb.run();
    let ccid_fut = async {
        loop {
            ccid.wait_connected().await;
            defmt::info!("core0: USB connected");
            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        led.set_status(LedStatus::Busy);
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
                            Ok(()) => {
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
                            }
                            Err(CcidError::UsbDisconnected) => {
                                let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                                let _ = RESP_CHANNEL.receive().await;
                                break;
                            }
                            Err(_) => {}
                        }
                        led.set_status(LedStatus::Ready);
                    }
                    Err(CcidError::UsbDisconnected) => {
                        let _ = APDU_CHANNEL.send(heapless::Vec::new()).await;
                        let _ = RESP_CHANNEL.receive().await;
                        led.set_status(LedStatus::Ready);
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
    feature = "waveshare_rp2350_lcd_sdcard_dual",
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
    use pico2hsm_firmware::display::{DisplayState, ScreensaverState, SCREENSAVER_TIMEOUT_SECS, LAST_OP_DISPLAY_SECS};
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

    // waveshare_rp2350_lcd_16m / waveshare_rp2350_lcd_sdcard_dual: degraded QMI.
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    let store: &'static mut _ = {
        let fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
        let sm = pico2hsm_firmware::storage::StorageManager::new(fs);
        let mut ks = pico2hsm_firmware::storage::FlashKeyStore::new(sm, smk);
        match ks.init() {
            Ok(()) => defmt::info!("KeyStore: initialized (waveshare_rp2350_lcd — degraded, no chips)"),
            Err(_) => defmt::warn!("KeyStore: init failed — degraded mode"),
        }
        KEYSTORE_CELL.init(ks)
    };

    // Set provisioning status for display (non-hybrid boards don't track qmi_ok/sd_ok).
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

    // ── Spawn APDU dispatcher on core1 ───────────────────────────────────────
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
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
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        // Wait for response with time-extension support.
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
                            Ok(()) => {
                                display_state.status = LedStatus::Ready;
                                display_state.uptime_secs = embassy_time::Instant::now().as_secs() as u32;
                                display_state.key_count = KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time) >= LAST_OP_DISPLAY_SECS {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    let (disp, spi) = board.led_and_spi0_mut();
                                    update_status_display(disp, spi, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                                }
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
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

// ─── Waveshare RP2350-LCD-1.47-B hybrid RAID-1 main function ────────────────

#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
async fn run_waveshare_lcd_hybrid_board(p: embassy_rp::Peripherals) {
    use embassy_futures::join::join;
    use embassy_rp::gpio::{Level, Output};
    use embassy_rp::pio::Pio;
    use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
    use embassy_rp::spi::{Config as SpiConfig, Phase, Polarity, Spi};
    use embassy_rp::usb::Driver as UsbDriver;
    use embassy_usb::{Builder as UsbBuilder, Config as UsbConfig};

    use pico2hsm_firmware::board::waveshare_rp2350_lcd::{
        init_lcd, update_status_display, PioWs2812Writer,
    };
    use pico2hsm_firmware::board::LedStatus;
    use pico2hsm_firmware::display::{DisplayState, ScreensaverState, SCREENSAVER_TIMEOUT_SECS, LAST_OP_DISPLAY_SECS};
    use pico2hsm_firmware::transport::ccid::CcidError;
    use pico2hsm_firmware::transport::CcidTransport;

    defmt::info!("Board: Waveshare RP2350-LCD-1.47-B hybrid (QMI + SD) initialising");

    // ── SPI0: LCD bus (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO4) ─────────────────
    // Async/DMA mode — DMA_CH1=TX, DMA_CH2=RX (RX unused, LCD is write-only).
    let mut spi0_cfg = SpiConfig::default();
    spi0_cfg.frequency = pico2hsm_firmware::board::waveshare_rp2350_lcd::SPI_FREQ_HZ;
    spi0_cfg.phase = Phase::CaptureOnFirstTransition;
    spi0_cfg.polarity = Polarity::IdleLow;
    let mut spi0 = Spi::new(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_4, p.DMA_CH1, p.DMA_CH2, Irqs, spi0_cfg);

    // ── SPI1: SD card bus (SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12) ─────────────
    // SPI1 is consumed entirely by the SD card driver — NOT passed to the board struct.
    let mut spi1_cfg = SpiConfig::default();
    spi1_cfg.frequency = 400_000; // 400 kHz — SD spec requires ≤400 kHz for card identification
    spi1_cfg.phase = Phase::CaptureOnFirstTransition;
    spi1_cfg.polarity = Polarity::IdleLow;
    let spi1 = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi1_cfg);

    // Wrap SPI1 in a shared-bus Mutex for the SpiDevice wrapper.
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::blocking_mutex::Mutex;
    static SPI1_BUS: StaticCell<Mutex<CriticalSectionRawMutex, core::cell::RefCell<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
    >>> = StaticCell::new();
    let spi1_bus: &'static Mutex<CriticalSectionRawMutex, core::cell::RefCell<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
    >> = SPI1_BUS.init(Mutex::new(core::cell::RefCell::new(spi1)));

    let sd_cs = Output::new(p.PIN_15, Level::High);
    let spi_device = embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice::new(
        spi1_bus, sd_cs,
    );

    // ── LCD control GPIO pins ─────────────────────────────────────────────────
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

    use pico2hsm_firmware::board::waveshare_rp2350_lcd::St7789V3StatusDisplay;
    let mut display = St7789V3StatusDisplay::new();

    // ── LCD hardware init ───────────────────────────────────────────────────
    let mut display_state = DisplayState::new();
    display_state.status = LedStatus::Busy;
    init_lcd(&mut spi0, &mut dc, &mut cs, &mut rst, &mut bl).await;
    update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;

    // ── Get RP2350 device ID for fingerprint (OTP CHIPID0-3, 64-bit public ID) ──
    let device_id: [u8; 8] = {
        let otp = unsafe { embassy_rp::pac::OTP_DATA_RAW };
        let mut id = [0u8; 8];
        let c0 = otp.chipid0().read() as u16;
        let c1 = otp.chipid1().read() as u16;
        let c2 = otp.chipid2().read() as u16;
        let c3 = otp.chipid3().read() as u16;
        id[0..2].copy_from_slice(&c0.to_le_bytes());
        id[2..4].copy_from_slice(&c1.to_le_bytes());
        id[4..6].copy_from_slice(&c2.to_le_bytes());
        id[6..8].copy_from_slice(&c3.to_le_bytes());
        id
    };
    let our_fingerprint = pico2hsm_firmware::storage::sdcard::compute_device_fingerprint(&device_id);

    // ── Primary storage: QMI flash ──────────────────────────────────────────
    let smk_bytes = pico2hsm_firmware::security::otp::derive_smk()
        .unwrap_or([0u8; 32]);
    let smk = zeroize::Zeroizing::new(smk_bytes);

    let qmi_raw = embassy_rp::flash::Flash::<
        _,
        embassy_rp::flash::Blocking,
        { pico2hsm_firmware::storage::flash_chip::QMI_FLASH_SIZE },
    >::new_blocking(p.FLASH);
    let qmi_flash = pico2hsm_firmware::storage::flash_chip::QmiFlash::new(qmi_raw);
    let mut qmi_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
    let _ = qmi_fs.add_chip(qmi_flash);
    let qmi_sm = pico2hsm_firmware::storage::StorageManager::new(qmi_fs);
    let flash_ks = pico2hsm_firmware::storage::FlashKeyStore::new(qmi_sm, smk.clone());

    // ── Secondary storage: SD card on SPI1 (with signature check) ───────────
    use embedded_sdmmc::SdCard;
    use pico2hsm_firmware::storage::sdcard::{check_sd_signature, write_sd_signature, SdCardCheckResult};

    let sd_card = SdCard::new(spi_device, embassy_time::Delay);
    let sd_init_result = sd_card.num_bytes();

    let hybrid_degraded_at_init;
    let sd_ks = match sd_init_result {
        Ok(capacity) => {
            let check_result = check_sd_signature(&sd_card, &our_fingerprint);
            match check_result {
                SdCardCheckResult::Matched => {
                    defmt::info!("Hybrid: SD card signature matched — recognized");
                    hybrid_degraded_at_init = false;
                    let sd_flash = pico2hsm_firmware::storage::sdcard::SdCardFlash::from_card(sd_card, capacity);
                    let mut sd_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let _ = sd_fs.add_chip(sd_flash);
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
                SdCardCheckResult::Blank | SdCardCheckResult::Corrupt => {
                    defmt::info!("Hybrid: SD card is blank/corrupt — auto-adopting");
                    let _ = write_sd_signature(&sd_card, &our_fingerprint);
                    hybrid_degraded_at_init = false;
                    let sd_flash = pico2hsm_firmware::storage::sdcard::SdCardFlash::from_card(sd_card, capacity);
                    let mut sd_fs = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let _ = sd_fs.add_chip(sd_flash);
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
                SdCardCheckResult::Foreign => {
                    defmt::warn!("Hybrid: SD card from different device — booting degraded");
                    hybrid_degraded_at_init = true;
                    display_state.sd_ok = Some(false);
                    // Create an empty FlashKeyStore with no chips — it will fail all ops.
                    let sd_fs: pico2hsm_firmware::storage::filesystem::KeyFilesystem<
                        pico2hsm_firmware::storage::board_chips::HybridSdChip,
                    > = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
                    let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
                    pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
                }
            }
        }
        Err(_) => {
            defmt::warn!("Hybrid: SD card init failed — starting in degraded mode");
            hybrid_degraded_at_init = true;
            // Create an empty FlashKeyStore with no chips — it will fail all ops.
            let sd_fs: pico2hsm_firmware::storage::filesystem::KeyFilesystem<
                pico2hsm_firmware::storage::board_chips::HybridSdChip,
            > = pico2hsm_firmware::storage::filesystem::KeyFilesystem::new();
            let sd_sm = pico2hsm_firmware::storage::StorageManager::new(sd_fs);
            pico2hsm_firmware::storage::FlashKeyStore::new(sd_sm, smk.clone())
        }
    };

    // ── Build HybridKeyStore ────────────────────────────────────────────────
    let mut ks = pico2hsm_firmware::storage::HybridKeyStore::new(flash_ks, sd_ks);

    // Init primary (QMI flash).
    match ks.primary_mut().init() {
        Ok(()) => defmt::info!("Hybrid: QMI flash keystore initialised"),
        Err(_) => defmt::warn!("Hybrid: QMI flash keystore init failed"),
    }

    // Init secondary (SD card) — non-fatal.
    match ks.secondary_mut().init() {
        Ok(()) => defmt::info!("Hybrid: SD card keystore initialised"),
        Err(_) => defmt::warn!("Hybrid: SD card keystore init failed — degraded"),
    }

    // Initial resync from flash → SD (non-fatal).
    if !hybrid_degraded_at_init {
        let _ = ks.resync();
    }

    // Populate display health fields.
    display_state.qmi_ok = Some(true);
    display_state.sd_ok = Some(!hybrid_degraded_at_init);
    display_state.provisioned = pico2hsm_firmware::security::otp::Otp::new().is_provisioned();

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

    let mut config_descriptor_buf = [0u8; 512];
    let mut bos_descriptor_buf    = [0u8; 256];
    let mut msos_descriptor_buf   = [0u8; 256];
    let mut control_buf           = [0u8; 64];

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
    let (mut cdc_sender, mut _cdc_receiver) = cdc_class.split();

    let mut usb = builder.build();

    defmt::info!("pico2hsm (RP2350-LCD-1.47-B hybrid): USB CCID+CDC ready, entering main loop");
    display_state.status = LedStatus::Ready;
    update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;

    // ── Spawn APDU dispatcher on core1 ───────────────────────────────────────
    spawn_core1(p.CORE1, unsafe { &mut *addr_of_mut!(CORE1_STACK) }, move || {
        let executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());
        executor.run(|spawner| spawner.spawn(dispatcher_task(store).expect("dispatcher task")));
    });

    // ── Concurrent USB + CCID command loop (core0) ───────────────────────────
    let usb_fut = usb.run();

    // Screensaver state — activated on each APDU response check.
    // The timer-based tick that cancelled recv_apdu() every second caused the
    // Embassy USB bulk-OUT endpoint to get stuck in NAK state after the first
    // cancel/re-arm cycle, preventing pcscd from initialising the CCID reader.
    // Using direct recv_apdu().await (like pico2) avoids all endpoint re-arming.
    let mut last_activity = embassy_time::Instant::now();
    let mut screensaver = ScreensaverState::Active;

    let ccid_fut = async {
        loop {
            ccid.wait_connected().await;
            defmt::info!("RP2350-LCD-1.47-B hybrid: USB connected");
            display_state.status = LedStatus::Ready;
            update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
            last_activity = embassy_time::Instant::now();
            screensaver = ScreensaverState::Active;

            loop {
                match ccid.recv_apdu().await {
                    Ok(apdu_bytes) => {
                        let now = embassy_time::Instant::now();
                        // Wake screensaver on any APDU.
                        if screensaver == ScreensaverState::Sleeping {
                            screensaver = ScreensaverState::Active;
                            display_state.status = LedStatus::Ready;
                            update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                        }
                        // Check idle timeout (screensaver activates on next check if exceeded).
                        if now.duration_since(last_activity).as_secs() >= SCREENSAVER_TIMEOUT_SECS as u64
                            && screensaver == ScreensaverState::Active
                        {
                            screensaver = ScreensaverState::Sleeping;
                            use pico2hsm_firmware::board::waveshare_rp2350_lcd::{Grb, Ws2812Writer};
                            pico2hsm_firmware::board::waveshare_rp2350_lcd::fill_screen(
                                &mut spi0, &mut dc, &mut cs, 0x0000,
                            ).await;
                            ws2812_writer.write_pixel(Grb::OFF).await;
                        }
                        last_activity = now;
                        display_state.status = LedStatus::Busy;
                        update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                        let _ = APDU_CHANNEL.send(apdu_bytes).await;
                        // Wait for response with time-extension support.
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
                            Ok(()) => {
                                // Check hybrid health via cross-core atomics.
                                let flash_err = HYBRID_FLASH_ERROR.load(core::sync::atomic::Ordering::Relaxed);
                                let degraded = HYBRID_DEGRADED.load(core::sync::atomic::Ordering::Relaxed);
                                if flash_err {
                                    display_state.status = LedStatus::Error;
                                } else if degraded {
                                    display_state.status = LedStatus::Degraded;
                                } else {
                                    display_state.status = LedStatus::Ready;
                                }
                                display_state.qmi_ok = Some(!flash_err);
                                display_state.sd_ok = Some(!degraded);
                                display_state.uptime_secs = embassy_time::Instant::now().as_secs() as u32;
                                display_state.key_count = KEY_COUNT.load(core::sync::atomic::Ordering::Relaxed);
                                if let Some((_, op_time)) = display_state.last_op {
                                    if display_state.uptime_secs.saturating_sub(op_time) >= LAST_OP_DISPLAY_SECS {
                                        display_state.last_op = None;
                                    }
                                }
                                if screensaver == ScreensaverState::Active {
                                    update_status_display(&mut display, &mut spi0, &mut dc, &mut cs, &mut ws2812_writer, &display_state).await;
                                }
                                pico2hsm_firmware::transport::cdc_serial::drain_one(&mut cdc_sender).await;
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

/// Debug dump for hybrid keystores — shows primary and secondary key counts.
#[cfg(all(target_arch = "arm", feature = "pico2_4m_sdcard_hybrid"))]
fn debug_dump_storage_hybrid(ks: &pico2hsm_firmware::storage::board_chips::BoardKeyStore) {
    use pico2hsm_firmware::storage::KeyStore;
    let pkeys = ks.enumerate_keys();
    defmt::info!(
        "=== hybrid storage dump: {} key(s) in primary (authoritative) ===",
        pkeys.len()
    );
    defmt::info!("=== end hybrid storage dump ===");
}

// ─── Host stub ────────────────────────────────────────────────────────────────

/// No-op entry point for non-ARM builds (e.g., `cargo test --target x86_64`).
/// The firmware is only meaningful on ARM; this stub allows the binary target
/// to compile without errors during host-side testing.
#[cfg(not(target_arch = "arm"))]
fn main() {}
