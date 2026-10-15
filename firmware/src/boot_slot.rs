//! Which firmware slot booted, and try-before-you-buy (FLASH_LAYOUT_2_0.md
//! §4.5).
//!
//! On the 16 MB boards the bootrom boots the higher-versioned of the A/B
//! images.  A new image flagged TBYB runs on trial: unless it is bought,
//! the next boot goes back to the other slot.  This firmware buys once it
//! has proven itself end to end — the first APDU answered by core1 and
//! handed back to core0 (USB, CCID, the dispatcher and the store all
//! worked) — see [`buy_if_pending`].

use core::sync::atomic::{AtomicBool, Ordering};

/// `SYS_INFO_BOOT_INFO` (RP2350 datasheet §5.5.11.1).
const SYS_INFO_BOOT_INFO: u32 = 0x0040;
/// `BOOT_TBYB_AND_UPDATE_FLAG_BUY_PENDING`.
const FLAG_BUY_PENDING: u8 = 0x01;

/// This boot runs a TBYB image that has not been bought yet.
static BUY_PENDING: AtomicBool = AtomicBool::new(false);

/// The bootrom's account of this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfo {
    /// The partition booted (`None`: no partition table, a flat image).
    pub partition: Option<u8>,
    /// `boot_type` (0 normal, 2 BOOTSEL, …).
    pub boot_type: u8,
    /// `tbyb_and_update_info` flags.
    pub tbyb: u8,
}

impl BootInfo {
    /// Decode the words after the flags word of `get_sys_info(BOOT_INFO)`
    /// (`diagnostic_partition_index i8 | boot_type u8 | partition i8 |
    /// tbyb_and_update_info u8`, little-endian).
    pub fn decode(word: u32) -> Self {
        let b = word.to_le_bytes();
        BootInfo {
            partition: (b[2] as i8 >= 0).then_some(b[2]),
            boot_type: b[1],
            tbyb: b[3],
        }
    }
}

/// Ask the bootrom about this boot.
#[cfg(target_arch = "arm")]
pub fn boot_info() -> Option<BootInfo> {
    let mut words = [0u32; 5];
    // SAFETY: the buffer is `words.len()` words long.
    let n = unsafe {
        embassy_rp::rom_data::get_sys_info(words.as_mut_ptr(), words.len(), SYS_INFO_BOOT_INFO)
    };
    (n >= 2 && words[0] & SYS_INFO_BOOT_INFO != 0).then(|| BootInfo::decode(words[1]))
}

/// Boot (core0): note whether this image still has to be bought.
#[cfg(target_arch = "arm")]
pub fn init() -> Option<BootInfo> {
    let info = boot_info();
    let pending = info.is_some_and(|i| i.tbyb & FLAG_BUY_PENDING != 0);
    BUY_PENDING.store(pending, Ordering::SeqCst);
    info
}

/// This image runs on trial (not bought yet).
pub fn buy_pending() -> bool {
    BUY_PENDING.load(Ordering::SeqCst)
}

/// Core0, after core1's first response: buy this image if it is on trial.
/// The ROM rewrites the image's first sector, so this runs like any flash
/// write: core1 paused, interrupts off, no flash DMA or XIP stream active.
/// Returns `false` only if a buy was attempted and the ROM refused it (the
/// trial then stands, and the next boot goes back to the other slot).
#[cfg(target_arch = "arm")]
pub fn buy_if_pending() -> bool {
    if !BUY_PENDING.swap(false, Ordering::SeqCst) {
        return true;
    }
    // Debug builds made with PICO2HSM_TEST_NO_BUY never buy: the A/B
    // revert test needs an image that stays on trial.
    if cfg!(feature = "debug") && option_env!("PICO2HSM_TEST_NO_BUY").is_some() {
        return false;
    }
    if embassy_rp::pac::SIO.cpuid().read() != 0 {
        BUY_PENDING.store(true, Ordering::SeqCst);
        return false;
    }
    // The ROM's work buffer: the image's first sector, read and rewritten.
    let mut buf = [0u8; 4096];
    crate::watchdog::progress();
    embassy_rp::multicore::pause_core1();
    let r = cortex_m::interrupt::free(|_| {
        // As embassy-rp's flash `in_ram`: no DMA reading flash, no
        // background XIP stream, while the flash leaves XIP mode.
        for n in 0..16 {
            let ch = embassy_rp::pac::DMA.ch(n);
            while ch.read_addr().read() < 0x2000_0000 && ch.ctrl_trig().read().busy() {}
        }
        while embassy_rp::pac::XIP_CTRL.stream_ctr().read().0 > 0 {}
        // SAFETY: core1 is paused and interrupts are off; the buffer is
        // 4096 bytes, which the ROM requires.
        unsafe { embassy_rp::rom_data::explicit_buy(buf.as_mut_ptr(), buf.len() as u32) }
    });
    embassy_rp::multicore::resume_core1();
    crate::watchdog::progress();
    r == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_boot_info_word() {
        // Seen on the Waveshare LCD board booted from slot B.
        let b = BootInfo::decode(0x0001_00FF);
        assert_eq!(b.partition, Some(1));
        assert_eq!(b.boot_type, 0);
        assert_eq!(b.tbyb, 0);
        // A flat image (no partition table), on trial.
        let b = BootInfo::decode(0x01FF_00FF);
        assert_eq!(b.partition, None);
        assert_eq!(b.tbyb & FLAG_BUY_PENDING, 1);
    }
}
