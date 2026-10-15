//! RP2350 IMAGE_DEF block placed in the `.start_block` linker section.
//!
//! We define a custom Block<5> that includes:
//!   - ITEM_1BS_IMAGE_TYPE : Secure ARM RP2350 executable
//!   - ITEM_1BS_VECTOR_TABLE : explicit vector table address (0x10000100)
//!   - ITEM_1BS_VERSION : image version, which picks between A/B slots
//!
//! The VECTOR_TABLE item is critical: without it, the RP2350 bootrom defaults
//! VTOR to the start of the flash (0x10000000) rather than 0x10000100 where
//! the cortex-m-rt vector table lives.  This causes the CPU to read garbage
//! as the initial MSP/PC and immediately double-faults on the first attempt
//! to service any exception.
//!
//! We disable embassy-rp's auto IMAGE_DEF via the `imagedef-none` feature and
//! replace it here.  All board linker scripts place the vector table at
//! FLASH ORIGIN = 0x10000100, so the address is the same for every target.

use embassy_rp::block::{
    item_generic_1bs, item_image_type_exe, item_vector_table, Architecture, Block, Security,
    IMAGE_TYPE_TBYB, ITEM_1BS_VECTOR_TABLE, ITEM_1BS_VERSION,
};

/// The vector table address as set by every board linker script.
const VECTOR_TABLE_ADDR: u32 = 0x10000100;

/// VECTOR_TABLE item header and pointer.
const VT: [u32; 2] = item_vector_table(VECTOR_TABLE_ADDR);

/// Parse a decimal `u16` at compile time (the build script's version).
const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v: u32 = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "image version digit");
        v = v * 10 + (b[i] - b'0') as u32;
        assert!(v <= 0xFFFF, "image version too large");
        i += 1;
    }
    v as u16
}

/// Image version (build.rs: crate version, or `PICO2HSM_IMAGE_VERSION`):
/// with a partition table, the bootrom boots the higher of the A/B images.
pub const IMAGE_MAJOR: u16 = parse_u16(env!("PICO2HSM_IMAGE_MAJOR"));
/// Minor version: `minor * 256 + patch`.
pub const IMAGE_MINOR: u16 = parse_u16(env!("PICO2HSM_IMAGE_MINOR"));

/// Whether this image is try-before-you-buy: release builds for the A/B
/// (16 MB) boards, so a new image keeps its slot only once it has worked
/// (`boot_slot::buy_if_pending`).  Debug builds only with PICO2HSM_TBYB:
/// the bootrom tries a trial image only on an update boot (a UF2 drop,
/// `picotool load -x`), never after a probe flash and reset.
const TBYB: bool = crate::storage::flash_layout::FLASH_16M
    && (!cfg!(debug_assertions) || option_env!("PICO2HSM_TBYB").is_some());

/// IMAGE_TYPE item: Secure ARM RP2350 EXE, try-before-you-buy if [`TBYB`].
const IMAGE_TYPE: u32 = if TBYB {
    item_image_type_exe(Security::Secure, Architecture::Arm) | ((IMAGE_TYPE_TBYB as u32) << 16)
} else {
    item_image_type_exe(Security::Secure, Architecture::Arm)
};

/// VERSION item: header (no OTP rollback rows), then `major << 16 | minor`.
const VERSION: [u32; 2] = [
    item_generic_1bs(0, 2, ITEM_1BS_VERSION),
    ((IMAGE_MAJOR as u32) << 16) | IMAGE_MINOR as u32,
];

/// IMAGE_DEF block: IMAGE_TYPE + VECTOR_TABLE + VERSION = 5 item words.
///
/// Block layout (9 words total):
///   [0] BLOCK_MARKER_START
///   [1] IMAGE_TYPE item  (Secure ARM RP2350 EXE; TBYB on 16 MB boards)
///   [2] VECTOR_TABLE item header
///   [3] VECTOR_TABLE address = 0x10000100
///   [4] VERSION item header
///   [5] VERSION major << 16 | minor
///   [6] LAST item (encodes N=5 item words)
///   [7] next-block offset (0 = self-loop)
///   [8] BLOCK_MARKER_END
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: Block<5> = Block::new([IMAGE_TYPE, VT[0], VT[1], VERSION[0], VERSION[1]]);
