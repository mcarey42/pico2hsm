//! RP2350 IMAGE_DEF block placed in the `.start_block` linker section.
//!
//! We define a custom Block<3> that includes:
//!   - ITEM_1BS_IMAGE_TYPE : Secure ARM RP2350 executable
//!   - ITEM_1BS_VECTOR_TABLE : explicit vector table address (0x10000100)
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
    item_image_type_exe, item_vector_table, Architecture, Block, Security,
    ITEM_1BS_VECTOR_TABLE,
};

/// The vector table address as set by every board linker script.
const VECTOR_TABLE_ADDR: u32 = 0x10000100;

/// VECTOR_TABLE item header and pointer.
const VT: [u32; 2] = item_vector_table(VECTOR_TABLE_ADDR);

/// IMAGE_DEF block: IMAGE_TYPE + VECTOR_TABLE = 3 item words (Block<3>).
///
/// Block layout (7 words total):
///   [0] BLOCK_MARKER_START
///   [1] IMAGE_TYPE item  (Secure ARM RP2350 EXE)
///   [2] VECTOR_TABLE item header
///   [3] VECTOR_TABLE address = 0x10000100
///   [4] LAST item (encodes N=3 item words)
///   [5] next-block offset (0 = self-loop)
///   [6] BLOCK_MARKER_END
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: Block<3> = Block::new([
    item_image_type_exe(Security::Secure, Architecture::Arm),
    VT[0],
    VT[1],
]);
