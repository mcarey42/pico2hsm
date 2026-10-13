/* memory.x for Waveshare RP2350-Geek 16MB (no SDCard)
 *
 * Flash layout:
 *   BOOT2    0x10000000 + 0x100 (0x100 = 256 bytes)
 *            RP2350 IMAGE_DEF (.start_block) goes here.
 *            No second-stage bootloader is needed for RP2350 —
 *            the bootrom handles XIP directly.
 *   FLASH    0x10000100 + 0x1D7F00 (2MB - 160KB - 256 bytes)
 *            ARM vector table + firmware code.  cortex-m-rt places
 *            .vector_table at ORIGIN(FLASH) = 0x10000100.
 *   BINDING  0x101D8000 + 0x8000 (32KB, 8 sectors)
 *            Storage V2 binding block ring (STORAGE_V2 §8.1).
 *   RETRY_COUNTERS 0x101E0000 + 0x10000 (64KB, 16 sectors)
 *            Counter log v2: PIN/PUK retry counters, device values, the
 *            keystore anchor.  On internal flash on every board.
 *   RSA_POOL 0x101F0000 + 0xC000 (48KB, 12 sectors)
 *            Pre-generated RSA keys (encrypted), one per sector.
 *            Never part of the firmware image.
 *   LEGACY_COUNTERS 0x101FC000 + 0x4000 (16KB, 4 sectors)
 *            The version-1 counter log: migrated into RETRY_COUNTERS once,
 *            then erased; reserved until the 2.0 layout (phase 6).
 *   KEYSTORE 0x10200000 + 0xE00000
 *   RAM      0x20000000 + 0x82000 (520KB)
 *
 * SECTIONS note: the .boot2 output section below must appear BEFORE
 * cortex-m-rt link.x places .vector_table, so it is declared here
 * inside memory.x which link.x INCLUDEs before its own SECTIONS.
 */

MEMORY {
    BOOT2    : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH    : ORIGIN = 0x10000100, LENGTH = 0x1D7F00
    /* Storage V2 binding block ring; see firmware/src/storage/flash_layout.rs */
    BINDING  : ORIGIN = 0x101D8000, LENGTH = 0x8000
    /* Counter log v2; see firmware/src/storage/flash_layout.rs */
    RETRY_COUNTERS : ORIGIN = 0x101E0000, LENGTH = 0x10000
    /* RSA key pool; see firmware/src/storage/flash_layout.rs */
    RSA_POOL : ORIGIN = 0x101F0000, LENGTH = 0xC000
    /* Version-1 counter log (migrated once); see flash_layout.rs */
    LEGACY_COUNTERS : ORIGIN = 0x101FC000, LENGTH = 0x4000
    KEYSTORE : ORIGIN = 0x10200000, LENGTH = 0xE00000
    RAM      : ORIGIN = 0x20000000, LENGTH = 0x82000
}

/* Place the RP2350 IMAGE_DEF block (embassy-rp .start_block section)
 * at the very beginning of flash, before the ARM vector table.
 * The RP2350 bootrom scans for this block to learn the image type. */
SECTIONS {
    .boot2 : {
        KEEP(*(.start_block .start_block.*))
    } > BOOT2
}
