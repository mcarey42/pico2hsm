/* memory.x for Waveshare RP2350-Geek 16MB (no SDCard)
 *
 * Flash layout:
 *   BOOT2    0x10000000 + 0x100 (0x100 = 256 bytes)
 *            RP2350 IMAGE_DEF (.start_block) goes here.
 *            No second-stage bootloader is needed for RP2350 —
 *            the bootrom handles XIP directly.
 *   FLASH    0x10000100 + 0x3FDF00 (4 MB - 8 KB - 256 bytes: one firmware slot)
 *            ARM vector table + firmware code.  The image runs from slot A
 *            (physical 0x002000) or slot B (0x400000) through the bootrom's
 *            address translation, or flat from 0 (no partition table); see
 *            docs/FLASH_LAYOUT_2_0.md and firmware/src/storage/flash_layout.rs.
 *   Store regions (physical, from 8 MB + 4 KB; closed partitions; nothing
 *   closed may start at 8 MB: see flash_layout.rs MAP_16M):
 *   BINDING  0x10801000 + 0x8000 (32KB, 8 sectors)  binding block ring
 *   RETRY_COUNTERS 0x10809000 + 0x10000 (64KB)      counter log v2
 *   RSA_POOL 0x10819000 + 0xC000 (48KB)             RSA key pool
 *   LEGACY_COUNTERS 0x10825000 + 0x4000 (16KB)      blank placeholder
 *   KEYSTORE 0x10829000 + 0x7D6000 (~7.8 MB; QMI boards; the last sector
 *            stays outside every partition: erratum RP2350-E10)
 *   RAM      0x20000000 + 0x82000 (520KB)
 *
 * SECTIONS note: the .boot2 output section below must appear BEFORE
 * cortex-m-rt link.x places .vector_table, so it is declared here
 * inside memory.x which link.x INCLUDEs before its own SECTIONS.
 */

MEMORY {
    BOOT2    : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH    : ORIGIN = 0x10000100, LENGTH = 0x3FDF00
    /* Storage V2 binding block ring; see firmware/src/storage/flash_layout.rs */
    BINDING  : ORIGIN = 0x10801000, LENGTH = 0x8000
    /* Counter log v2; see firmware/src/storage/flash_layout.rs */
    RETRY_COUNTERS : ORIGIN = 0x10809000, LENGTH = 0x10000
    /* RSA key pool; see firmware/src/storage/flash_layout.rs */
    RSA_POOL : ORIGIN = 0x10819000, LENGTH = 0xC000
    /* Version-1 counter log (migrated once); see flash_layout.rs */
    LEGACY_COUNTERS : ORIGIN = 0x10825000, LENGTH = 0x4000
    KEYSTORE : ORIGIN = 0x10829000, LENGTH = 0x7D6000
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
