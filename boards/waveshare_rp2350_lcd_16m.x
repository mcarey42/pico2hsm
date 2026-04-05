/* memory.x for Waveshare RP2350-LCD-1.47-B (16MB external flash)
 *
 * Flash layout:
 *   BOOT2    0x10000000 + 0x100 (0x100 = 256 bytes)
 *            RP2350 IMAGE_DEF (.start_block) goes here.
 *            No second-stage bootloader is needed for RP2350 —
 *            the bootrom handles XIP directly.
 *   FLASH    0x10000100 + 0x1FFF00 (2MB - 256 bytes)
 *            ARM vector table + firmware code.  cortex-m-rt places
 *            .vector_table at ORIGIN(FLASH) = 0x10000100.
 *   KEYSTORE 0x10200000 + 0xE00000
 *   RAM      0x20000000 + 0x82000 (520KB)
 *
 * External flash: Winbond W25Q128JVSIQ (16MB) on QSPI.
 *
 * SECTIONS note: the .boot2 output section below must appear BEFORE
 * cortex-m-rt link.x places .vector_table, so it is declared here
 * inside memory.x which link.x INCLUDEs before its own SECTIONS.
 */

MEMORY {
    BOOT2    : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH    : ORIGIN = 0x10000100, LENGTH = 0x1FFF00
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
