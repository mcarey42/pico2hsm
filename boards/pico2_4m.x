/* memory.x for Raspberry Pi Pico 2 (stock, RP2350A, 4MB flash)
 *
 * Flash layout:
 *   BOOT2    0x10000000 + 0x100 (256 bytes)
 *            RP2350 IMAGE_DEF (.start_block) goes here.
 *   FLASH    0x10000100 + 0x1FFF00 (2MB - 256 bytes)
 *            ARM vector table + firmware code.
 *   KEYSTORE 0x10200000 + 0x200000 (2MB — no external flash on stock Pico 2)
 *   RAM      0x20000000 + 0x82000 (520KB)
 */

MEMORY {
    BOOT2    : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH    : ORIGIN = 0x10000100, LENGTH = 0x1FFF00
    KEYSTORE : ORIGIN = 0x10200000, LENGTH = 0x200000
    RAM      : ORIGIN = 0x20000000, LENGTH = 0x82000
}

SECTIONS {
    .boot2 : {
        KEEP(*(.start_block .start_block.*))
    } > BOOT2
}
