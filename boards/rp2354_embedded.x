/* memory.x for RP2354 with embedded flash
 *
 *   BOOT2  0x10000000 + 0x100  IMAGE_DEF (.start_block)
 *   FLASH  0x10000100 + 0x1FFF00  vector table + code
 *   RAM    0x20000000 + 0x82000 (520KB)
 * Keystore on external SPI chips only (no internal KEYSTORE region).
 */

MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH : ORIGIN = 0x10000100, LENGTH = 0x1FFF00
    RAM   : ORIGIN = 0x20000000, LENGTH = 0x82000
}

SECTIONS {
    .boot2 : {
        KEEP(*(.start_block .start_block.*))
    } > BOOT2
}
