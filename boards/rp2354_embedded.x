/* memory.x for RP2354 with 2 MB embedded flash
 *
 * Flash layout (2 MB total, split 1 MB / 1 MB):
 *   BOOT2    0x10000000 + 0x100    IMAGE_DEF (.start_block), 256 bytes
 *   FLASH    0x10000100 + 0x0FFF00 vector table + firmware code (~1 MB - 256 B)
 *   KEYSTORE 0x10100000 + 0x100000 keystore region, 1 MB
 *   RAM      0x20000000 + 0x82000  520 KB on-chip SRAM
 *
 * IMPORTANT: only release builds fit in FLASH (worst-case ~476 KB).
 * Debug builds are typically 2-3× larger and exceed 1 MB; use a 4 MB
 * external-flash board variant (e.g. rp2350_one_4m) for development.
 *
 * Keystore capacity at 1 MB:
 *   EC P-256/384 key (~200 B) → ~5,200 key slots
 *   RSA-2048      (~1.5 KB)   → ~680 key slots
 * The 254-key addressable limit per PKCS#11 session is the binding
 * constraint, not storage capacity.
 */

MEMORY {
    BOOT2    : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH    : ORIGIN = 0x10000100, LENGTH = 0x0FFF00
    KEYSTORE : ORIGIN = 0x10100000, LENGTH = 0x100000
    RAM      : ORIGIN = 0x20000000, LENGTH = 0x82000
}

SECTIONS {
    .boot2 : {
        KEEP(*(.start_block .start_block.*))
    } > BOOT2
}
