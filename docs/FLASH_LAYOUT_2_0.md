# 2.0 flash layout: partition tables, firmware slots, the closed store

Status: **implemented (Storage V2 phase 6), 2026-10-14; hardware-verified
on the Pico 2, RP2350-One and Waveshare LCD SD boards.**  This is the
"separate plan" [STORAGE_V2.md](STORAGE_V2.md) §3 and §14 call for, as
built.  The owner's decisions are in §8.

## 1. Summary

- **Every board boots through a bootrom partition table** (PT), 4 MB and
  16 MB alike, so provisioning is the same everywhere.
- **16 MB boards:** A/B firmware slots of 4 MB with try-before-you-buy
  (TBYB): an update keeps its slot only once it has worked; otherwise the
  board goes back to the previous image.
- **4 MB boards:** one slot of 1.83 MB, no A/B: the room goes to the
  firmware (post-quantum algorithms will need it).  128 SC-HSM keys.
- **The store regions are partitions of their own, closed to the
  bootloader** (BOOTSEL: picotool, UF2) and to Non-secure code.  From
  BOOTSEL nothing can read, write or erase them, not even a full-chip
  `picotool erase`.
- **The firmware checks the loaded table at boot**; a release build does
  not open its store against a table that differs from its compiled one.

## 2. Layouts

Offsets are physical (from the start of flash).  The source of truth is
`firmware/src/storage/flash_layout.rs`; `boards/pt_*.json` are the tables
(picotool format) and `boards/*.x` the linker scripts.  A host test ties
the three together.

### 2.1 4 MB boards (Pico 2, RP2350-One): `boards/pt_4m.json`

| Range | Size | Partition | Bootloader |
|---|---|---|---|
| `0x000000–0x002000` | 8 KB | the table (unpartitioned) | dev: rw; prod: r |
| `0x002000–0x1D8000` | 1,880 KB | `fw-a` | rw |
| `0x1D8000–0x1E0000` | 32 KB | `binding` | none |
| `0x1E0000–0x1F0000` | 64 KB | `counters` | none |
| `0x1F0000–0x1FC000` | 48 KB | `rsa-pool` | none |
| `0x1FC000–0x200000` | 16 KB | `spare` | none |
| `0x200000–0x201000` | 4 KB | unpartitioned (the midpoint, §5.2) | dev: rw; prod: r |
| `0x201000–0x400000` | 2,044 KB | `keystore` | none |

The store regions are where the flat interim layout had them, except the
keystore, which starts one sector later (§5.2).  Release images are
~650 KB, debug ~1.3 MB.

### 2.2 16 MB boards (Geek, Waveshare LCD, RP2350-One 16 MB): `boards/pt_16m.json`

| Range | Size | Partition | Bootloader |
|---|---|---|---|
| `0x000000–0x002000` | 8 KB | the table (unpartitioned) | dev: rw; prod: r |
| `0x002000–0x400000` | 4,088 KB | `fw-a` | rw |
| `0x400000–0x7FE000` | 4,088 KB | `fw-b` (A/B with `fw-a`) | rw |
| `0x7FE000–0x801000` | 12 KB | unpartitioned (gap, midpoint §5.2) | dev: rw; prod: r |
| `0x801000–0x809000` | 32 KB | `binding` | none |
| `0x809000–0x819000` | 64 KB | `counters` | none |
| `0x819000–0x825000` | 48 KB | `rsa-pool` | none |
| `0x825000–0x829000` | 16 KB | `spare` | none |
| `0x829000–0xFFF000` | ~7.8 MB | `keystore` (QMI boards; reserved on SD boards) | none |
| `0xFFF000–0x1000000` | 4 KB | unpartitioned (RP2350-E10, §5.3) | dev: rw; prod: r |

`rp2350_one_16m` is the RP2350-One with a 16 MB chip fitted: the One board
code with this map.

## 3. Firmware

- **Address translation.** The bootrom maps the booted slot to
  `0x1000_0000`, so one ELF, linked against a slot's size, runs from either
  slot.  Store reads therefore use the untranslated uncached alias
  `0x1C00_0000` (`flash_chip::xip_read`); through `0x1000_0000` they would
  read the firmware slot.  Programs and erases use physical offsets.
- **Boot check** (`boot_slot::read_layout`, called from
  `otp::boot_storage_master_key`): every store region must be a partition
  of its own at the compiled offsets, Secure read/write only, and no other
  partition may overlap it.  Release builds that find no table, or a
  different one, drop the storage key (after the OTP key page is locked):
  the store reports down.  Debug builds warn.
- **Image version** (IMAGE_DEF `VERSION`): major from the crate version,
  minor = minor * 256 + patch (`PICO2HSM_IMAGE_VERSION` overrides it).
  The bootrom boots the higher-versioned valid image.
- **Try-before-you-buy** (16 MB, release builds; debug only with
  `PICO2HSM_TBYB=1`): the image is flagged TBYB and buys itself on core0
  once core1 has answered its first APDU (USB, CCID, the dispatcher and the
  store worked end to end), with core1 paused and interrupts off, as for
  any flash write (`boot_slot::buy_if_pending`).  An image that never buys
  is dropped at the next reboot.
- **Key cap** (`MAX_SC_HSM_KEYS`): 128 SC-HSM user keys on 4 MB boards,
  251 (every user key ref) on 16 MB boards; the key index holds 400 / 768
  entries.  A new key past the cap fails with 6A84.
- **Debug commands** (`debug` builds): `80 FE 14` reboots into BOOTSEL,
  `80 FE 15` returns the image version and the bootrom's boot info (slot,
  trial state), `80 FE 16` the loaded table.

## 4. Flashing and updates

- **Development, probe:** `build-all-debug.sh` writes the table at `0x0`
  and the image into slot A with probe-rs, resets, and attaches for RTT.
- **Development, no probe:** `80 FE 14` (or the BOOT button), then
  `picotool load <table>.uf2`, `picotool reboot -u`, and
  `picotool load -p 0 -x <image>.uf2`.
- **Releases:** CI ships `pico2hsm-<board>-unsigned.uf2` and the board's
  tables `-pt-dev.uf2` / `-pt-prod.uf2`.  Install the table once, then the
  firmware; later updates are the firmware alone.
- **A trial image boots only on an update boot:** a UF2 copied to the
  BOOTSEL drive, or `picotool load -p N -x`.  A plain reboot ignores an
  unbought trial image (and with only trial images, the board stays in
  BOOTSEL).
- **Buying keeps the other slot's image**: the previous firmware stays as
  a fallback.  The bootrom only clears an abandoned (never-bought) trial.

## 5. Hardware findings

### 5.1 What BOOTSEL can and cannot do (verified)

With the table installed: reading the binding or keystore, erasing the
counter log, and a full-chip `picotool erase` are all refused ("permission
failure"; nothing is erased).  The firmware slots stay readable and
writable.  The firmware's own access is unaffected (unchecked ROM flash
calls and the raw XIP alias).

### 5.2 The midpoint rule

If a partition closed to the bootloader **contains the flash's midpoint**
(8 MB on 16 MB chips, 2 MB on 4 MB chips), the bootrom refuses **every**
BOOTSEL write, anywhere in flash, whether that partition starts at the
midpoint or straddles it; one starting a sector past it is fine (bisected
on the LCD board and the RP2350-One, 2026-10-14).  Erases still work.  So
the midpoint sector stays outside every closed partition; compile-time
checks and the table host test enforce it.

### 5.3 RP2350-E10

picotool keeps the last 256 bytes of a 16 MB address space
(`0x10ffff00`) out of every partition, for the erratum's absolute block;
the 16 MB keystore stops one sector short.  On 4 MB chips that address is
outside the chip and the table UF2 writes nothing there.

### 5.4 Removing the table

The table's own sector is unpartitioned space.  On **development** tables
it stays open, so erasing it from BOOTSEL (`picotool erase -r 0x10000000
0x10001000`) reopens every region: the way back for a dev board.  The
**production** tables (`pt_*_prod.json`) make the unpartitioned space
read-only to the bootloader, so from BOOTSEL the table can be neither erased
nor replaced (verified on the Pico 2 and the RP2350-One).

### 5.5 A2 silicon: BOOTSEL needs to read unpartitioned space

If the table gives the bootloader **no** access to unpartitioned space, an
A2 bootrom refuses **every** BOOTSEL flash program (picotool and UF2), even
into a firmware slot the bootloader may write; erases still work.  Bisected
on the Pico 2 over SWD, 2026-10-15: unpartitioned `bootloader: "r"` makes
slot writes work again, while table erase or overwrite, a full-chip erase
and reads of the store partitions all stay refused.  So the production
tables use `"r"`; the table itself and the unpartitioned gaps hold nothing
secret.  (Padding the gaps with closed partitions instead did not help.)

## 6. Production

- Install the `-prod` table, signed with the firmware signing key
  (`ec_firmware_signing_key-bootkey0.pem`, secp256k1).  Secure boot needs that key's
  hash in an OTP boot-key slot and the secure-boot enable bit: the same
  OTP burn covers the firmware and the table.  Secure boot alone does not
  make the bootrom *require* a signed table; `BOOT_FLAGS0.SECURE_PARTITION_TABLE`
  would, and with it an invalid table is replaced by an empty, open one, so
  provisioning leaves that flag off.  The whole procedure, verified on an
  RP2350-One, is [PROVISIONING.md](PROVISIONING.md).
- Recovery on a production board is through the firmware (STORE STATUS,
  OPEN DEGRADED, ACCEPT STORE, FORMAT STORE; [KEYSTORE_RECOVERY.md](KEYSTORE_RECOVERY.md))
  or SWD where debug is enabled; BOOTSEL cannot wipe the store.

## 7. Tests

- Host: the maps, linker scripts and tables agree (incl. the midpoint
  rule and closed store partitions); `check_layout` on real table words;
  boot-info decoding; the key cap.
- Hardware: `tests/hw/test_22_layout.py` (booted from a partition; store
  partitions closed; with `PICO2HSM_ALLOW_BOOTSEL=1`, BOOTSEL refused on
  the store).  A/B selection, fallback and TBYB were run on the LCD board
  (scripts in the session log; not automated: they reflash the board).

## 8. Owner decisions (2026-10-14)

- Partition tables on every board and build type; provisioning as close
  to identical as possible.
- 4 MB: one slot (option A), 128-key cap; 16 MB: A/B, 4 MB slots, store
  from 8 MB, all 251 keys.
- Production uses signed tables; development tables stay replaceable.
- TBYB buy rule: the first answered APDU.
