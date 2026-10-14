# 2.0 flash layout: partition table and firmware slots (Storage V2 phase 6)

Status: **plan, for owner review (2026-10-14).**  This is the "separate
plan" that [STORAGE_V2.md](STORAGE_V2.md) §3 and §14 (phase 6) call for.
Decisions D1–D5 (§7) need the owner; the rest follows from them.

## 1. What phase 6 delivers

1. A bootrom **partition table** (PT) on every board, describing the
   firmware slot(s) and the four store regions.
2. **A/B firmware slots** on the 16 MB boards, with try-before-you-buy
   (TBYB): a new image that fails its health check is never kept.
3. The store regions **closed to the bootloader**, so BOOTSEL (picotool,
   UF2) cannot read or rewrite the keystore, binding, counter log or RSA
   pool (D2).
4. Firmware that is correct when booted from a partition (§4: today it is
   not), and that refuses to run its store against a PT that disagrees
   with its compiled layout.

Not in phase 6: OTP anti-rollback (S-15, on hold), signed partition
tables beyond what secure boot requires, a bigger keystore on the 16 MB
QMI boards (possible later, §3.3).

## 2. RP2350 facts this plan relies on

From the RP2350 datasheet (§5.1 boot, §5.9 partition tables) and the
bootrom's behaviour; step S0 (§6) confirms each on hardware before any
firmware change depends on it.

- The PT is a block (a `PARTITION_TABLE` item) in the **first 4 KB** of
  flash.  Up to 16 partitions, 4 KB aligned, each with permissions
  (Secure, Non-secure, bootloader: read / write), optional A/B link,
  accepted UF2 families and a name.
- An image booted from a partition runs **address-translated**: the
  bootrom maps the partition to `0x1000_0000` (and the `0x1400_0000`
  uncached alias), with the window as large as the partition.  So one ELF,
  linked at `0x1000_0000`, runs from either slot.  Accesses past the window
  fault.  The **untranslated** uncached alias `0x1C00_0000` still sees
  physical flash.
- With an A/B pair, the bootrom boots the valid image with the higher
  version (IMAGE_DEF `VERSION` item).  A UF2 dropped in BOOTSEL goes to
  the slot that is **not** the current boot slot.
- **TBYB:** an image flagged try-before-you-buy is booted once; unless it
  calls the ROM's `explicit_buy` in time, the next boot goes back to the
  other slot.
- PT permissions bind the bootloader (picotool, UF2 writes) and the ROM's
  checked flash calls.  Secure firmware using the unchecked ROM flash
  calls (embassy-rp does) is not limited by them.

## 3. Proposed layout (D1)

**Keep every store region at its current physical offset.**  The interim
placement of phases 1–5 becomes the final one; the PT describes it.
Nothing on any board moves, so no store or counter log is migrated again,
and a board on today's flat layout keeps its keys across the switch.

### 3.1 4 MB boards (Pico 2, RP2350-One)

| Physical range | Size | Partition | Bootloader access (D2) |
|---|---|---|---|
| `0x000000–0x001000` | 4 KB | partition table | — |
| `0x001000–0x1D8000` | 1,884 KB | `fw-a` (firmware slot A) | read/write |
| `0x1D8000–0x1E0000` | 32 KB | `binding` | none |
| `0x1E0000–0x1F0000` | 64 KB | `counters` | none |
| `0x1F0000–0x1FC000` | 48 KB | `rsa-pool` | none |
| `0x1FC000–0x200000` | 16 KB | (spare; the old v1 counter log) | none |
| `0x200000–0x400000` | 2 MB | `keystore` | none |

Slot A is 4 KB smaller than today's firmware region (the PT takes the
first sector).  Release images are ~0.55 MB, debug ~1.3 MB.

### 3.2 16 MB boards (Geek, Waveshare LCD; QMI and SD variants)

The lower 4 MB exactly as above, plus:

| Physical range | Size | Partition |
|---|---|---|
| `0x400000–0x5D7000` | 1,884 KB | `fw-b` (slot B, A/B-linked to `fw-a`) |
| `0x5D7000–0x1000000` | ~10.2 MB | unallocated |

On the SD boards the keystore partition is unused (the store is on the
card) but stays reserved, so all boards share one map.

### 3.3 The alternative (not recommended)

STORAGE_V2 §3 sketched a 1.5 MB slot and a ~2.4 MB keystore on 4 MB
boards, ~12.9 MB on 16 MB.  It means moving the store regions once more
(another breaking change before rc1) for ~400 KB that no board needs
yet.  A 16 MB QMI keystore can grow into the unallocated space later,
without moving anything.

## 4. Firmware changes

1. **Untranslated store reads.**  `xip_read` and the verify read in
   `QmiFlash::write_page` (`embassy_rp::flash::Flash::blocking_read`) use
   the translated window `0x1000_0000 + offset`.  Booted from `fw-a` at
   `0x1000`, every store read would land 4 KB off, and anything past the
   slot would fault.  All store reads move to `0x1C00_0000 + offset`
   (physical, uncached: also correct on the flat layout, so this lands
   first).  Programs and erases already use physical offsets.
2. **Layout constants and checks.**  `flash_layout.rs` gains the PT, slot
   A/B ranges and per-flash-size maps; the existing compile-time checks
   and the host test that matches the linker scripts extend to them.  A
   new host test checks the PT definitions (§5) against the constants.
3. **Boot check.**  At boot, core0 reads the loaded PT through the ROM
   (`get_partition_table_info`) and compares every store partition with
   the constants.  A mismatch (or no PT where one is required, D5) fails
   closed with a new display/APDU error, before any store write.
4. **IMAGE_DEF.**  Add a `VERSION` item (from the crate version), and the
   TBYB flag on the A/B boards.
5. **Buy.**  On the A/B boards, after the health check (D4) the firmware
   calls `explicit_buy`; until then nothing durable changes that the old
   firmware could not read.

## 5. Tooling, CI and the update path

- PT definitions as picotool JSON in `boards/` (one per flash size);
  `picotool partition create` turns each into a one-time install UF2.
- CI builds the PT UF2s next to the firmware UF2s (family `rp2350-arm-s`,
  as now); the release notes say: install the PT once, then the firmware.
- Updates: BOOTSEL + UF2 or `picotool load`.  On the 16 MB boards the
  image lands in the other slot and is tried (TBYB); on the 4 MB boards it
  replaces slot A (no fallback: the flash has no room for two slots).
- `build-all-debug.sh` keeps flashing a flat image with probe-rs (D3).
- Signed builds: `picotool seal` signs the image as now; S0 checks
  whether the bootrom then also requires a signed PT and, if so, the PT
  is signed with the same key.

## 6. Steps

| Step | What | Tested by |
|---|---|---|
| S0 | Hardware spike: PT install, boot from `fw-a`, translated-window fault, untranslated reads, UF2 to `fw-b`, TBYB revert and buy, bootloader denied on a closed partition, `picotool erase` against it. | Notes in this doc; no firmware merged. |
| S1 | Untranslated store reads (§4.1). | Host tests; full suite on the flat layout. |
| S2 | Constants, PT JSON, linker scripts, host checks (§4.2, §5). | Host tests; clippy on all boards. |
| S3 | Boot PT check, IMAGE_DEF version and TBYB, buy (§4.3–4.5). | Host tests for the check; HW below. |
| S4 | CI artifacts, release and upgrade docs, runbook. | CI. |
| S5 | Hardware: flat → PT upgrade keeps the store (Pico 2, RP2350-One, LCD SD); A/B update and TBYB revert on the LCD board; full suites booted from a partition. | Full suites; a new `test_22_layout`. |

## 7. Decisions for the owner

- **D1, layout:** keep today's physical offsets (§3; recommended), or the
  §3.3 layout that moves the store.
- **D2, bootloader access to the store partitions:** none (recommended:
  in production BOOTSEL is the main physical attack surface; with access,
  picotool can dump the sealed store and RSA pool, or erase the counter
  log), or read-only, or open.  Recovery stays FORMAT STORE and SWD.  S0
  checks that a full-chip `picotool erase` still works or fails cleanly.
- **D3, development flashing:** keep probe-rs flashing flat images
  (recommended; the store regions are at the same offsets either way), or
  make debug builds PT images flashed with picotool.
- **D4, TBYB buy rule:** buy once core1 answers, USB is configured and
  the store is up, read-only, or refused for a reason the old firmware
  would also see (missing card, rollback); do not buy when the new
  firmware refuses a store the old one mounted (an incompatible change):
  the board goes back to the old slot.  Recommended as stated.
- **D5, flat images on PT boards:** whether 2.0 release firmware refuses
  to run without a PT (stricter: one layout in the field), or runs flat
  too (recommended until rc1, to keep the Pico 2 and RP2350-One dev
  boards simple; revisit for 2.0.0).
