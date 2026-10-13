# Storage V2 — journaled keystore for pico2hsm 2.0

Status: **design approved by the owner (2026-10-12), revised after a
security review and re-reviewed the same day (§17, §18); owner decisions
in §16.  Implemented: phase 1 (counter log v2, binding ring, interim
layout, #14); the engine and its wiring (phases 2–4 core: object format,
journal, snapshots, lookup, allocation, anchor checks, formatting rules,
fail-closed boot, FORMAT STORE).  Still to do: OPEN DEGRADED and ACCEPT
STORE commands (the engine has the read-only mount), the SO-PIN verifier
in the binding, removal of the 1.x code (phase 5), the partition-table
layout (phase 6), the SD power-pull campaign.**  Ships in the 2.0.0 series.  It is a
breaking change: 1.x keystores are not migrated (no devices are in use),
and 2.0 firmware refuses a 1.x keystore with a clear error.

**Reviews (2026-10-12).**  The first review of the draft found 3
critical, 6 high, 5 medium and several low issues; §17 maps each to its
fix.  A second review of the revision found 3 high and 7 medium/low
issues in the fixes themselves (an anchor fork, ACCEPT STORE, runtime
write failures, the torn-tail VOID at a sector boundary, …); §18 resolves
them and wins where it disagrees with the text.

## 1. Why

The 1.x keystore (`firmware/src/storage/filesystem.rs`) works, but a
review of its write path (2026-10-12) found:

| # | Finding | Consequence |
|---|---|---|
| F1 | The directory is one 4 KB sector, rewritten (A/B, sectors 0 and 1) on **every** save and delete. | Each directory sector takes ½ erase per keystore write: ~200 000 writes in the device's life, whatever the flash size. |
| F2 | The OpenPGP signature counter (DO 93) is a keystore object, saved on every PSO:CDS (`openpgp/commands/pso.rs:62`). | Every signature costs 2 data-sector erases and a directory rewrite. 100 signatures a day wears the directory out in ~5 years; automated signing at 10 000 a day in ~3 weeks. |
| F3 | The directory caps the store at 340 objects (keys, certificates and files together). | 2 MB of keystore flash holds 340 objects using ~1.36 MB; 16 MB boards use 4 MB of their flash. |
| F4 | RAM holds the whole directory (16 B × 340), the SC-HSM key index (8 B × 340) and an EF cache (16 × 1 KB). | ~24.5 KB of RAM on every board. |
| F5 | The directory has an unkeyed CRC32, no MAC. | Integrity of the object → location map rests on the objects' own checks. |
| F6 | Object generation is written but never compared (`check_seq_no` has no callers); the per-object key is `HKDF(SMK, "pico2hsm-keyobj-v1" ‖ key_id low byte)`. | With raw write access to the store, an old copy of an object — or a deleted key — can be put back and is accepted. |
| F7 | Delete erases the data sectors, then rewrites the directory. | A power cut in between leaves an entry pointing at erased sectors. |
| F8 | Boot fetches and decrypts every SC-HSM object to build the key index and EF cache. | Up to ~1.4 MB read and 340 AES-GCM decrypts at boot. |
| F9 | The WAL (`wal.rs`) and RAID-1 mirroring (`raid.rs`) are never used; `StorageManager::init`'s comment says it replays the WAL, and it does not. Multi-chip support (`chips: Vec<_, 8>`, mirror pairs) only serves the RAID design. | Dead code and misleading documentation. |

## 2. Goals and non-goals

**Goals**
- No erase-hot sector: wear spread so the store outlives the device at any
  realistic write rate.
- Frequently-changing values (counters) never touch the keystore.
- Capacity set by flash, not by a RAM table.
- No per-object RAM tables; nothing decrypted at boot.
- Every byte that steers the store is authenticated with a key derived
  from the storage master key (SMK).
- Rollback and resurrection of deleted keys detected wherever the hardware
  allows (fully on SD-card boards; see §8).
- Power-cut safe at every program and erase, proven by fault-injection
  tests (and, for SD cards, real-card power-pull tests).
- A store is never formatted by accident: no state of the card or flash
  alone triggers a format once a store exists (§8.3).
- A damaged store fails closed but stays recoverable (§9.3).

**Non-goals**
- **No RAID, no multi-chip stores, no custom boards.** The project targets
  off-the-shelf RP2350 boards: SmartCard-HSM / OpenSC compatibility
  already bounds what one device can usefully hold (255 SC-HSM key
  references), so a custom board with several flash chips buys nothing.
  The RAID-1 code, the WAL and the multi-chip plumbing are removed.
- No migration of 1.x stores, and no supported downgrade from 2.0 to 1.x
  (§8.2).
- Protection of a QMI-flash board against an attacker who can rewrite
  the *whole* internal flash consistently (counter log and binding block
  included) needs an OTP counter: audit item S-15, on hold.

## 3. Flash layout (2.0)

Internal (QMI) flash.  The bootrom partition table and the A/B firmware
slots are part of the 2.0 layout work (`docs/` plan to follow); they are
listed here so the store's place is fixed.

| Region | 4 MB boards (Pico 2, RP2350-One) | 16 MB boards (Geek, Waveshare LCD) |
|---|---|---|
| Partition table | bootrom block | bootrom block |
| Firmware | slot A, 1.5 MB | slots A and B, 1.5 MB each |
| Binding block | 32 KB (ring of 8 sectors, R8) | 32 KB |
| Counter log | 64 KB (16 sectors) | 64 KB |
| RSA key pool | 48 KB | 48 KB |
| Keystore (QMI boards) | rest, ~2.4 MB | rest, ~12.9 MB |

- The **binding block** (new) holds the store's identity, epoch secrets
  and the SO-PIN verifier (§8.1).  It is written only on format,
  applet reset, SO-PIN change and epoch rotation.
- The **counter log** grows from 4 to 16 sectors: it now also carries the
  signature counter and the per-commit anchor (§8.2).
- **SD-card boards** (Geek SD, Waveshare LCD SD) keep the keystore on the
  card (up to 16 MiB of it, as now).  The binding block, counter log and
  RSA pool stay on internal flash: a removable card never holds retry
  counters, pooled keys, epoch secrets or the anchor.
- Exact offsets go in `storage/flash_layout.rs` with the existing
  compile-time checks; the linker scripts end the firmware slot where the
  constants say.
- **Interim placement (phases 1–5, until the partition table of phase
  6):** the new regions come out of the top of the firmware region, not
  the keystore (the 1.x filesystem allocates anywhere above 0x200000):
  firmware 0x000000–0x1D8000 (1.84 MB; the debug image is ~1.3 MB),
  binding ring 0x1D8000–0x1E0000, counter log v2 0x1E0000–0x1F0000, RSA
  pool 0x1F0000–0x1FC000 (unchanged, pooled keys survive), the v1 counter
  log 0x1FC000–0x200000 (migrated once, then erased and left spare),
  keystore 0x200000+.

## 4. Keys

All derived at boot from the SMK (`OTP → HKDF → SMK`, unchanged):

| Key | Derivation | Use |
|---|---|---|
| K_bind | `HKDF(SMK, "pico2hsm-bind-v2")` | HMAC of the binding block; SO-PIN verifier. |
| K_idx | `HKDF(SMK, "pico2hsm-idx-v2" ‖ store_id ‖ E_store)` | HMAC-SHA256 of journal records, snapshot sectors and ring headers. |
| K_obj(key_id) | `HKDF(SMK, "pico2hsm-obj-v2" ‖ store_id ‖ E_group ‖ key_id as u32 BE)` | AES-256-GCM of one object. The **full** 32-bit key ID (applet and partition bytes included), not its low byte. |

- `store_id`: 16 random bytes chosen when the store is formatted (§8.3).
  It is in the binding block, every ring header and every object header,
  and in K_idx and K_obj: a sector from another store, another device's
  card, or a store from before a format never verifies or decrypts.
- **Epoch secrets** (32 random bytes each, binding block only, never on
  the card).  `E_store` is replaced on every format.  `E_group` is one of
  three applet groups, chosen by the key ID's applet byte:

  | Group | Applet bytes | Replaced on |
  |---|---|---|
  | SC-HSM | 0x00 (SC-HSM), 0x10 (domain records) | format, SC-HSM INITIALIZE |
  | PIV | 0x01 | format, PIV reset |
  | OpenPGP | 0x02 | format, OpenPGP factory reset |

  Per-group epochs follow the owner scoping of the resets: SC-HSM
  INITIALIZE wipes SC-HSM keys and domain records but never PIV or
  OpenPGP keys (security invariant), so it can only crypto-erase its own
  group.  K_idx uses only `E_store`: rotating a group epoch must not
  invalidate the journal's MACs.
- The old epoch is gone once the binding block's previous copy is erased
  (§8.1).  From then on, copies of that group's objects left on an SD card
  — sectors overwritten with 0xFF but kept by the card's FTL, or an old
  card dump — cannot be decrypted with this device (fixes M2).
- **Limit:** a single-key DELETE does not rotate an epoch.  On QMI flash
  the erase is real; on an SD card the FTL may keep the old pages, which
  stay decryptable by this device until the group's next reset or a
  format.  Index metadata (below) is never crypto-erased.

All MAC and tag comparisons are constant-time.

## 5. Objects

One object = one or more consecutive 4 KB data sectors, as now.  Header
(in every sector of the object, so a sector can be recognised):

```
magic "P2O2" | store_id(16) | key_id u32 | seq u64 | type u8 | algo u8 |
flags u8 | sector_index u8 | sector_count u8 | plaintext_len u16 |
nonce(12) | ciphertext … | tag(16)
```

- `seq` is the store-wide sequence number of the PUT record that commits
  this version (§6).  It is in the AES-GCM associated data with every
  other header field, so a header cannot be edited and an old version
  cannot be passed off as a newer one: the index says which `seq` each
  key ID must have.
- `nonce` is 96 bits from the TRNG, fresh for every write, never derived
  from `seq` or a counter.  With K_obj unique per (store, epoch, key ID),
  a repeat needs a 96-bit random collision under one key.
- A new version of a key ID is always written to fresh sectors; the old
  ones are erased only after the new version is committed.
- Non-secret metadata (`type`, `algo`, `flags`) is also in the index entry,
  so LIST KEYS and the display never decrypt anything.  After decryption
  the firmware checks the header's key ID, `seq`, type, algo and flags
  against the index entry; a mismatch fails that key (§9.3).
- **Cleartext on the card:** key IDs, types, algorithms, flags, sizes,
  `seq` numbers and the write history (journal) are readable by anyone
  holding an SD card.  Key material, labels, certificates and PKCS#15
  files are encrypted objects.  Accepted.

## 6. Journal

The journal is the commit log and the only place the location of an
object is written.  It is a ring of sectors inside the keystore region:
**16 sectors** on QMI flash, **64** on SD (below).  Ring sector *i* is
always physical ring position *i*; positions are used in order.

**Sector header** (first 32 B): `"P2J2" | store_id(16) | ring_seq u32 |
HMAC-truncated(8)`.  `ring_seq` grows by one per recycled sector and
`ring_seq mod n` must equal the sector's ring position.

**Record** (32 B, 127 per QMI sector, page-aligned so a record never spans
a 256-byte program page):

```
kind u8 | sector_count u8 | rsv u16 | key_id u32 | first_sector u32 |
seq u64 | aux u32 | mac(8)
```

| Kind | Meaning | `aux` / other fields |
|---|---|---|
| PUT | key ID now lives at `first_sector`, `sector_count` | type, algo, flags |
| DELETE | key ID is gone | — |
| WIPE_OWNER | every key of one applet group is gone (applet resets, SC-HSM INITIALIZE) | group, new epoch generation |
| CHECKPOINT | index snapshot (§7) | `first_sector`, `sector_count`; `key_id ‖ aux` = 8-byte snapshot hash |
| VOID | an abandoned slot | all 32 bytes 0x00; no `seq`, no MAC |

- `mac` = first 8 bytes of `HMAC-SHA256(K_idx, store_id ‖ ring_seq ‖
  slot u16 ‖ record[0..24])`.  Ring sequence and slot index bind the
  record to its physical place: a record moved to another slot or sector
  fails.
- **Contiguity.**  From the newest valid CHECKPOINT (seq C) to the head
  (seq H), the records in ring order carry exactly C, C+1, …, H, with
  only VOID slots between them.  A gap, a repeat or a step back is
  corruption (§9).  Removing a record — a DELETE, say — and shifting the
  later ones down therefore fails twice: the shifted MACs no longer match
  their slots, and the seqs no longer run on (fixes H1).  Dropping the
  newest records instead leaves the head behind the anchor (§8.2).
- **Commit point:** a write is committed when its record is programmed,
  verifies and (SD) the card reports it written.  Programming a record
  needs no erase.

**Write (PUT):** allocate free sectors → program the object → verify →
append PUT → update the anchor (§8.2) → erase the superseded version's
sectors.
**Delete:** append DELETE → update the anchor → erase the object's
sectors.  The record comes first, so a power cut can only leave
unreferenced sectors (reclaimed when next allocated, §7), never a
reference to erased ones (fixes F7).
**Applet reset / SC-HSM INITIALIZE:** append WIPE_OWNER (one record, so
the reset is atomic) → anchor → write the binding block with the group's
new epoch (§8.1) → erase the group's sectors.  A power cut after the
record and before the epoch is written is finished at boot: a WIPE_OWNER
whose epoch generation is above the binding block's is completed before
any write.  PIV and OpenPGP keys are untouched by SC-HSM INITIALIZE, as
today; it is an owner-scoped delete, **not** a format.

### 6.1 Torn tail (fixes C1)

Only the slot being programmed when the power went can be torn.  A torn
slot cannot be reprogrammed on NOR, so it is retired, not reused.  At
mount, **before any append**:

1. Find the tail: the last record that verifies and continues the seq
   chain.
2. (QMI only) Re-program that record with its own bytes and verify.
   Programming the same 0 bits again is idempotent on NOR and completes
   a record whose cells were cut short but read valid.
3. Program the slot after it to VOID (all zero), whatever it reads:
   torn bytes, or apparently blank cells that a cut may have partly
   programmed.  A torn VOID is re-VOIDed at the next mount.
4. Appends resume at the following slot.

Any slot that is neither blank, VOID nor a valid record *before* a valid
record is corruption, never a torn tail.  One VOID per mount costs
nothing measurable (§10).

### 6.2 Ring wrap and a full store (fixes H3)

- A ring sector may be recycled only if every record in it is older than
  the newest CHECKPOINT.  If the next sector to recycle still holds live
  records, a checkpoint is written first.  With the checkpoint threshold
  (128 records on QMI, 64 on SD) far below the ring's capacity (2 032 /
  448), this only happens if checkpoints keep failing.
- **Reserved journal slots:** a PUT is refused while fewer than 4
  writable slots would remain (head sector plus recyclable sectors), so a
  DELETE, a CHECKPOINT and a mount VOID always fit.
- **Reserved data sectors:** a PUT of a *new* key ID is refused with
  `6A84` (not enough memory) if it would leave fewer free sectors than a
  snapshot of the live entries plus one, plus one largest object
  (`MAX_OBJECT_SECTORS`).  An update of an existing object may use the
  object reserve (a CHANGE PIN must still work on a full store); a
  checkpoint may use the snapshot reserve.  DELETE needs no sectors.
  So a full store can always delete, checkpoint and recycle the ring: it
  cannot wedge.

### 6.3 Ring sector recycle and power cuts (fixes H4, part)

Recycle = erase the sector → check it blank → program its header.  A cut
in between leaves a sector with no valid header.  At mount this is
allowed in exactly one place, the position after the head sector (the
next to recycle, which held no live records by §6.2); it is re-erased.
An invalid header anywhere else is corruption.

### 6.4 SD cards (fixes C2)

`sdcard.rs` today emulates page programs by read-modify-writing the whole
512-byte block (`write_page`).  A cut, or an FTL that loses a page
written earlier in the same flash page pair, can then lose records that
were already committed.  2.0 rules for the card:

- **A block that holds a committed record is never written again** until
  its ring sector is recycled.  On SD each journal record gets its own
  512-byte block (record + 0xFF padding): block 0 of a ring sector is the
  header, blocks 1–7 hold 7 records.  The ring is 64 sectors (448
  records) to compensate.  The SD backend gets a block-granular write
  API; the read-modify-write path is removed.
- Object and snapshot sectors are written as whole new blocks in fresh
  sectors (no read-modify-write); a sector's first block, which holds the
  header, is written last.
- **Durability check:** after each record block, wait for the card to
  leave busy, then CMD13 (SEND_STATUS) must report no error, before the
  anchor is updated.  The anchor is never ahead of what the card has
  accepted.  A read-back after the write proves little (the card may
  answer from its buffer), so it is not relied on.  The SD 6.0 cache is
  never enabled.
- **Residual risk:** a card may still lose acknowledged data on power
  loss (FTL behaviour is card-specific).  The result is a journal behind
  the anchor: indistinguishable from a rollback, so it fails closed, with
  the recovery path of §9.3.  **Real-card power-pull testing is
  required** before SD boards ship 2.0: several card brands and types,
  thousands of cuts, recording any false rollback (§13).  The results
  decide which cards the docs recommend (industrial / pSLC cards with
  power-loss protection expected).

## 7. Index snapshot and lookup

Replaying the whole journal for every lookup would be slow, so the
journal is **checkpointed**.

**Snapshot.**  When the tail since the last checkpoint reaches the
threshold (128 records on QMI, 64 on SD), the firmware writes all live
entries, sorted by key ID, to free data sectors (so its wear is spread
like any object's).  Entry, 24 B: `key_id, first_sector, sector_count,
type, algo, flags, seq, rsv`.  Each sector:

```
"P2S2" | store_id(16) | as_of_seq u64 | sector_index u16 |
sector_count u16 | entry_count u16 | next_sector u32 | rsv |
mac(16)                                  — 64 B header
entries: up to 168 × 24 B                — (4096 − 64) / 24 = 168
```

- `mac` = `HMAC-SHA256(K_idx, header-without-mac ‖ entries)[0..16]`.  It
  binds the store, the as-of sequence number, the sector's index and the
  snapshot's length, so a sector from an older valid snapshot, or from
  elsewhere in this one, fails (fixes H2).
- Sectors are chained by `next_sector`, so the reserve is a count of free
  sectors, not a contiguous run.  The header is programmed last.
- The **CHECKPOINT** record (seq S) carries the first sector, the sector
  count and the snapshot hash: `SHA-256(mac_0 ‖ … ‖ mac_{n−1})[0..8]`.
  The snapshot must have `as_of_seq = S − 1`.
- Order: write snapshot → append CHECKPOINT → anchor → erase the previous
  snapshot.  A cut before the CHECKPOINT commits leaves orphan sectors
  and the previous checkpoint authoritative.

**Merge RAM (fixes M5).**  The new snapshot is the old one merged with the
tail.  The tail's distinct key IDs (≤ threshold) are sorted in a static
table of 8 B each (`key_id`, slot, kind): 1 KB for 128 records.  The old
snapshot is streamed (XIP on QMI; one verified 4 KB sector at a time on
SD, in the existing sector buffer) and the new one is written through a
512 B buffer.  All static, none on the core1 stack.

**Lookup** = the tail first (newest wins), then the snapshot.
- QMI: binary search in the snapshot through XIP, then a scan of ≤128
  tail records: microseconds.
- SD: at mount the firmware keeps a **fence table** (first key ID of each
  snapshot sector, 4 B × ≤ 24 sectors) and a **tail cache** (8 B per tail
  record, ≤ 512 B).  A lookup reads one record block or one snapshot
  sector.  Every block read from the card is MAC-checked on every read,
  and must carry the `seq` (or `as_of_seq`) that RAM expects (fixes M3,
  part).

**Free space (fixes M4).**  A bitmap, 1 bit per sector, built at mount from
the snapshot and the tail: referenced sectors (objects, the live
snapshot, the ring) are used, everything else is free.  No scan of the
data area at boot.  A free sector may still hold leftovers of an
interrupted write or of a delete cut short: **allocation checks it blank
and erases it if not**.  Bitmap: 77 B on 4 MB boards, ~410 B on 16 MB,
512 B on a 16 MiB SD keystore.

**Capacity** is set by flash.  Counting one-sector objects, after the
journal ring, the live snapshot and the reserves of §6.2: ~580 on 4 MB
boards, ~3 200 on 16 MB boards, ~3 950 on a 16 MiB SD keystore.  Larger
objects (RSA-4096 keys, large certificates) take two sectors.  The
one-byte SC-HSM key reference still caps SC-HSM *keys* at 255;
certificates, descriptions and the other applets fill the rest.

**RAM:** the bitmap, the 1 KB merge table, a 512 B write buffer; on SD
boards also the existing 4 KB sector buffer, the fence table and the tail
cache.  The 1.x directory copy, key index and EF cache (~24.5 KB, F4) go
away.

## 8. Binding, anchor and formatting

### 8.1 Binding block (internal flash)

A ring of 8 sectors (R8; was A/B): each write goes to the sector after
the current one, with `gen + 1`; at boot the valid copy with the highest
`gen` wins and every other sector is erased.  Content:

```
"P2B2" | gen u32 | state (FORMATTING | ACTIVE) | store_id(16) |
format_gen u32 | E_store, E_scHsm, E_piv, E_pgp (4 × 32) |
epoch generation per group (3 × u32) | SO-PIN salt(16) |
SO-PIN verifier(32) | HMAC(K_bind)(32)
```

- Written to the next ring sector with a higher `gen`; **then the old
  sector is erased** (that erase is what destroys a replaced epoch).  At
  boot the valid copy with the highest `gen` wins and any other sector is
  erased.  Two valid copies with the same `gen`: identical bytes → keep
  one; different → fail closed.  `gen` at its maximum → refuse further
  writes (R14).
- **The SO-PIN verifier lives here**, not in the keystore:
  `HMAC(K_bind, salt ‖ SO-PIN)`, retries spent in the counter log as
  today.  The SO-PIN therefore works when the store is missing or
  refused, which recovery (§9.3) and FORMAT STORE (§8.3) need.  The
  SC-HSM PIN record keeps the user PIN and PUK.
- Why a block of its own, not counter-log records (the review proposed a
  multi-field counter-log record): it does not fit a 12-byte slot
  payload; it must be erasable on demand for epoch rotation, while the
  counter log only erases a sector when it wraps; and the log rotation of
  older firmware cannot drop it.

### 8.2 Anchor (counter log, fixes H6)

The per-commit anchor is a counter-log record on internal flash (R1, R6):

```
[0] 'A' | [1] id = 0 | [2..4] format_gen u16 (low half of the binding's)
| [4..10] head_seq u48 | [10..12] head slot u16 (ring position × slots
per sector + slot) | [12..16] CRC (as every counter-log record)
```

- `head slot` binds the anchor to *where* the head record is, not only to
  its seq: at mount the head must be exactly there, or be `head_seq + 1`
  at a later slot with only VOIDs between (R1).  A u48 seq lasts ~89 000
  years at 100 commits a second.

- Updated after every commit (journal first, then anchor).
- **One commit in flight.**  If the anchor write fails after the record
  committed, the command returns `6581` although the write *did* commit;
  the store accepts no further commit until the anchor has been brought
  forward (retried before the next commit and at boot).  Hosts that get
  `6581` on a write should re-read the state (e.g. LIST KEYS) before
  retrying.  So the head is never more than anchor + 1 (fixes H4).
- **Boot check:** the journal's head must be `head_seq` or `head_seq + 1`
  (a cut between the two writes); the anchor is then brought forward.  A
  journal *behind* the anchor, or with another `store_id`, is a rollback
  or a different store: **fail closed** (display error code, keystore
  refused), never a silent fallback.  The display shows how many records
  are missing, so a lost SD tail (§6.4) can be told from a stale copy.
- **Deleted keys stay deleted:** putting an erased object back needs a
  PUT record newer than its DELETE with a valid MAC (needs K_idx) *and* a
  journal head consistent with the anchor.  Restoring an old journal is a
  rollback (above).
- **Missing anchor.**  A binding block in ACTIVE state with no anchor
  record for its `format_gen` (counter log lost or replaced) → fail
  closed.  A missing binding block next to a non-blank store → fail
  closed (§8.3).
- **Counter-log format version 2.**  The log's `FORMAT_VERSION` goes to 2
  with the new record kinds (anchor, signature counter).  Every v2 kind is
  an absolute value keyed by (tag, id), and rotation carries the newest
  record of **every** (tag, id), known or not: later 2.x firmware can add
  kinds without an older 2.x dropping them.
- **Downgrade to 1.x is unsupported and cannot be made safe in
  software.**  1.x accepts only a version-1 header, so it reads a v2 log
  as unformatted and formats it (`migrate_retry_counters`); it also
  places its log and keystore at 1.x offsets inside the 2.0 layout.  The
  review proposed the version bump so that 1.x refuses; it cannot, so the
  defence is on the 2.0 side: after a downgrade and re-upgrade, the lost
  anchor or binding next to a non-blank store fails closed, never
  formats.  Blocking the downgrade itself needs the bootrom's image
  rollback version (OTP), tied to S-15 and the OTP layout fix.

What this covers, by board:

| Board | Attacker can rewrite… | Detected? |
|---|---|---|
| SD-card boards | the card (copy, roll back, drop or move records, swap with another device's card) | **Yes**: binding and anchor are on internal flash; another device's card fails `store_id` and K_idx (its SMK differs). |
| QMI boards | the keystore only | **Yes** (binding and anchor elsewhere on the chip, same check). |
| QMI boards | the whole internal flash, consistently | **No** — needs an OTP counter (S-15, on hold). Requires the chip's flash to be read and rewritten, i.e. physical access with debug enabled or the flash chip desoldered. |

### 8.3 Formatting (fixes C3)

A format creates a new `store_id` and new epochs; every key of every
applet is lost.  It happens **only**:

- at **first boot**: no valid binding block, no anchor, and the journal
  ring region is blank (every ring sector header reads erased); or
- by the explicit **FORMAT STORE** command: a pico2hsm proprietary APDU
  on the SC-HSM applet, authenticated with the SO-PIN against the binding
  block's verifier (no PIN needed if none was ever set), with a fixed
  confirmation value in its data.  It is shown on the display and
  recorded in the counter log.

Nothing else formats: not a blank, foreign, unreadable or corrupt card,
not an erased or damaged QMI keystore, not SC-HSM INITIALIZE (§6).  With a
binding block present, such a store is refused (`WRONG CARD` / `STORE`
fault) and the binding stays, so the real card still mounts when it comes
back: the split shipment of §11 survives a wrong card.  The 1.x card
pairing block (P2HSDCARD, which treated a corrupt signature as blank)
goes.

Two-phase, so a cut at any step resumes:

1. Binding block → `FORMATTING(new store_id, new epochs, format_gen+1)`;
   the old copy is erased, so the old store's objects are now
   undecryptable.
2. Erase the journal ring; write ring sector 0's header and a CHECKPOINT
   (seq 0) of the empty snapshot.  Data sectors are not erased (they are
   blank-checked when allocated).
3. Anchor record `(format_gen, 0)`.
4. Binding block → `ACTIVE`.

A binding block found in FORMATTING at boot restarts the format from
step 2 with the same `store_id`.

## 9. Boot, failure handling and recovery

### 9.1 Mount

1. Binding block (§8.1); FORMATTING → finish the format; none → first
   boot or fail closed (§8.3).
2. Anchor for the binding's `format_gen`; none → fail closed.
3. Ring headers: `store_id` matches; at most one invalid header, at the
   next-to-recycle position (§6.3).
4. Newest CHECKPOINT; its snapshot verifies (per-sector MACs, `as_of_seq`,
   chain, hash); build the fence table (SD) and the bitmap.
5. Tail: contiguous seqs and slot-bound MACs from the checkpoint; torn
   tail repair (§6.1).
6. Head against the anchor (§8.2); bring the anchor forward.
7. Finish a pending epoch rotation (§6, WIPE_OWNER).

### 9.2 Errors

- Program/erase failures: retry, then fail the command with `6581`; RAM
  state follows flash (existing invariant).  A `6581` may accompany a
  write that committed (§8.2).
- A 1.x store (directory magic `P2D2`/`P2KD`, objects `P2HM`) is reported
  as *incompatible: re-initialise* — on the display and through the
  existing incompatible-store path — and never written to.
- **Card removal (fixes M3).**  On a card-detect change or any SD command
  failure that looks like a missing card, all cached store state is
  dropped (bitmap, fence table, tail cache, hot entries, mount state).  A
  reinserted card gets the full mount check of §9.1.  Because every SD
  read is MAC-checked against the `seq` RAM expects, a card swapped
  between two commands without electrical detection is caught at the
  first read and triggers the same remount.

### 9.3 Damage and recovery (fixes H5)

Never "drop the bad entry and carry on": silently losing an entry is
itself a rollback or a denial of service.  But damage is contained:

| Damage | Effect |
|---|---|
| One object fails GCM, or its header disagrees with the index | That key only: `6581` on use, listed as damaged. Everything else works. |
| Snapshot or journal damage (MAC, chain, contiguity, impossible pointer), journal behind the anchor | Store **refused**. With the SO-PIN, `OPEN DEGRADED` mounts it **read-only** until reboot: the longest verifiable state (snapshot plus the valid contiguous tail) is used, keys are usable and DKEK-exportable, nothing is written. |
| Binding block or anchor lost | Store refused; FORMAT STORE is the only way on. |

`OPEN DEGRADED` needs the SO-PIN because the verifiable prefix can
predate a DELETE: without the gate, an attacker who corrupts one record
on a card could bring a deleted key back into use.  It is shown on the
display and recorded in the counter log.

Recovery from a refused store is then: `OPEN DEGRADED` → DKEK export (or
domain resync from a peer, cluster plan V3) → FORMAT STORE → restore.
The SO-PIN may also **accept the current head and re-anchor**
(`ACCEPT STORE`, §16 OD-1: decided, implement with its guards).

## 10. Wear

NOR flash is rated for ~100 000 erase cycles per sector (20-year
retention).

| Hot spot | 1.x | 2.0 |
|---|---|---|
| Directory / journal | ½ erase per write on 2 fixed sectors → ~200 000 writes | 1 erase per 127 records, rotated over 16 sectors → ~203 million records (less one VOID per boot) |
| Object data | 2 erases per update, rotated over all free sectors | same; snapshots (≤ 4 sectors per 128 records on 4 MB boards) share the rotation |
| Counter log | 4 sectors, retry counters only | 16 sectors × 255 slots × 100 000 ≈ 408 M slot writes, ~390 M after rotation carry-over — **one budget** shared by everything below |
| — anchor | — | 1 slot per keystore commit |
| — signature counter | a keystore write per signature (F2) | 1 slot per PSO:CDS |
| — PIN VERIFY | (in the counter log since 1.x) | 2 slots per VERIFY (attempt spent, then restored) |
| Binding block | — | 1 erase per format, applet reset, SO-PIN change |

Example: automated signing at 10 000 signatures a day, each with a PIN
VERIFY, costs ~3 slots per signature: 390 M / 30 000 a day ≈ 35 years.

SD cards wear-level internally.  2.0 writes the card in whole 512-byte
blocks, one journal record per block (§6.4); a mount VOID costs one
block.  The SD checkpoint threshold is 64 records and the tail is cached
in RAM (§7), because each read over SPI costs ~1 ms per block.

## 11. The SD-card use case: split shipment

An SD-card board can be enrolled in a domain, then shipped to a remote
party **with the card sent separately**:

- The card alone is useless: every object is encrypted under keys derived
  from the device's SMK (from OTP, per device on provisioned boards) and
  epoch secrets that never leave internal flash; the index is MACed under
  K_idx.  Metadata is readable (§5).
- The device alone holds no user keys: keys, DKEK and domain records live
  on the card.  Internal flash holds only the binding block, retry
  counters, the anchor and not-yet-issued pooled RSA keys.
- Booted without its card, or with a blank or foreign one, the device
  refuses the store and changes nothing (§8.3): the right card still
  mounts later.
- On reinsertion the device mounts the card with the full check of §9.1
  — a card copied, rolled back or tampered with in transit is refused —
  and resumes domain sync (cluster plan V3, P3/P4 anti-entropy) to catch
  up on what changed while it was away.
- If the card is lost for good, FORMAT STORE (SO-PIN) adopts a new one;
  the old card can never be mounted again.
- **Unprovisioned development boards** share a blank-OTP SMK computable
  from public data, so anyone holding their card can decrypt it, and a
  DKEK or domain key imported into one is exposed.  Shown on the display
  (DEV footer).  DKEK import and domain enrolment stay allowed, with a
  prominent warning (§16, OD-2: decided, warn only).

## 12. Removed in 2.0

- `storage/raid.rs`, `storage/wal.rs`, `HybridKeyStore`, mirror-pair status in
  `StorageManager`, multi-chip `chips: Vec<_, 8>` (audit M-07).
- The `P2KD` legacy directory, `P2K2`/`P2K3` key formats, `check_seq_no`.
- The SD read-modify-write `write_page` path and the P2HSDCARD pairing
  block (§6.4, §8.3).
- Docs describing RAID-1 / mirrored SPI flash (README, board docs).

## 13. Testing

- **Host, fault injection:** a simulated flash that can cut power before,
  during (torn page, partly programmed bits that read erased) or after
  every program and erase; an SD model that can also lose earlier blocks
  of the same erase unit.  Property test: random sequences of PUT /
  DELETE / WIPE_OWNER / checkpoint / ring wrap / format with a cut at
  every step, then a remount *and further writes and another remount*;
  the store equals the state after the last committed operation, or the
  one before it if the cut hit its anchor update.
- **Host, adversarial:** replay an old store image; a stale snapshot, an
  older snapshot's sector inside the current one, sectors reordered; a
  record from another store; a record dropped, moved to another slot, or
  replaced by VOID mid-chain; a swapped object sector; a re-written
  deleted object; a card swapped between two commands → each is refused.
- **Host, exhaustion:** fill the store, then DELETE, CHECKPOINT and wrap
  the ring; PUT on a full store returns `6A84`; anchor failure twice in a
  row never leaves head > anchor + 1.
- **Host, formatting:** blank card, foreign card, erased QMI keystore,
  missing anchor, missing binding block → refused, nothing written;
  first boot formats; a cut at each format step resumes; SC-HSM
  INITIALIZE leaves PIV and OpenPGP keys readable and makes old SC-HSM
  objects undecryptable.
- **Wear model:** count erases per sector over a million mixed operations;
  assert the maximum stays within the table above.
- **Hardware:** probe-rs resets mid-write in a loop (QMI and SD boards),
  card from another device, live card swap, and the existing full suite.
- **SD power-pull campaign (required before SD boards ship 2.0):**
  power removed mid-write, thousands of cycles, on several card brands
  and types; count false rollbacks; publish the recommended cards.

## 14. Phasing

1. Binding block; counter log v2 (16 sectors; anchor and signature
   counter records; carry-over of every kind).
2. Object format V2 (store_id and epoch in K_obj, full key ID, `seq` in
   the AAD, TRNG nonces).
3. Journal (contiguity, slot-bound MACs, torn-tail repair, reserves),
   snapshot, lookup, free bitmap; SD block-granular writes; remove the RAM
   directory, key index and EF cache.
4. Anchor checks, formatting rules, fail-closed boot, `OPEN DEGRADED`
   and `ACCEPT STORE` (OD-1).
5. Remove RAID / WAL / multi-chip / legacy formats / SD pairing block.
6. 2.0 flash layout with the partition table (separate plan).
7. Docs; full hardware runs; SD power-pull campaign; `v2.0.0-rc1`.

A re-review of this revision comes first; then each phase lands with its
tests.

## 15. Open questions

- Whether to keep a 1–2 entry EF cache for repeated READ BINARY of the
  same PKCS#15 file on SD boards.
- Checkpoint thresholds (128 QMI, 64 SD) vs. the cost of a checkpoint;
  measure.
- Which SD cards survive the power-pull campaign (§6.4).

## 16. Owner decisions

**OD-1 — SO-PIN re-anchor (`ACCEPT STORE`), from H5.**
*Decided 2026-10-12: implement, with the guards below (the recommendation).*
A refused store (journal behind the anchor, or damaged) can today only be
recovered through `OPEN DEGRADED` → DKEK export → FORMAT STORE → restore,
or a domain resync.  `ACCEPT STORE` would let the SO-PIN accept the
current verifiable head of the **same** `store_id` (never a foreign
store) as the new anchor and resume read-write.
- It lets an SO-PIN holder with access to the card roll the store back:
  bring back a deleted key or an old version of an object.  Counters are
  not affected (they live in the counter log).
- **Recommendation: implement it**, because SD cards can lose
  acknowledged writes (§6.4) and the alternative turns every such glitch
  into a full restore.  Guard it: SO-PIN (retries in the counter log);
  only while the store is refused; the display shows the number of lost
  records and asks for a confirmation value in the APDU; the old and new
  heads are recorded in the counter log, and a re-anchor count is kept
  and reported (in the device status and to domain peers).
- **Alternative:** no re-anchor.  Recovery only via `OPEN DEGRADED` + DKEK
  export, domain resync, or FORMAT STORE and a restore from backup.
  Strictest; costs availability on SD boards.

**OD-2 — unprovisioned development boards, from the low findings.**
*Decided 2026-10-12: warn only, in every build, but prominently* (see
"Decision" below).
A blank-OTP board's SMK is computable from public data, so a DKEK or a
domain key imported into one is exposed to anyone with its flash or card.
- **Recommendation:** production builds refuse DKEK import (key shares)
  and domain enrolment on an unprovisioned board (`6985`, reason on the
  display); development builds allow both with a persistent warning on the
  display and a log line on every boot.
- **Alternative:** warn only, in every build.
- **Decision (owner): warn only, with a significant warning** about key
  integrity, and about losing every key when the board is provisioned:
  - The display keeps the DEV · UNPROVISIONED footer, and DKEK share import
    or domain enrolment on such a board first shows a full-screen warning
    ("keys on this board are NOT protected; provisioning OTP will make
    them unreadable").  The APDU still succeeds.
  - Every boot logs the same text; device status reports `unprovisioned`.
  - Writing the storage-key IKM changes the SMK, so the store written
    before it can't be opened afterwards (the anchor binding fails); the
    old keys are lost unless they were exported (DKEK) or are held by
    domain peers.  `docs/PROVISIONING.md` says so before the IKM step.
  - Release builds without `insecure-dev-keystore` keep refusing to run
    the keystore at all on a blank IKM (unchanged).

## 17. Review findings and resolutions (2026-10-12)

| ID | Finding | Resolution |
|---|---|---|
| C1 | Torn tail record bricks the store after the next write | Mount VOIDs the slot after the tail before any append; last valid record re-programmed on NOR (§6.1) |
| C2 | SD read-modify-write and FTL loss drop committed records → false rollback | One record per block, no rewrite of committed blocks, CMD13 before the anchor, recovery path, power-pull campaign (§6.4, §9.3) |
| C3 | Auto-format orphans the real store; format not two-phase; INITIALIZE as format | Format only at first boot or by FORMAT STORE (SO-PIN); two-phase; INITIALIZE stays owner-scoped (§8.3, §6) |
| H1 | Records can be dropped/shifted on SD | Contiguous seqs from the checkpoint; slot index and ring_seq in the MAC (§6) |
| H2 | Snapshot MAC coverage unspecified | Per-sector MACs bind store, as-of seq, index, count; hash in CHECKPOINT (§7) |
| H3 | Ring wrap and full store undefined; wedge | Recycle rule; reserved slots and sectors; `6A84` on a full store (§6.2) |
| H4 | Cuts in ring recycle; anchor failure after commit | One invalid header only at next-to-recycle; one commit in flight; `6581` may mean committed; old snapshot erased after the anchor (§6.3, §8.2, §7) |
| H5 | No recovery from fail-closed | Damage contained per key; SO-PIN `OPEN DEGRADED` read-only; re-anchor is OD-1 (§9.3, §16) |
| H6 | Anchor does not fit a slot; 1.x drops tags; no-anchor case | Binding block + 12-byte anchor record; log v2 carries every kind; downgrade unsupported (1.x formats a v2 log, so 2.0 fails closed); missing anchor fails closed (§8.1, §8.2) |
| M1 | Nonces unspecified; K_obj not bound to the store | 96-bit TRNG nonces; store_id and epoch in K_obj (§4, §5) |
| M2 | Deleted keys persist on SD | Epoch secrets on internal flash, per applet group, rotated on reset/format (§4) |
| M3 | Live card swap keeps RAM state | Drop caches on removal; full mount on reinsert; MAC and expected seq on every read (§9.2, §7) |
| M4 | Boot scans every SD sector | Bitmap from the index; blank-check at allocation (§7) |
| M5 | Snapshot arithmetic; merge RAM | 168 entries/sector; 1 KB static merge table, threshold 128 (§7) |
| L | Counter-log budget, bitmap and capacity numbers; dev-board SMK; constant-time MAC; metadata cross-check; cleartext metadata | Fixed in §10, §7; OD-2; §4; §5; §5 |

## 18. Re-review findings and resolutions (2026-10-12, second pass)

The revision above was re-reviewed before any code was written.  The §17
fixes hold; these are the new or remaining issues and what the design
does about them.  Where this section and the text above disagree, this
section wins.

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| R1 | High | The anchor proves a seq count, not which record holds it: an SD attacker cuts after a record, VOIDs its slot on a copy, lets the device commit a different record with the same seq, then restores the original card (fork; a DELETE undone). | The anchor carries the head's ring slot (§8.2); the head must be at that slot, or anchor + 1 later with only VOIDs between. |
| R2 | High | ACCEPT STORE had no mechanism; lowering the anchor and appending reuses seqs under the same K_idx and K_obj, so lost records or an old object version could be replayed. | ACCEPT STORE is a **re-index**: the binding goes to a new `E_store` and `format_gen + 1` (same `store_id`, same group epochs, state REINDEXING, resumable like FORMATTING); a fresh ring with a CHECKPOINT of the accepted index; new seqs start above max(old anchor, head) + 1.  Invariant: a seq is never reused under one (`store_id`, `E_group`). |
| R3 | High | A program or verify failure at run time (not a cut) left a slot that is neither blank, VOID nor valid before later records — corruption by §6.1; SD CMD13 errors are ambiguous. | On failure: VOID the slot and verify it, retry the same seq in the next slot.  If the VOID fails: stop all commits, drop RAM state, remount.  These VOIDs count against the 4-slot reserve. |
| R4 | Medium-high | The mount VOID could land in the first slot of the *next* ring sector, which may still hold live records when checkpoints lag. | The mount VOID goes only into the current head sector; a full head sector has nothing to tear (a cut in a recycle is §6.3). |
| R5 | Medium | "At most one invalid header" contradicts a freshly formatted ring (only sector 0 has a header). | Blank and invalid are distinct: blank headers are allowed after the head while the ring is in its first lap (head `ring_seq < n`).  The head sector is the valid header with the highest `ring_seq`, `ring_seq mod n` = position. |
| R6 | Medium | The anchor's u24 + u64 left no id byte, against the v2 carry-over key (tag, id). | Anchor layout of §8.2: id byte 0, u16 `format_gen`, u48 `head_seq`, u16 head slot. |
| R7 | Medium | A pending epoch rotation could be lost (a checkpoint moves the WIPE_OWNER out of the tail) or bypassed (a PUT under the old epoch after a failed binding write). | No commit of any kind while a WIPE_OWNER's generation is above the binding's; snapshots carry the three group generations, checked against the binding at mount. |
| R8 | Medium | Binding-block wear is host-drivable: a PIV or OpenPGP reset needs only blocked PINs, and each reset writes the binding; 2 sectors last ~200 000 writes. | Ring of 8 sectors (§8.1; 32 KB); 800 000 writes. |
| R9 | Medium | FORMAT STORE "without a PIN if none was ever set" is a remote wipe of a PIV/OpenPGP-only device. | The PIN-less form only while the store is refused or the binding is absent or fails its HMAC (e.g. after OTP provisioning changed the SMK, OD-2).  A format carries the SO-PIN verifier forward when the binding verified. |
| R10 | Medium | INITIALIZE (WIPE_OWNER → binding → PIN record) cut after the binding leaves a new SO-PIN and no user PIN. | Defined state "uninitialised, SO-PIN set", recovered by re-INITIALIZE; the new SO-PIN verifier goes in the same binding write as the new epoch. |
| R11 | Low | Erased SD cards often read 0x00, which is VOID: a new card on a new device would fail the first-boot test. | For first-boot detection only, ring header blocks reading all 0x00 or all 0xFF count as blank. |
| R12 | Low | embedded-sdmmc has no public raw-command API for CMD13. | Check what `SdCard::write` issues after the data token; else a small patched driver.  Phase 3. |
| R13 | Low | A card swapped between commands is caught on reads only; an append could land on the other card. | Before each SD append, re-read and MAC-check the tail record block (or compare the CID). |
| R14 | Low | Binding edge cases: two valid copies with the same `gen`, `gen` overflow, a FORMATTING resume with another card inserted. | §8.1 rules; FORMATTING records a fingerprint of the card's ring sector 0 header. |
| R15 | Low | "QMI, keystore only" is not a real attacker class: the counter log is CRC-only on the same chip. | Accepted: anyone who can rewrite the keystore over SWD can rewrite the log; the anchor stays CRC-protected, and the table row means a keystore-region-only fault or edit. |

**Phase 1 decisions** (binding block + counter log v2):

- Counter-log v2 keeps a RAM table of raw records keyed by (tag, id),
  capped at 32; a write that would add a 33rd key is refused, never
  dropped.  Rotation carries every entry, known kinds or not.
- The v1 log (4 sectors at 0x1FC000, header version 1) is migrated once:
  its credentials and values become v2 records in the new 16-sector log,
  the sequence continues above v1's, then the v1 sectors are erased.  A
  v1 log is never treated as unformatted (that would reseed PIN state
  from the PIN records).
- The OpenPGP signature counter becomes counter-log value 0x05 (not
  monotonic: key generation and import reset it).  The key's PUT commits
  before the counter resets; a cut between leaves the count high, which
  is harmless.  The DO 93 keystore object is migrated once, then deleted.
- The binding module, its ring region and its tests land in phase 1, but
  the binding is written only by the format path (phases 3–4); the
  fail-closed rules of §8.3 are not enforced while the 1.x keystore is
  live.  The SO-PIN verifier moves to the binding in phase 4.
- WIPE_OWNER `aux`: group u8 + generation u24 (the binding keeps u32).
- `put_anchor` refuses a lower `head_seq` within one `format_gen`; only
  format and re-index change `format_gen`; a counter log in its Failed
  state blocks every keystore commit; an anchor write failure sets a RAM
  commit-blocked flag, cleared only by a successful anchor write.

