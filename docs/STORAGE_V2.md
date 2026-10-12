# Storage V2 — journaled keystore for pico2hsm 2.0

Status: **design, approved in principle by the owner (2026-10-12)**; to be
reviewed for security before any code is written.  Ships in the 2.0.0
series.  It is a breaking change: 1.x keystores are not migrated (no
devices are in use), and 2.0 firmware refuses a 1.x keystore with a clear
error.

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
  tests.

**Non-goals**
- **No RAID, no multi-chip stores, no custom boards.** The project targets
  off-the-shelf RP2350 boards: SmartCard-HSM / OpenSC compatibility
  already bounds what one device can usefully hold (255 SC-HSM key
  references), so a custom board with several flash chips buys nothing.
  The RAID-1 code, the WAL and the multi-chip plumbing are removed.
- No migration of 1.x stores.
- Protection of a QMI-flash board against an attacker who can rewrite
  the *whole* internal flash consistently (counter log included) needs
  an OTP counter: audit item S-15, on hold.

## 3. Flash layout (2.0)

Internal (QMI) flash.  The bootrom partition table and the A/B firmware
slots are part of the 2.0 layout work (`docs/` plan to follow); they are
listed here so the store's place is fixed.

| Region | 4 MB boards (Pico 2, RP2350-One) | 16 MB boards (Geek, Waveshare LCD) |
|---|---|---|
| Partition table | bootrom block | bootrom block |
| Firmware | slot A, 1.5 MB | slots A and B, 1.5 MB each |
| Counter log | 64 KB (16 sectors) | 64 KB |
| RSA key pool | 48 KB | 48 KB |
| Keystore (QMI boards) | rest, ~2.4 MB | rest, ~12.9 MB |

- The **counter log** grows from 4 to 16 sectors: it now also carries the
  signature counter and the store anchor (§8).
- **SD-card boards** (Geek SD, Waveshare LCD SD) keep the keystore on the
  card (up to 16 MiB of it, as now).  The counter log and the RSA pool stay
  on internal flash: a removable card never holds retry counters, pooled
  keys or the anchor.
- Exact offsets go in `storage/flash_layout.rs` with the existing
  compile-time checks; the linker scripts end the firmware slot where the
  constants say.

## 4. Keys

All derived at boot from the SMK (`OTP → HKDF → SMK`, unchanged):

| Key | Derivation | Use |
|---|---|---|
| K_obj(key_id) | `HKDF(SMK, "pico2hsm-obj-v2" ‖ key_id as u32 BE)` | AES-256-GCM of one object. The **full** 32-bit key ID (applet and partition bytes included), not its low byte. |
| K_idx | `HKDF(SMK, "pico2hsm-idx-v2" ‖ store_id)` | HMAC-SHA256 of journal records, index pages and sector headers. |

`store_id` is 16 random bytes chosen when the store is formatted
(INITIALIZE / first boot).  It is in every sector header and in the
anchor, so a sector from another store, or another device's card, never
verifies.

## 5. Objects

One object = one or more consecutive 4 KB data sectors, as now.  Header
(in every sector of the object, so a scan can recognise it):

```
magic "P2O2" | store_id(16) | key_id u32 | seq u64 | type u8 | algo u8 |
flags u8 | sector_index u8 | sector_count u8 | plaintext_len u16 |
nonce(12) | ciphertext … | tag(16)
```

- `seq` is the store-wide write sequence number of the write that created
  this version (§6).  It is in the AES-GCM associated data with every
  other header field, so a header cannot be edited and an old version
  cannot be passed off as a newer one: the index says which `seq` each
  key ID must have.
- A new version of a key ID is always written to fresh sectors; the old
  ones are erased only after the new version is committed.
- Non-secret metadata (`type`, `algo`, `flags`) is also in the index entry,
  so LIST KEYS and the display never decrypt anything.

## 6. Journal

The journal is the commit log and the only place the location of an
object is written.  It is a ring of **16 sectors** inside the keystore
region.

**Sector header** (first 32 B): `"P2J2" | store_id(16) | ring_seq u32 |
HMAC-truncated(8)`.  `ring_seq` orders the ring's sectors; the oldest is
the next to be erased.

**Record** (32 B, 127 per sector, page-aligned so a record never spans a
256-byte program page):

```
kind u8 (PUT, DELETE, CHECKPOINT) | sector_count u8 | rsv u16 |
key_id u32 | first_sector u32 | seq u64 | aux u32 | mac(8)
```

- `mac` = first 8 bytes of `HMAC-SHA256(K_idx, store_id ‖ ring_seq ‖
  record[0..24])`.
- `seq` is the store-wide sequence number, one per record, strictly
  increasing.  For PUT, `aux` is the object's metadata (type, algo,
  flags); for CHECKPOINT, `first_sector`/`aux` locate the index snapshot.
- **Commit point:** a write is committed when its record is programmed
  and verifies.  Programming a record needs no erase.

**Write (PUT):** allocate free sectors → program the object → verify →
append PUT → update the anchor (§8) → erase the superseded version's
sectors.
**Delete:** append DELETE → update the anchor → erase the object's
sectors.  The record comes first, so a power cut can only leave
unreferenced sectors (reclaimed at boot), never a reference to erased
ones (fixes F7).

**Torn records.**  Only the newest record can be torn by a power cut.  A
record that fails its MAC *at the tail* is the end of the journal; one
that fails *before* a valid record is corruption — the store fails closed
(§9).

## 7. Index snapshot and lookup

Replaying the whole journal for every lookup would be slow, so the
journal is **checkpointed**:

- When the tail since the last checkpoint passes a threshold (512 records
  on QMI; tuned lower for SD, §10), the firmware writes a **snapshot**:
  all live entries sorted by key ID, 24 B each (`key_id, first_sector,
  sector_count, type, algo, flags, seq, rsv`), 170 per sector, with a
  sector header and an HMAC over the whole snapshot.  It is written to
  free data sectors (so its wear is spread like any object), then a
  CHECKPOINT record points at it, then the previous snapshot is erased.
- **Lookup** = binary search in the snapshot, then a scan of the journal
  tail since the checkpoint (newest wins).  On QMI boards both are read
  through XIP (memory-mapped): microseconds.
- **Free space** is a bitmap rebuilt at boot from the snapshot and the
  tail: 1 bit per sector (64 B for 4 MB, ~400 B for 16 MB).  Sectors that
  are neither referenced nor blank (an interrupted write) are erased in
  the background.
- **Capacity** is set by flash: ~570 objects on 4 MB boards, ~3 100 on
  16 MB boards, ~4 000 on a 16 MiB SD keystore.  The one-byte SC-HSM key
  reference still caps SC-HSM *keys* at 255; certificates, descriptions
  and the other applets fill the rest.

**RAM:** the free bitmap, one sector buffer (SD boards), and a small
cache of hot index entries.  The 1.x directory copy, key index and EF
cache (~24.5 KB, F4) go away.

## 8. Anchor: rollback and card binding

The **anchor** is a counter-log record on *internal* flash:
`(store_id, head_seq)` — the `seq` of the newest committed journal record.

- Updated after every commit (journal first, then anchor).
- **Boot check:** the journal's head must be `head_seq` or `head_seq + 1`
  (a power cut between the two writes); the anchor is then brought
  forward.  A journal *behind* the anchor, or with another `store_id`, is
  a rollback or a different store: **fail closed** (display error code,
  keystore refused), never a silent fallback.
- **Deleted keys stay deleted:** putting an erased object back needs a
  PUT record newer than its DELETE with a valid MAC (needs K_idx) *and* a
  journal head consistent with the anchor.  Restoring an old journal is a
  rollback (above).

What this covers, by board:

| Board | Attacker can rewrite… | Detected? |
|---|---|---|
| SD-card boards | the card (copy, roll back, swap with another device's card) | **Yes**: the anchor is on internal flash; another device's card fails `store_id` and K_idx (its SMK differs). |
| QMI boards | the keystore only | **Yes** (anchor elsewhere on the chip, same check). |
| QMI boards | the whole internal flash, consistently | **No** — needs an OTP counter (S-15, on hold). Requires the chip's flash to be read and rewritten, i.e. physical access with debug enabled or the flash chip desoldered. |

## 9. Failure handling

- Any MAC failure, impossible pointer or sequence anomaly outside a torn
  tail → storage error (`6581` to the host, `STORE` fault on the display),
  store read-only or refused.  Never "drop the bad entry and carry on":
  silently losing an entry is itself a rollback or a denial of service.
- Program/erase failures: retry, then fail the command with `6581`; RAM
  state follows flash (existing invariant).
- A 1.x store (directory magic `P2D2`/`P2KD`, objects `P2HM`) is reported
  as *incompatible: re-initialise* — on the display and through the
  existing incompatible-store path — and never written to.

## 10. Wear

NOR flash is rated for ~100 000 erase cycles per sector (20-year
retention).

| Hot spot | 1.x | 2.0 |
|---|---|---|
| Directory / journal | ½ erase per write on 2 fixed sectors → ~200 000 writes | 1 erase per 127 records, rotated over 16 sectors → ~200 million writes |
| Object data | 2 erases per update, rotated over all free sectors | same; snapshots share the rotation |
| Signature counter | a keystore write per signature (F2) | a 16-byte counter-log record; log grows to 16 sectors × 256 slots → ~400 million updates |
| Anchor | — | one counter-log record per commit (same budget as above) |

SD cards wear-level internally; 2.0 writes the card in whole 4 KB logical
sectors as now.  The SD checkpoint threshold is lower (e.g. 64 records)
because each journal read over SPI costs ~1 ms per 512-byte card sector.

## 11. The SD-card use case: split shipment

An SD-card board can be enrolled in a domain, then shipped to a remote
party **with the card sent separately**:

- The card alone is useless: every object is encrypted under keys derived
  from the device's SMK (from OTP, per device on provisioned boards), and
  the index under K_idx.
- The device alone holds no user keys: keys, DKEK and domain records live
  on the card.  Internal flash holds only the retry counters, the anchor
  and not-yet-issued pooled RSA keys.
- On reinsertion the device mounts the card, checks `store_id`, MACs and
  the anchor (§8) — a card copied or tampered with in transit is refused —
  and resumes domain sync (cluster plan V3, P3/P4 anti-entropy) to catch
  up on what changed while it was away.
- Unprovisioned development boards share a blank-OTP SMK, so their cards
  are interchangeable; that is a development convenience only and is
  shown on the display (DEV footer).

## 12. Removed in 2.0

- `storage/raid.rs`, `storage/wal.rs`, `HybridKeyStore`, mirror-pair status in
  `StorageManager`, multi-chip `chips: Vec<_, 8>` (audit M-07).
- The `P2KD` legacy directory, `P2K2`/`P2K3` key formats, `check_seq_no`.
- Docs describing RAID-1 / mirrored SPI flash (README, board docs).

## 13. Testing

- **Host, fault injection:** a simulated flash that can cut power before,
  during (torn page) or after every program and erase.  Property test:
  random sequences of PUT / DELETE / checkpoint with a cut at every step;
  after remount the store equals the state after the last committed
  operation, or the one before it if the cut hit its anchor update.
- **Host, adversarial:** replay an old store image, a stale snapshot, a
  record from another store, a swapped object sector, a re-written deleted
  object → each is refused.
- **Wear model:** count erases per sector over a million mixed operations;
  assert the maximum stays within the table above.
- **Hardware:** probe-rs resets mid-write in a loop (QMI and SD boards),
  SD card pulled mid-write, card from another device, and the existing
  full suite.

## 14. Phasing

1. Counter log to 16 sectors; signature counter and anchor records in it.
2. Object format V2 (full key ID in K_obj, `seq` in the AAD).
3. Journal, snapshot, lookup, free bitmap; remove the RAM directory, key
   index and EF cache.
4. Anchor checks and fail-closed boot.
5. Remove RAID / WAL / multi-chip / legacy formats.
6. 2.0 flash layout with the partition table (separate plan).
7. Docs; full hardware runs; `v2.0.0-rc1`.

Security review of this document comes first; then each phase lands with
its tests.

## 15. Open questions

- SD lookup latency: with no RAM index, is a 64-record checkpoint
  threshold enough, or do SD boards keep a small RAM cache of the tail?
  Measure on hardware.
- Whether to keep a 1–2 entry EF cache for repeated READ BINARY of the
  same PKCS#15 file on SD boards.
- Snapshot threshold on QMI (512) vs. the cost of a checkpoint; measure.
