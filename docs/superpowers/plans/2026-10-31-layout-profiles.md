# Layout Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One definition of every RP2350 board's flash map, from which the linker script, partition tables, firmware constants, scripts, CI and hardware test are derived or checked; a key cap computed from keystore size; a CI image budget; a CI-tested SC-HSM-only build.

**Architecture:** A new `no_std` workspace crate `pico2hsm-layout` holds the profiles, the board table, compile-time validation, the key-cap computation and (feature `std`) renderers plus a small CLI. `firmware/build.rs` uses it to write `memory.x`; `flash_layout.rs` re-exports its values under today's names; scripts and CI query the CLI; committed partition-table JSONs are checked against the generator.

**Tech Stack:** Rust 2021 (`no_std` + `std` feature), cargo build scripts, bash, GitHub Actions, Python (pytest hardware test).

**Spec:** `docs/superpowers/specs/2026-10-31-layout-profiles-design.md`

## Global Constraints

- Every existing board's flash map is unchanged: generated `memory.x` regions and partition-table JSON bytes equal today's (`boards/*.x`, `boards/pt_*.json` at main 6ab2b84).
- Board feature names stay: `pico2_4m`, `rp2350_one_4m`, `rp2350_one_16m`, `rp2350_geek_16m`, `rp2350_geek_sdcard`, `waveshare_rp2350_lcd_16m`, `waveshare_rp2350_lcd_sdcard`. `rp2350_one_16m` keeps implying `rp2350_one_4m` (firmware/Cargo.toml line 33).
- Profiles: `4m` and `16m`. Board → profile: the two `*_4m` boards except `rp2350_one_16m` → `4m`; all others → `16m`.
- Exactly one board after resolving the `rp2350_one_16m`/`rp2350_one_4m` pair, on every target (host included); otherwise the build fails naming the active board features. No fallback board.
- The `pico2hsm-layout` crate's default build is `no_std` with no dependencies; generators and CLI only under feature `std`.
- Firmware public names in `storage::flash_layout` stay (`SECTOR`, `Map`, `MAP_4M`, `MAP_16M`, `MAP`, `FLASH_16M`, `PT_SIZE`, `SLOT_A`, `FIRMWARE_END`, `BINDING_OFFSET`, `BINDING_SECTORS`, `BINDING_SIZE`, `RETRY_COUNTER_OFFSET`, `RETRY_COUNTER_SECTORS`, `RETRY_COUNTER_SIZE`, `RSA_POOL_OFFSET`, `RSA_POOL_SECTORS`, `RSA_POOL_SIZE`, `LEGACY_COUNTER_OFFSET`, `LEGACY_COUNTER_SECTORS`, `LEGACY_COUNTER_SIZE`, `QMI_KEYSTORE_OFFSET`, `QMI_KEYSTORE_END`, `QMI_FLASH_SIZE`, `MIDPOINT_RULE`).
- SC-HSM key cap: `min(251, computed bound)` on QMI boards; pinned 251 on SD boards; override env `PICO2HSM_MAX_SC_HSM_KEYS` may only lower it (1 ≤ n ≤ bound).
- No change to Storage V2 format, OTP layout, provisioning, or protocol behaviour other than the key cap value.
- Host tests use `--target x86_64-unknown-linux-gnu`; firmware builds always `--no-default-features`.
- Commits end with the two attribution lines (`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, `Claude-Session: https://claude.ai/code/session_01SzmX3zRZNebJV2TRCpWhYS`).

## Review Focus

1. Scripts given an unknown board name must fail loudly, not default to a profile (today's `case … *) 16m` silently treats a typo as 16 MB) — test in Task 3 (`profile` of an unknown board exits non-zero listing the boards) and the scripts' use in Task 6 aborts on that exit code.
2. A board-feature mistake (none, two unrelated boards) must fail the build with a message, never pick a board — tested via `resolve_board` in Task 1.
3. A bad `PICO2HSM_MAX_SC_HSM_KEYS` (`0`, non-numeric, above the bound) must fail the build with the bound in the message — tested via `checked_cap` in Task 5.
4. `check` must fail when a committed table is missing, edited, or lacks its trailing newline — tested in Task 3.
5. The SC-HSM-only build's hardware run must not fail PIV/OpenPGP tests: they must skip when the applet is absent — Task 7 fixes any that fail.

---

## File Structure

| File | Responsibility |
|---|---|
| `layout/Cargo.toml` (create) | crate `pico2hsm-layout`, features `default = []`, `std = []`; `[[bin]] name = "pico2hsm-layout" required-features = ["std"]` |
| `layout/src/lib.rs` (create) | types, profiles, board table, `resolve_board`, const validation |
| `layout/src/geometry.rs` (create) | store-engine constants shared with `store_v2`, key-cap computation, `checked_cap` |
| `layout/src/render.rs` (create, `std`) | `memory_x`, `partition_json` |
| `layout/src/main.rs` (create, `std`) | CLI |
| `Cargo.toml` (modify) | add `layout` to workspace members |
| `firmware/Cargo.toml` (modify) | dependency + build-dependency on `pico2hsm-layout` |
| `firmware/build.rs` (modify) | board resolution, `memory.x` rendering, cap override passthrough |
| `firmware/src/storage/flash_layout.rs` (modify) | thin re-exports; tests rewritten against the crate |
| `firmware/src/storage/store_v2.rs` (modify) | use / assert the shared geometry constants |
| `firmware/src/protocol/sc_hsm/mod.rs:272-298` (modify) | `MAX_KEY_INDEX`, `MAX_SC_HSM_KEYS` from the crate |
| `boards/*.x` (delete) | replaced by the generator |
| `build-all.sh`, `build-all-debug.sh`, `.github/workflows/build.yml`, `.github/workflows/release.yml` (modify) | profile via CLI; CI `check`, image budget, SC-HSM-only host tests |
| `tests/hw/test_22_layout.py` (modify) | regions from the committed JSON |
| `docs/FLASH_LAYOUT_2_0.md`, `docs/BUILD_CONFIGURATIONS.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md` (modify) | document the definition, the CLI, the cap |

---

### Task 1: `pico2hsm-layout` core: profiles, boards, validation

**Files:**
- Create: `layout/Cargo.toml`, `layout/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)
- Test: `layout/src/lib.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  - `pub const SECTOR: u32 = 4096; pub const PT_SIZE: u32 = 0x2000; pub const SLOT_A: u32 = PT_SIZE;`
  - `pub struct Region { pub name: &'static str /* linker name, e.g. "BINDING" */, pub partition: &'static str /* e.g. "binding" */, pub id: u8, pub size: u32 }`
  - `pub struct Profile { pub name: &'static str /* "4m" | "16m" */, pub flash_size: u32, pub slot_size: u32, pub slot_b: u32 /* 0 = none */, pub store_base: u32, pub regions: &'static [Region] /* binding, counters, rsa-pool, spare, in order from store_base */, pub keystore_start: u32, pub keystore_end: u32 }`
  - `impl Profile { pub const fn region_offset(&self, partition: &str) -> u32; pub const fn keystore_sectors(&self) -> u32 }` (offsets are `store_base` + sizes of the preceding regions)
  - `pub const PROFILE_4M: Profile; pub const PROFILE_16M: Profile; pub const PROFILES: [&Profile; 2];`
  - `pub enum Media { Nor, Sd }`
  - `pub struct Board { pub feature: &'static str, pub profile: &'static Profile, pub media: Media, pub precedence: u8 }`, `pub const BOARDS: [Board; 7];`
  - `pub fn board(feature: &str) -> Option<&'static Board>`
  - `pub fn resolve_board(active: &[&str]) -> Result<&'static Board, BoardError>`; `pub enum BoardError { None, Several(/* names */ heapless-free: a fixed array or the input slice echoed */) }` — implement `core::fmt::Display` listing the active board features.
  - `pub const fn validate(p: &Profile)` — panics (const assert) on any violation.

- [ ] **Step 1: Write failing tests** in `layout/src/lib.rs`:

```rust
#[test] fn profile_4m_matches_the_shipped_map() {
    let p = &PROFILE_4M;
    assert_eq!((p.flash_size, p.slot_size, p.slot_b, p.store_base), (0x40_0000, 0x1D_6000, 0, 0x1D_8000));
    assert_eq!((p.keystore_start, p.keystore_end), (0x20_1000, 0x40_0000));
    assert_eq!(p.region_offset("binding"), 0x1D_8000);
    assert_eq!(p.region_offset("counters"), 0x1E_0000);
    assert_eq!(p.region_offset("rsa-pool"), 0x1F_0000);
    assert_eq!(p.region_offset("spare"), 0x1F_C000);
}
#[test] fn profile_16m_matches_the_shipped_map() {
    let p = &PROFILE_16M;
    assert_eq!((p.flash_size, p.slot_size, p.slot_b, p.store_base), (0x100_0000, 0x3F_E000, 0x40_0000, 0x80_1000));
    assert_eq!((p.keystore_start, p.keystore_end), (0x82_9000, 0xFF_F000));
    assert_eq!(p.region_offset("counters"), 0x80_9000);
    assert_eq!(p.region_offset("rsa-pool"), 0x81_9000);
    assert_eq!(p.region_offset("spare"), 0x82_5000);
}
#[test] fn region_sizes_and_ids() { /* binding 0x8000 id 16; counters 0x10000 id 17; rsa-pool 0xC000 id 18; spare 0x4000 id 19 (linker name LEGACY_COUNTERS); keystore id 20 */ }
#[test] fn every_board_has_its_profile() { /* pico2_4m, rp2350_one_4m -> "4m" Nor; rp2350_one_16m, rp2350_geek_16m, waveshare_rp2350_lcd_16m -> "16m" Nor; rp2350_geek_sdcard, waveshare_rp2350_lcd_sdcard -> "16m" Sd */ }
#[test] fn one_16m_wins_over_one_4m() { assert_eq!(resolve_board(&["rp2350_one_4m","rp2350_one_16m"]).unwrap().feature, "rp2350_one_16m"); }
#[test] fn no_board_is_an_error() { assert!(matches!(resolve_board(&[]), Err(BoardError::None))); }
#[test] fn two_boards_are_an_error_naming_both() {
    let e = resolve_board(&["pico2_4m","rp2350_geek_16m"]).unwrap_err();
    let s = e.to_string(); assert!(s.contains("pico2_4m") && s.contains("rp2350_geek_16m"));
}
#[test] fn unknown_feature_is_ignored_by_lookup() { assert!(board("pico2_4mm").is_none()); }
```

(`to_string` needs `extern crate std;` inside the test module.)

- [ ] **Step 2: Run** `cargo test -p pico2hsm-layout --target x86_64-unknown-linux-gnu` — expected: FAIL (crate does not exist / items undefined).

- [ ] **Step 3: Implement** the items above. Move every assertion of `firmware/src/storage/flash_layout.rs:166-205` into `validate` (sector alignment, region order and disjointness, keystore inside flash, `BINDING_SECTORS >= 2`, `RETRY_COUNTER_SECTORS >= 2`, MIDPOINT_RULE: no closed region or keystore contains `flash_size / 2`, slots below the store and B after A), plus: on 16 MB the keystore ends at least one `SECTOR` before `flash_size` (RP2350-E10). Call `const _: () = validate(&PROFILE_4M);` and the same for 16M. Keep the doc comments that explain MIDPOINT_RULE and E10 (move them from `flash_layout.rs`).

- [ ] **Step 4: Run** the tests — expected: PASS. Also `cargo build -p pico2hsm-layout --target thumbv8m.main-none-eabihf` succeeds (proves `no_std`).

- [ ] **Step 5: Commit** `feat(layout): pico2hsm-layout crate with the 4 MB and 16 MB profiles`.

---

### Task 2: Renderers: `memory.x` and partition-table JSON

**Files:**
- Create: `layout/src/render.rs` (`#[cfg(feature = "std")]`)
- Test: `layout/src/render.rs` tests; golden inputs `include_str!("../../boards/pt_4m.json")` etc.

**Interfaces:**
- Consumes: Task 1 `Profile`, `PROFILE_4M`, `PROFILE_16M`.
- Produces: `pub fn memory_x(p: &Profile) -> String`; `pub enum Table { Dev, Prod }`; `pub fn partition_json(p: &Profile, t: Table) -> String`; `pub fn table_file_name(p: &Profile, t: Table) -> &'static str` (`"pt_4m.json"`, `"pt_4m_prod.json"`, …).

- [ ] **Step 1: Before deleting anything, record the golden linker values** in the test (copied from today's files): 4m — `BOOT2 0x10000000/0x100, FLASH 0x10000100/0x1D5F00, BINDING 0x101D8000/0x8000, RETRY_COUNTERS 0x101E0000/0x10000, RSA_POOL 0x101F0000/0xC000, LEGACY_COUNTERS 0x101FC000/0x4000, KEYSTORE 0x10201000/0x1FF000, RAM 0x20000000/0x82000`; 16m — `FLASH 0x10000100/0x3FDF00, BINDING 0x10801000/0x8000, RETRY_COUNTERS 0x10809000/0x10000, RSA_POOL 0x10819000/0xC000, LEGACY_COUNTERS 0x10825000/0x4000, KEYSTORE 0x10829000/0x7D6000, RAM` same.

- [ ] **Step 2: Write failing tests:**

```rust
#[test] fn memory_x_regions_match_the_shipped_scripts() { /* parse MEMORY lines of memory_x(&PROFILE_4M) and _16M; assert each (name, origin, length) equals the golden table */ }
#[test] fn memory_x_keeps_the_start_block_section() { assert!(memory_x(&PROFILE_4M).contains("KEEP(*(.start_block .start_block.*))")); }
#[test] fn partition_json_is_byte_identical_to_the_committed_tables() {
    assert_eq!(partition_json(&PROFILE_4M, Table::Dev),  include_str!("../../boards/pt_4m.json"));
    assert_eq!(partition_json(&PROFILE_4M, Table::Prod), include_str!("../../boards/pt_4m_prod.json"));
    assert_eq!(partition_json(&PROFILE_16M, Table::Dev), include_str!("../../boards/pt_16m.json"));
    assert_eq!(partition_json(&PROFILE_16M, Table::Prod),include_str!("../../boards/pt_16m_prod.json"));
}
```

- [ ] **Step 3: Run** `cargo test -p pico2hsm-layout --features std --target x86_64-unknown-linux-gnu` — expected: FAIL.

- [ ] **Step 4: Implement** both renderers. JSON: hand-written string building (no serde) reproducing today's formatting exactly — 4-space indent, key order `$schema, version, unpartitioned, partitions`; per partition `name, id, start, size, families, permissions, ignored_during_arm_boot, ignored_during_riscv_boot` (the last two only on data partitions); sizes as `"<n>K"`; unpartitioned permissions dev `rw/rw/rw`, prod `rw/""/"r"`; firmware slots `fw-a` (id 0) and `fw-b` (id 1, 16 MB only — read `boards/pt_16m.json` for its exact fields, e.g. any `link` to `fw-a`), family `rp2350-arm-s`, permissions `rw/rw/rw`; data partitions family `data`, permissions `rw/""/""`; trailing newline exactly as the committed files. `memory.x`: a short header comment ("generated by pico2hsm-layout; do not edit"), the MEMORY block above, and the `SECTIONS { .boot2 : { KEEP(*(.start_block .start_block.*)) } > BOOT2 }` block from today's scripts.

- [ ] **Step 5: Run** the tests — expected: PASS.

- [ ] **Step 6: Commit** `feat(layout): render memory.x and partition tables`.

---

### Task 3: CLI

**Files:**
- Create: `layout/src/main.rs`
- Test: `layout/tests/cli.rs` (runs the built binary via `env!("CARGO_BIN_EXE_pico2hsm-layout")`)

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces (subcommands; stdout as stated, errors on stderr, exit 0 on success, 2 on usage/unknown board, 1 on `check` mismatch):
  - `profile <board>` → `4m` or `16m`
  - `slot-size <board>` → decimal bytes of one firmware slot
  - `regions <board>` → one line per store partition: `<partition> <start-hex> <size-hex>` (binding, counters, rsa-pool, spare, keystore)
  - `pt <profile> [--prod]` → JSON
  - `write [--boards-dir <dir>]` → writes the four `pt_*.json` (default `<workspace>/boards`, found via `CARGO_MANIFEST_DIR/..` at compile time)
  - `check [--boards-dir <dir>]` → compares; on mismatch prints each differing/missing file name and exits 1

- [ ] **Step 1: Write failing tests** in `layout/tests/cli.rs`: `profile pico2_4m` → `4m\n`; `profile rp2350_geek_sdcard` → `16m\n`; `profile nope` → exit 2 and stderr contains `pico2_4m`; `slot-size pico2_4m` → `1925120\n`; `regions waveshare_rp2350_lcd_16m` first line `binding 0x801000 0x8000`; `check` on a temp dir created by `write` → exit 0; then (a) append a space to `pt_4m.json` → exit 1 naming `pt_4m.json`, (b) delete `pt_16m_prod.json` → exit 1 naming it, (c) strip the final newline of `pt_16m.json` → exit 1; `check` against the real `boards/` → exit 0.

- [ ] **Step 2: Run** `cargo test -p pico2hsm-layout --features std --target x86_64-unknown-linux-gnu --test cli` — expected: FAIL.

- [ ] **Step 3: Implement** with `std::env::args` (no clap).

- [ ] **Step 4: Run** — expected: PASS.

- [ ] **Step 5: Commit** `feat(layout): CLI for scripts and CI (profile, slot-size, regions, pt, write, check)`.

---

### Task 4: Firmware uses the definition

**Files:**
- Modify: `firmware/Cargo.toml`, `firmware/build.rs:19-80`, `firmware/src/storage/flash_layout.rs` (whole file)
- Delete: `boards/pico2_4m.x`, `boards/rp2350_one_4m.x`, `boards/rp2350_one_16m.x`, `boards/rp2350_geek_16m.x`, `boards/rp2350_geek_sdcard.x`, `boards/waveshare_rp2350_lcd_16m.x`

**Interfaces:**
- Consumes: Task 1 (`resolve_board`, `BOARDS`, profiles), Task 2 (`memory_x`).
- Produces: `firmware/build.rs` emits `cargo:rustc-env=PICO2HSM_BOARD=<feature>` for every target; `flash_layout` keeps all names in Global Constraints, now computed from `pico2hsm_layout::board(env!("PICO2HSM_BOARD"))` resolved at compile time (`const BOARD: &Board = match pico2hsm_layout::board_const(env!("PICO2HSM_BOARD")) { … }` — add a `pub const fn board_const(feature: &str) -> &'static Board` to the crate that compares bytes in a loop and panics on an unknown name).

- [ ] **Step 1: Rewrite the firmware layout tests first** (`flash_layout::tests`): replace `boards_reserve_the_storage_regions` with `this_board_matches_its_profile` (each `flash_layout` constant equals the profile's value, e.g. `RETRY_COUNTER_OFFSET == BOARD.profile.region_offset("counters")`) and replace `partition_tables_match_the_maps` with `committed_tables_match_the_generator` (calls `pico2hsm_layout::render::partition_json` — enable the `std` feature for the firmware's `dev-dependencies` only). Run `cargo test --manifest-path firmware/Cargo.toml --lib --no-default-features --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519 --target x86_64-unknown-linux-gnu flash_layout` — expected: FAIL to compile (names missing).

- [ ] **Step 2: Implement `build.rs`:** collect active board features from `CARGO_FEATURE_<NAME>` env vars for every `BOARDS` row (feature names upper-cased, `-`→`_`), call `resolve_board`; on `Err(e)` `panic!("{e}")`; emit `PICO2HSM_BOARD`; then, only when `CARGO_CFG_TARGET_ARCH == "arm"`, write `memory_x(board.profile)` to `$OUT_DIR/memory.x` and keep the existing linker args (`-Tlink.x`, `-Tdefmt.x`, `--nmagic`). Remove the `boards/*.x` copy and the fallback. Keep `image_version()`.

- [ ] **Step 3: Implement `flash_layout.rs`** as re-exports (keep module docs short, pointing at `pico2hsm-layout`); `FLASH_16M = BOARD.profile.flash_size == 0x100_0000`; delete the moved asserts (now in the crate). Delete the six `boards/*.x` files.

- [ ] **Step 4: Verify:**
  - host tests for every board: `for f in pico2_4m rp2350_one_4m rp2350_one_16m rp2350_geek_16m rp2350_geek_sdcard waveshare_rp2350_lcd_16m waveshare_rp2350_lcd_sdcard; do cargo test --manifest-path firmware/Cargo.toml --lib --no-default-features --features $f,rsa,applet-piv,applet-openpgp-curve25519 --target x86_64-unknown-linux-gnu; done` — all pass;
  - release ARM build for every board succeeds, and for `pico2_4m` and `waveshare_rp2350_lcd_16m` `arm-none-eabi-size` text+data equals the pre-change build (record before Step 2) — proves identical linking;
  - `cargo build -p pico2hsm-firmware --no-default-features --target thumbv8m.main-none-eabihf` (no board) fails with a message naming no board; with `--features pico2_4m,rp2350_geek_16m` fails naming both.

- [ ] **Step 5: Commit** `refactor(layout): firmware takes its flash map from pico2hsm-layout; generated memory.x`.

---

### Task 5: Computed key cap

**Files:**
- Create: `layout/src/geometry.rs`
- Modify: `firmware/src/storage/store_v2.rs:86-160`, `firmware/src/protocol/sc_hsm/mod.rs:272-298`, `firmware/build.rs`
- Test: `layout/src/geometry.rs` tests; `firmware/src/storage/keystore_v2.rs` tests

**Interfaces:**
- Consumes: Task 1 `Profile`, `Media`, `Board`; Task 4 `PICO2HSM_BOARD`.
- Produces:
  - `pub const NOR_RING_SECTORS: u32 = 16; pub const SD_RING_SECTORS: u32 = 64; pub const SNAP_ENTRIES_PER_SECTOR: u32 = 168; pub const MAX_SNAPSHOT_SECTORS: u32 = 32; pub const MAX_DATA_SECTORS: u32 = 4096; pub const OBJECTS_PER_KEY: u32 = 3; pub const SC_HSM_KEY_REFS: u32 = 251;`
  - `pub const NON_SC_HSM_OBJECTS: u32` — the budget for PIV (`MAX_PIV_KEYS` 24 + `MAX_PIV_DATA_OBJECTS` 4 + PIN records), OpenPGP (its keys and data objects + PIN records), SC-HSM reserved records 0xFC–0xFF (4) and domain records (member capacity + sidecars + pinned peer); derive each term from the firmware constants and document it in a comment table. The firmware asserts each term against its own constant (`const _: () = assert!(pico2hsm_layout::geometry::PIV_OBJECTS >= MAX_PIV_KEYS + MAX_PIV_DATA_OBJECTS + …)`).
  - `pub const fn max_sc_hsm_keys(b: &Board) -> u32` — Sd: `SC_HSM_KEY_REFS` (with a const assert that `MAX_DATA_SECTORS - SD_RING_SECTORS - reserves` holds 251 keys + `NON_SC_HSM_OBJECTS`); Nor: `min(SC_HSM_KEY_REFS, (keystore_sectors - NOR_RING_SECTORS - snapshot_reserve - maintenance_reserve - NON_SC_HSM_OBJECTS) / OBJECTS_PER_KEY)`, where `snapshot_reserve = 2 * ceil(max_live_objects / SNAP_ENTRIES_PER_SECTOR)` and `maintenance_reserve` is what `store_v2` needs to replace one object and complete a checkpoint (read `store_v2.rs` to set it; document why).
  - `pub fn checked_cap(override_value: Option<&str>, bound: u32) -> Result<u32, CapError>`; `CapError` Display includes the bound.
  - `pub const fn key_index_capacity(cap: u32) -> u32` = `cap * 3 + 4 + allowance` (allowance 12 on 4 MB, 11 on 16 MB today: express as the free-standing-file allowance, keeping today's 400/768 when `cap` is 128/251).

- [ ] **Step 1: Write failing tests** (layout crate): `checked_cap(None, 140) == Ok(140)`; `checked_cap(Some("100"), 140) == Ok(100)`; `checked_cap(Some("0"), 140)` is `Err` and its message contains `140`; `Some("141")` → `Err`; `Some("x")` → `Err`; `max_sc_hsm_keys` of every 16M Nor board `== 251`; of SD boards `== 251`; of 4M boards `>= 100` and `<= 251` (print the value in the test output).

- [ ] **Step 2: Run** — expected: FAIL.

- [ ] **Step 3: Implement** `geometry.rs`; in `store_v2.rs` replace the local literals with the shared constants (`ring: NOR_RING_SECTORS`, `SD_RING_SECTORS`, `SNAP_PER_SECTOR` asserted equal to `SNAP_ENTRIES_PER_SECTOR`, `MAX_SNAPSHOT_SECTORS`, `MAX_DATA_SECTORS`). In `build.rs`: read `PICO2HSM_MAX_SC_HSM_KEYS` (emit `cargo:rerun-if-env-changed`), compute the bound for the resolved board, call `checked_cap`, panic on `Err`, emit `cargo:rustc-env=PICO2HSM_SC_HSM_KEY_CAP=<n>`. In `sc_hsm/mod.rs`: `MAX_SC_HSM_KEYS` parses that env at compile time (reuse `image_version::parse_u16`-style const parsing) and `MAX_KEY_INDEX = key_index_capacity(MAX_SC_HSM_KEYS)`; keep the existing `assert!(MAX_KEY_INDEX >= MAX_SC_HSM_KEYS * 3 + 4)`. Update the doc comments on both constants.

- [ ] **Step 4: Add the firmware fill test** in `keystore_v2.rs` tests: `fills_to_the_cap_on_a_keystore_of_the_profiles_size` — a `Nor` store of `PROFILE_4M.keystore_sectors()` sectors (note: `Dev::new()` uses 96 sectors; add `Dev::with_store_sectors(n)`), save `MAX_SC_HSM_KEYS` SC-HSM keys with descriptor and certificate objects plus `NON_SC_HSM_OBJECTS` other objects, reboot, all present; one more SC-HSM key fails with the cap error (6A84 path). Build it for `pico2_4m` (the 4 MB cap).

- [ ] **Step 5: Run** layout tests and firmware host tests for `pico2_4m` and `waveshare_rp2350_lcd_16m` — expected: PASS. Run `PICO2HSM_MAX_SC_HSM_KEYS=0 cargo build -p pico2hsm-firmware --no-default-features --features pico2_4m --target thumbv8m.main-none-eabihf` — expected: build fails with the bound in the message.

- [ ] **Step 6: Commit** `feat(layout): SC-HSM key cap computed from keystore size (PICO2HSM_MAX_SC_HSM_KEYS may lower it)`.

---

### Task 6: Scripts and CI use the definition

**Files:**
- Modify: `build-all.sh:~313`, `build-all-debug.sh:~146`, `.github/workflows/build.yml` (build matrix steps, lint job, build-artifacts `~:304`), `.github/workflows/release.yml:~139`

**Interfaces:**
- Consumes: Task 3 CLI (`profile`, `slot-size`, `check`).

- [ ] **Step 1:** Replace each `case "$X" in pico2_4m|rp2350_one_4m) …=4m ;; *) …=16m ;; esac` with `SIZE=$(cargo run -q -p pico2hsm-layout --features std -- profile "$X")` (keep the variable names each script uses: `PT_SIZE` in the scripts, `SIZE` in workflows), under `set -e` / an explicit `|| die`/`exit 1` so an unknown board aborts.
- [ ] **Step 2:** `build.yml` lint job: add step `Layout tables match the definition` running `cargo run -q -p pico2hsm-layout --features std -- check`, and `cargo test -p pico2hsm-layout --features std` to the host-test steps of the build job (once, `if: matrix.feature == 'pico2_4m'`).
- [ ] **Step 3:** `build.yml` build job, after the release "all applets" build: step `Image budget (${{ matrix.feature }})` — `arm-none-eabi-objcopy` (install `binutils-arm-none-eabi` via apt in that job, or use `rust-objcopy` from `cargo-binutils`; pick one and install it in the job) to a binary; compare `stat -c%s` against `slot-size`; print `image <bytes> / slot <bytes> = headroom <bytes> (<pct>%)`; exit 1 if the image exceeds the slot.
- [ ] **Step 4:** `build.yml` build job: add host-test steps for the SC-HSM-only feature set (`--features ${{ matrix.feature }},rsa`, lib tests and firmware integration tests) with `if: matrix.feature == 'pico2_4m' || matrix.feature == 'waveshare_rp2350_lcd_16m'`.
- [ ] **Step 5: Verify:** `bash -n` on both scripts; run `./build-all-debug.sh` far enough to print the table path for `pico2_4m` without flashing is not possible (it always flashes) — instead run the replaced snippet standalone for every board and an unknown board (expect `4m`/`16m` and a non-zero exit); validate both workflow YAMLs parse (`python3 -c "import yaml…"` with PyYAML from `tests/hw/.venv`, or `pip install --target` into the scratchpad); push the branch and confirm the CI run passes (Task 8 controller step if not available to the implementer).
- [ ] **Step 6: Commit** `ci(layout): scripts and CI take the board's profile from pico2hsm-layout; table check, image budget, SC-HSM-only host tests`.

---

### Task 7: Hardware test reads the committed tables; SC-HSM-only hardware readiness

**Files:**
- Modify: `tests/hw/test_22_layout.py:36-56,115-145`; any `tests/hw/test_piv_*.py` / `test_openpgp_*.py` that fail instead of skip without the applet
- Test: the modified tests themselves

**Interfaces:**
- Consumes: committed `boards/pt_4m.json`, `boards/pt_16m.json`.

- [ ] **Step 1:** Replace `STORE_4M`/`STORE_16M` with `_store_regions(big: bool) -> dict[str, tuple[int, int]]` that parses `boards/pt_16m.json` or `boards/pt_4m.json` (path relative to the repo root from `__file__`) and returns `{partition: (first_sector, last_sector)}` for `binding, counters, rsa-pool, spare, keystore`, with sectors computed from `start`/`size` (`"<n>K"` → bytes → `// 4096`). Assert in a new host-runnable test (`test_store_regions_from_tables`, marked so it runs without hardware, e.g. no `hw` marker) that the result equals today's dicts: 4M `binding (0x1D8, 0x1DF)`, `counters (0x1E0, 0x1EF)`, `rsa-pool (0x1F0, 0x1FB)`, `spare (0x1FC, 0x1FF)`, `keystore (0x201, 0x3FF)`; 16M `binding (0x801, 0x808)`, `counters (0x809, 0x818)`, `rsa-pool (0x819, 0x824)`, `spare (0x825, 0x828)`, `keystore (0x829, 0xFFE)`.
- [ ] **Step 2:** Run `tests/hw/.venv/bin/python -m pytest tests/hw/test_22_layout.py -k from_tables -q -p no:cacheprovider` — expected: PASS (and the hardware tests in the file still collect).
- [ ] **Step 3:** Grep PIV/OpenPGP tests for SELECT handling: each must `pytest.skip("PIV applet not present in this build")`-style when SELECT returns `6A82`. Add a shared helper in `tests/hw/helpers/` if more than two files need it. (Hardware confirmation happens in Task 9.)
- [ ] **Step 4: Commit** `test(hw): layout test reads the committed tables; applet tests skip when the applet is absent`.

---

### Task 8: Documentation and changelog

**Files:**
- Modify: `docs/FLASH_LAYOUT_2_0.md` (§2 source of truth, §3 key cap), `docs/BUILD_CONFIGURATIONS.md` (key cap override, layout CLI), `CLAUDE.md` (where the layout lives; `boards/*.x` gone), `README.md` (board table key counts), `CHANGELOG.md` (`## [Unreleased]`: Added — layout profiles, computed key cap with the measured 4 MB value, `PICO2HSM_MAX_SC_HSM_KEYS`, CI image budget, SC-HSM-only CI; Changed — `boards/*.x` removed; build fails without exactly one board)

- [ ] **Step 1:** Update the docs; quote the computed 4 MB cap from Task 5's test output.
- [ ] **Step 2:** `grep -rn "boards/.*\.x\b\|128 keys\|128 SC-HSM" docs README.md CLAUDE.md` returns only intended, updated mentions.
- [ ] **Step 3: Commit** `docs(layout): one definition for the flash map; computed key cap`.

---

### Task 9 (controller): Hardware verification and release

Done by the controlling session, not a subagent (needs the boards, the signing key and the owner's BOOT presses).

- [ ] Development Pico 2 (probe E664A836A3718537, reader DCD7948F6983C9CF): `PROBE_SERIAL=E664A836A3718537 EXTRA_FEATURES=debug ./build-all-debug.sh pico2_4m` over the existing store; `pico2hsm-tool store status` up with its keys; full suite (`PICO2HSM_READER=DCD7948F6983C9CF …`) passes.
- [ ] Same Pico 2 with the SC-HSM-only build (`--features pico2_4m,rsa,debug`): full suite passes, PIV/OpenPGP tests skip.
- [ ] Merge the PR after CI is green (owner authorization for this PR).
- [ ] Release 2.1.0: version bump, CHANGELOG section, tag, release workflow; sign the CI ELFs with bootkey0; install on the RP2350-One and the LCD board (owner presses BOOT); `picotool partition info` unchanged; keystore opens; release-build suite passes on both.
