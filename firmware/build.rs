//! Build script for pico2hsm-firmware.
//!
//! Resolves the one active board feature through `pico2hsm-layout` (the
//! build fails naming the active boards if there is none or several),
//! passes it to the crate as `PICO2HSM_BOARD` (and its SC-HSM key cap as
//! `PICO2HSM_SC_HSM_KEY_CAP`), and, for ARM builds,
//! renders the board's `memory.x` into `$OUT_DIR` for `cortex-m-rt`.
//!
//! ## How cortex-m-rt linker scripts work
//!
//! `cortex-m-rt` ships a `link.x` that defines all section layout. It
//! includes `memory.x` via `INCLUDE memory.x`. The user crate must provide
//! `memory.x` somewhere in the linker search path: we write it to
//! `$OUT_DIR` and add that to the search path with
//! `cargo:rustc-link-search`.
//!
//! ARM-specific linker args are only emitted when building for ARM so that
//! `cargo test --target x86_64` is unaffected.

use std::fs;
use std::path::PathBuf;

fn main() {
    image_version();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../layout/src");

    // Board features arrive as CARGO_FEATURE_<NAME> (upper case, `-` → `_`).
    let active: Vec<&str> = pico2hsm_layout::BOARDS
        .iter()
        .map(|b| b.feature)
        .filter(|f| {
            let var = format!("CARGO_FEATURE_{}", f.to_uppercase().replace('-', "_"));
            std::env::var_os(var).is_some()
        })
        .collect();
    let board = pico2hsm_layout::resolve_board(&active).unwrap_or_else(|e| panic!("{e}"));
    println!("cargo:rustc-env=PICO2HSM_BOARD={}", board.feature);
    key_cap(board);

    // Only write memory.x and emit linker arguments for bare-metal ARM.
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target != "arm" {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let dst = PathBuf::from(&out_dir).join("memory.x");
    fs::write(&dst, pico2hsm_layout::render::memory_x(board.profile))
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", dst.display()));

    // Add $OUT_DIR to the linker search path so `memory.x` is found by link.x.
    println!("cargo:rustc-link-search={out_dir}");
    // Use cortex-m-rt's link.x as the top-level linker script.
    // cortex-m-rt's build.rs adds its OUT_DIR to the search path so the linker
    // can find link.x, but it does NOT emit -Tlink.x — that is the user crate's
    // responsibility. link.x then does `INCLUDE memory.x` to pick up our layout.
    println!("cargo:rustc-link-arg=-Tlink.x");
    // defmt.x defines the .defmt section header that probe-rs/defmt need to
    // decode RTT log messages. It must be linked after link.x.
    println!("cargo:rustc-link-arg=-Tdefmt.x");
    // --nmagic: disable page-aligned ELF segments (required for bare-metal flash).
    println!("cargo:rustc-link-arg=--nmagic");
}

/// The SC-HSM key cap: the board's (computed from its keystore size by
/// `pico2hsm_layout::geometry::max_sc_hsm_keys`), or a lower
/// `PICO2HSM_MAX_SC_HSM_KEYS`.  The build fails, naming the board's cap,
/// on 0, a larger value or junk.  Passed on as `PICO2HSM_SC_HSM_KEY_CAP`.
fn key_cap(board: &pico2hsm_layout::Board) {
    use pico2hsm_layout::geometry::{checked_cap, max_sc_hsm_keys};
    println!("cargo:rerun-if-env-changed=PICO2HSM_MAX_SC_HSM_KEYS");
    let over = std::env::var("PICO2HSM_MAX_SC_HSM_KEYS").ok();
    let cap = checked_cap(over.as_deref(), max_sc_hsm_keys(board))
        .unwrap_or_else(|e| panic!("{} ({}): {e}", board.feature, board.profile.name));
    println!("cargo:rustc-env=PICO2HSM_SC_HSM_KEY_CAP={cap}");
}

/// IMAGE_DEF version (the bootrom boots the higher of two A/B images):
/// major from the crate version, minor = minor * 256 + patch.
/// PICO2HSM_IMAGE_VERSION ("2.0.1") overrides it, for A/B tests.  Host
/// builds need it too (`image_def` is in the library).
fn image_version() {
    let version = std::env::var("PICO2HSM_IMAGE_VERSION")
        .unwrap_or_else(|_| std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION"));
    let parts: Vec<u32> = version
        .split(['.', '-', '+'])
        .take(3)
        .map(|p| {
            p.parse()
                .unwrap_or_else(|_| panic!("bad image version {version}"))
        })
        .collect();
    let (major, minor, patch) = (parts[0], parts[1], parts.get(2).copied().unwrap_or(0));
    assert!(
        major <= 0xFFFF && minor <= 0xFF && patch <= 0xFF,
        "image version {version}"
    );
    println!("cargo:rustc-env=PICO2HSM_IMAGE_MAJOR={major}");
    println!(
        "cargo:rustc-env=PICO2HSM_IMAGE_MINOR={}",
        minor * 256 + patch
    );
    println!("cargo:rerun-if-env-changed=PICO2HSM_IMAGE_VERSION");
    println!("cargo:rerun-if-env-changed=PICO2HSM_TEST_NO_BUY");
    println!("cargo:rerun-if-env-changed=PICO2HSM_TBYB");
}
