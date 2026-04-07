//! Build script for pico2hsm-firmware.
//!
//! Selects the correct memory layout based on the active board feature flag
//! and writes `memory.x` to `$OUT_DIR` for `cortex-m-rt` to include.
//!
//! ## How cortex-m-rt linker scripts work
//!
//! `cortex-m-rt` ships a `link.x` that defines all section layout. It
//! includes `memory.x` via `INCLUDE memory.x` (line 23 of link.x). The user
//! crate must provide `memory.x` somewhere in the linker search path.
//! The idiomatic way is to write it to `$OUT_DIR` and add that to the search
//! path with `cargo:rustc-link-search`.
//!
//! ARM-specific linker args are only emitted when building for ARM so that
//! `cargo test --target x86_64` is unaffected.

use std::fs;
use std::path::PathBuf;

fn main() {
    // Only emit ARM linker arguments when targeting bare-metal ARM.
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target != "arm" {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Select board linker script based on active feature flag.
    let board = if cfg!(feature = "rp2350_one_4m") {
        "rp2350_one_4m"
    } else if cfg!(feature = "rp2350_one_16m") {
        "rp2350_one_16m"
    } else if cfg!(feature = "rp2350_geek_16m") {
        "rp2350_geek_16m"
    } else if cfg!(feature = "rp2350_geek_sdcard") || cfg!(feature = "rp2350_geek_sdcard_dual") {
        "rp2350_geek_sdcard"
    } else if cfg!(feature = "rp2354_embedded") {
        "rp2354_embedded"
    } else if cfg!(feature = "pico2_4m") {
        "pico2_4m"
    } else if cfg!(feature = "waveshare_rp2350_lcd_16m") || cfg!(feature = "waveshare_rp2350_lcd_sdcard_dual") {
        "waveshare_rp2350_lcd_16m"
    } else {
        // Fallback — should not happen with workspace defaults.
        "rp2350_one_4m"
    };

    // Locate the boards/ directory (sibling of the firmware/ crate).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR set by cargo");
    let boards_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("firmware/ has a parent")
        .join("boards");

    let src = boards_dir.join(format!("{board}.x"));

    // Write the selected layout to $OUT_DIR/memory.x so cortex-m-rt can find
    // it via `INCLUDE memory.x`.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let dst = PathBuf::from(&out_dir).join("memory.x");
    fs::copy(&src, &dst)
        .unwrap_or_else(|e| panic!("failed to copy {}: {e}", src.display()));

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

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", boards_dir.display());
}
