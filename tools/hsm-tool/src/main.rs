//! hsm-tool — Command-line tool for managing pico2hsm devices.
//!
//! Provides host-side operations for the pico2hsm HSM:
//! - Device initialization and PIN management
//! - Key generation, import, and export
//! - Certificate management
//! - DKEK share exchange
//! - Device diagnostics and status
//!
//! # Usage (to be implemented)
//! ```text
//! hsm-tool init --so-pin 12345678
//! hsm-tool generate-key --type ec-p256 --label "signing-key-1"
//! hsm-tool list-keys
//! hsm-tool export-key --id 1 --out key-backup.bin
//! hsm-tool dkek-share import --file share1.bin
//! hsm-tool status
//! ```
//!
//! # TODO (tooling specialist agent)
//! - Add CLI argument parsing (clap or argh)
//! - Implement PCSC/USB device discovery
//! - Implement APDU send/receive via USB CCID
//! - Implement all subcommands

fn main() {
    // TODO: implement — parse CLI args and dispatch to subcommands
    eprintln!("hsm-tool: not yet implemented");
    std::process::exit(1);
}
