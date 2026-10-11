//! Domains — cluster plan V3 (`docs/CLUSTER_PLAN_V3.md`), phase P1.
//!
//! A domain is the set of devices sharing one DKEK.  This module holds the
//! pieces every later phase builds on:
//!
//! - [`key`]: the deterministic domain signing key derived from the DKEK
//!   (§4.1) and the `domain_id` that names the domain;
//! - [`member`]: member certificates and the on-device member list
//!   (§4.3, §4.4), which replaces the single peer slot 0xFC;
//! - [`object_id`]: global object IDs and their per-object sidecars
//!   (§6.2, §6.5);
//! - [`records`]: where all of this lives in the keystore.
//!
//! The Lamport counter that numbers local changes (§6.1) lives in the
//! retry-counter log (`storage::retry_counter::advance_lamport`).
//!
//! # Keystore namespace
//! Domain records are keystore objects with applet byte
//! [`APPLET_DOMAIN`] (`AppletId::Domain`, 0x10).  SC-HSM INITIALIZE wipes
//! them together with SC-HSM's keys (the DKEK they depend on goes too);
//! PIV and OpenPGP resets never touch them.  See [`records`] for the
//! `KeyId` layout.

pub mod key;
pub mod member;
pub mod object_id;
pub mod records;

/// Applet byte (bits 23–16 of a `KeyId`) of every domain record.
pub const APPLET_DOMAIN: u8 = pico2hsm_core::key::AppletId::Domain as u8;
