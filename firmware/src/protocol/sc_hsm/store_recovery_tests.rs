//! Host tests: the SC-HSM SO-PIN in the Storage V2 binding block (§8.1,
//! R9, R10) and store recovery (§9.3: STORE STATUS, OPEN DEGRADED, ACCEPT
//! STORE), APDU in, the real V2 key store underneath.

use super::*;
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
use crate::storage::keystore_v2::tests::{Dev, Ks};
use crate::storage::keystore_v2::StoreStatus;
use crate::storage::KeyStore;

const USER_PIN: &[u8] = b"648219";
const SO_PIN: &[u8] = b"57621880";
const OTHER_SO: &[u8] = b"11223344";

fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 300> {
    let mut v = heapless::Vec::new();
    v.extend_from_slice(&[cla, ins, p1, p2, data.len() as u8])
        .unwrap();
    v.extend_from_slice(data).unwrap();
    v
}

fn sw(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
}

fn run(hsm: &mut ScHsm, ks: &mut Ks, ins: u8, p1: u8, p2: u8, data: &[u8]) -> u16 {
    sw(&hsm.process_apdu_with_store(&apdu(0x80, ins, p1, p2, data), ks))
}

fn initialize(hsm: &mut ScHsm, ks: &mut Ks, so_pin: &[u8]) -> u16 {
    let mut d: heapless::Vec<u8, 64> = heapless::Vec::new();
    d.extend_from_slice(&[0x81, USER_PIN.len() as u8]).unwrap();
    d.extend_from_slice(USER_PIN).unwrap();
    d.extend_from_slice(&[0x82, so_pin.len() as u8]).unwrap();
    d.extend_from_slice(so_pin).unwrap();
    run(hsm, ks, 0x50, 0, 0, &d)
}

fn verify_so(hsm: &mut ScHsm, ks: &mut Ks, pin: &[u8]) -> u16 {
    run(hsm, ks, 0x20, 0, 0x88, pin)
}

/// Boot: the key store, then the applet's credentials from it.
fn boot(d: &Dev) -> (ScHsm, Ks) {
    let (mut ks, _) = d.boot();
    let mut hsm = ScHsm::new();
    ScHsm::load_pin_state_from_store(&mut hsm.state, &mut ks);
    (hsm, ks)
}

fn initialized() -> (ScHsm, Ks) {
    let (mut hsm, mut ks) = boot(&Dev::new());
    assert_eq!(initialize(&mut hsm, &mut ks, SO_PIN), SW_OK);
    (hsm, ks)
}

fn pin_record(ks: &mut Ks) -> heapless::Vec<u8, 160> {
    let obj = ks.fetch_key(ScHsm::sc_hsm_pin_key_id()).unwrap().unwrap();
    let mut v = heapless::Vec::new();
    v.extend_from_slice(&obj.private_key).unwrap();
    v
}

#[test]
fn initialize_puts_the_so_pin_in_the_binding_not_the_record() {
    let (_hsm, mut ks) = initialized();
    assert!(matches!(ks.so_pin_home(), SoPinHome::Binding(Some(_))));
    let rec = pin_record(&mut ks);
    assert!(
        rec[49..97].iter().all(|&b| b == 0),
        "no SO-PIN in the record"
    );
    assert!(rec[0..32].iter().any(|&b| b != 0), "the user PIN is there");
    // After a reboot the SO-PIN still verifies, and a wrong one is charged.
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert_eq!(verify_so(&mut hsm, &mut ks, OTHER_SO), 0x63C4);
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
}

/// A rolled-back store is refused; the user PIN is out of reach, the
/// SO-PIN is not (recovery needs it).
#[test]
fn a_refused_store_still_verifies_the_so_pin() {
    let (mut hsm, mut ks) = initialized();
    let old = Dev::of(&mut ks).store;
    // A journal commit after the copy: change the user PIN.
    let mut d: heapless::Vec<u8, 32> = heapless::Vec::new();
    d.extend_from_slice(USER_PIN).unwrap();
    d.extend_from_slice(b"135790").unwrap();
    assert_eq!(run(&mut hsm, &mut ks, 0x24, 0, 0x81, &d), SW_OK);
    let mut dev = Dev::of(&mut ks);
    dev.store = old;
    let (mut hsm, mut ks) = boot(&dev);
    assert!(matches!(ks.status(), StoreStatus::Refused(_)));
    assert_eq!(
        run(&mut hsm, &mut ks, 0x20, 0, 0x81, USER_PIN),
        pico2hsm_core::apdu::SW_AUTH_BLOCKED
    );
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert!(hsm.state.so_pin_verified);
}

#[test]
fn change_so_pin_goes_to_the_binding() {
    let (mut hsm, mut ks) = initialized();
    let mut d: heapless::Vec<u8, 32> = heapless::Vec::new();
    d.extend_from_slice(SO_PIN).unwrap();
    d.extend_from_slice(OTHER_SO).unwrap();
    assert_eq!(run(&mut hsm, &mut ks, 0x24, 0, 0x88, &d), SW_OK);
    let rec = pin_record(&mut ks);
    assert!(rec[49..97].iter().all(|&b| b == 0));
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), 0x63C4);
    assert_eq!(verify_so(&mut hsm, &mut ks, OTHER_SO), SW_OK);
}

/// FORMAT STORE carries the SO-PIN forward (R9): the empty store's
/// INITIALIZE needs it (R10's "uninitialised, SO-PIN set").
#[test]
fn after_format_store_initialize_needs_the_carried_so_pin() {
    let (mut hsm, mut ks) = initialized();
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(
        run(&mut hsm, &mut ks, 0x54, 0x4E, 0, b"FORMAT-STORE-V2"),
        SW_OK
    );
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert!(!hsm.state.initialized);
    assert_eq!(
        initialize(&mut hsm, &mut ks, OTHER_SO),
        pico2hsm_core::apdu::SW_SECURITY_STATUS
    );
    assert_eq!(initialize(&mut hsm, &mut ks, SO_PIN), SW_OK);
}

/// A fresh device has no SO-PIN: INITIALIZE takes any.
#[test]
fn a_fresh_store_initializes_without_an_so_pin() {
    let (mut hsm, mut ks) = boot(&Dev::new());
    assert!(hsm.state.so_pin_hash.is_none());
    assert_eq!(initialize(&mut hsm, &mut ks, OTHER_SO), SW_OK);
}

/// A PIN record from before the binding held the SO-PIN moves it there.
#[test]
fn an_old_record_moves_its_so_pin_into_the_binding() {
    let (hsm, mut ks) = initialized();
    ks.set_binding_so_pin(None).unwrap();
    let mut obj = KeyObject::new(
        KmKeyType::Generic,
        ScHsm::sc_hsm_pin_key_id().0,
        AppletId::ScHsm,
        AlgorithmId::AesGcm,
    );
    let _ = obj
        .private_key
        .extend_from_slice(&ScHsm::pin_record_with(&hsm.state, true));
    ks.save_key(&obj).unwrap();
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert!(matches!(ks.so_pin_home(), SoPinHome::Binding(Some(_))));
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
}

fn status(hsm: &mut ScHsm, ks: &mut Ks) -> (u8, u8, u64, u32, u32) {
    let r = hsm.process_apdu_with_store(&apdu(0x80, 0x54, 0x52, 0, &[]), ks);
    assert_eq!(sw(&r), SW_OK);
    let b = &r[..r.len() - 2];
    (
        b[0],
        b[1],
        u64::from_be_bytes(b[2..10].try_into().unwrap()),
        u32::from_be_bytes(b[10..14].try_into().unwrap()),
        u32::from_be_bytes(b[14..18].try_into().unwrap()),
    )
}

/// An initialised device whose store was rolled back by `n` commits (a
/// lost SD tail, a restored image): refused at boot.
fn rolled_back(n: usize) -> (ScHsm, Ks) {
    let (mut hsm, mut ks) = initialized();
    ks.save_key(&crate::storage::keystore_v2::tests::key(0x0000_0007, 7))
        .unwrap();
    let old = Dev::of(&mut ks).store;
    for i in 0..n {
        ks.save_key(&crate::storage::keystore_v2::tests::key(
            0x0000_0010 + i as u32,
            9,
        ))
        .unwrap();
    }
    let mut d = Dev::of(&mut ks);
    d.store = old;
    let _ = hsm;
    boot(&d)
}

fn open_degraded(hsm: &mut ScHsm, ks: &mut Ks) -> u16 {
    run(hsm, ks, 0x54, 0x4F, 0, b"OPEN-DEGRADED")
}

#[test]
fn store_status_of_an_up_store() {
    let (mut hsm, mut ks) = initialized();
    assert_eq!(status(&mut hsm, &mut ks), (0, 0, 0, 0, 0));
}

#[test]
fn a_refused_store_reports_what_it_lost() {
    let (mut hsm, mut ks) = rolled_back(3);
    assert_eq!(status(&mut hsm, &mut ks), (2, 4, 3, 0, 0));
}

#[test]
fn open_degraded_needs_the_so_pin_and_a_refused_store() {
    let (mut hsm, mut ks) = initialized();
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(
        open_degraded(&mut hsm, &mut ks),
        pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED,
        "the store is up"
    );
    let (mut hsm, mut ks) = rolled_back(1);
    assert_eq!(
        open_degraded(&mut hsm, &mut ks),
        pico2hsm_core::apdu::SW_SECURITY_STATUS
    );
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(
        run(&mut hsm, &mut ks, 0x54, 0x4F, 0, b"OPEN"),
        pico2hsm_core::apdu::SW_WRONG_DATA
    );
    assert_eq!(status(&mut hsm, &mut ks).3, 0, "nothing counted yet");
}

/// OPEN DEGRADED: the verifiable state, read-only, until reboot.
#[test]
fn open_degraded_mounts_read_only_until_reboot() {
    let (mut hsm, mut ks) = rolled_back(2);
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(open_degraded(&mut hsm, &mut ks), SW_OK);
    assert_eq!(status(&mut hsm, &mut ks), (1, 4, 2, 1, 0));
    // The keys of the accepted state are there; the lost ones are not.
    assert_eq!(crate::storage::keystore_v2::tests::tag(&mut ks, 7), Some(7));
    assert_eq!(crate::storage::keystore_v2::tests::tag(&mut ks, 0x10), None);
    // The applets reload: the user PIN works again (verifying the SO-PIN
    // while it was locked out left its counter alone); nothing can change.
    let mut hsm = ScHsm::new();
    ScHsm::load_pin_state_from_store(&mut hsm.state, &mut ks);
    assert_eq!(run(&mut hsm, &mut ks, 0x20, 0, 0x81, USER_PIN), SW_OK);
    assert!(ks
        .save_key(&crate::storage::keystore_v2::tests::key(0x20, 1))
        .is_err());
    // A reboot refuses the store again; the count stays.
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert_eq!(status(&mut hsm, &mut ks), (2, 4, 2, 1, 0));
}

fn accept(hsm: &mut ScHsm, ks: &mut Ks, lost: u64) -> u16 {
    let mut d: heapless::Vec<u8, 32> = heapless::Vec::new();
    d.extend_from_slice(b"ACCEPT-STORE-V2").unwrap();
    d.extend_from_slice(&lost.to_be_bytes()).unwrap();
    run(hsm, ks, 0x54, 0x53, 0, &d)
}

/// The recovery of §9.3 end to end: refused → OPEN DEGRADED → ACCEPT
/// STORE with the count shown → a read-write store, counted.
#[test]
fn accept_store_recovers_a_rolled_back_store() {
    let (mut hsm, mut ks) = rolled_back(2);
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(
        accept(&mut hsm, &mut ks, 2),
        pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED,
        "OPEN DEGRADED first"
    );
    assert_eq!(open_degraded(&mut hsm, &mut ks), SW_OK);
    assert_eq!(
        accept(&mut hsm, &mut ks, 1),
        pico2hsm_core::apdu::SW_WRONG_DATA,
        "not the count STORE STATUS showed"
    );
    assert_eq!(accept(&mut hsm, &mut ks, 2), SW_OK);
    assert_eq!(status(&mut hsm, &mut ks), (0, 0, 0, 1, 1));
    // A reboot finds it up; the applet works and writes again.
    let (mut hsm, mut ks) = boot(&Dev::of(&mut ks));
    assert_eq!(status(&mut hsm, &mut ks), (0, 0, 0, 1, 1));
    assert_eq!(run(&mut hsm, &mut ks, 0x20, 0, 0x81, USER_PIN), SW_OK);
    let mut d: heapless::Vec<u8, 32> = heapless::Vec::new();
    d.extend_from_slice(USER_PIN).unwrap();
    d.extend_from_slice(b"135790").unwrap();
    assert_eq!(run(&mut hsm, &mut ks, 0x24, 0, 0x81, &d), SW_OK);
    assert_eq!(crate::storage::keystore_v2::tests::tag(&mut ks, 7), Some(7));
}

#[test]
fn accept_store_needs_the_so_pin() {
    let (mut hsm, mut ks) = rolled_back(1);
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(open_degraded(&mut hsm, &mut ks), SW_OK);
    // The reload after OPEN DEGRADED starts a fresh applet state.
    let mut hsm = ScHsm::new();
    ScHsm::load_pin_state_from_store(&mut hsm.state, &mut ks);
    assert_eq!(
        accept(&mut hsm, &mut ks, 1),
        pico2hsm_core::apdu::SW_SECURITY_STATUS
    );
    assert_eq!(verify_so(&mut hsm, &mut ks, SO_PIN), SW_OK);
    assert_eq!(accept(&mut hsm, &mut ks, 1), SW_OK);
}
