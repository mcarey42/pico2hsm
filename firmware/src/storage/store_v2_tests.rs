//! Host tests of the Storage V2 engine (docs/STORAGE_V2.md §13): fault
//! injection at every flash write, adversarial images, exhaustion.

extern crate std;

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use pico2hsm_core::error::StorageError;
use zeroize::Zeroizing;

use super::store_v2::*;
use crate::storage::retry_counter::Anchor;

const SS: usize = SECTOR as usize;

// ─── Simulated media ─────────────────────────────────────────────────────────

/// NOR flash or an SD card, with a power cut after `budget` programmed
/// bytes (or erases).  A cut leaves the interrupted program half done (NOR:
/// the first bytes programmed; SD: the block either fully old or new).
#[derive(Clone)]
struct Sim {
    media: Media,
    mem: Vec<u8>,
    budget: Option<usize>,
    dead: bool,
    /// Offsets whose program silently does nothing (a worn cell, R3).
    stuck: Vec<u32>,
    programs: usize,
    erases: usize,
    /// Budget units consumed (bytes programmed + erases): what a cut
    /// position counts.
    written: usize,
}

impl Sim {
    fn new(media: Media, sectors: usize) -> Self {
        Sim {
            media,
            mem: vec![0xFF; sectors * SS],
            budget: None,
            dead: false,
            stuck: Vec::new(),
            programs: 0,
            erases: 0,
            written: 0,
        }
    }
    fn reboot(&self) -> Self {
        Sim {
            budget: None,
            dead: false,
            stuck: Vec::new(),
            ..self.clone()
        }
    }
    fn tick(&mut self, n: usize) -> Result<usize, StorageError> {
        if self.dead {
            return Err(StorageError::WriteError);
        }
        self.written += n;
        match self.budget.as_mut() {
            None => Ok(n),
            Some(b) if *b >= n => {
                *b -= n;
                Ok(n)
            }
            Some(b) => {
                let done = *b;
                *b = 0;
                self.dead = true;
                Ok(done)
            }
        }
    }
}

impl StoreFlash for Sim {
    fn media(&self) -> Media {
        self.media
    }
    fn sectors(&self) -> u32 {
        (self.mem.len() / SS) as u32
    }
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let o = offset as usize;
        buf.copy_from_slice(&self.mem[o..o + buf.len()]);
        Ok(())
    }
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        self.programs += 1;
        if self.stuck.contains(&offset) {
            return Ok(());
        }
        match self.media {
            Media::Nor => {
                let done = self.tick(data.len())?;
                for (i, &d) in data[..done].iter().enumerate() {
                    self.mem[offset as usize + i] &= d;
                }
                if done < data.len() {
                    return Err(StorageError::WriteError);
                }
            }
            Media::Sd => {
                assert_eq!(offset % 512, 0, "SD writes whole blocks");
                assert_eq!(data.len() % 512, 0, "SD writes whole blocks");
                for (b, chunk) in data.chunks(512).enumerate() {
                    if self.tick(512)? < 512 {
                        return Err(StorageError::WriteError);
                    }
                    let o = offset as usize + b * 512;
                    self.mem[o..o + 512].copy_from_slice(chunk);
                }
            }
        }
        Ok(())
    }
    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        self.erases += 1;
        if self.tick(1)? < 1 {
            // Cut mid-erase: half the sector back to 0xFF.
            let s = sector as usize * SS;
            self.mem[s..s + SS / 2].fill(0xFF);
            return Err(StorageError::EraseError);
        }
        let s = sector as usize * SS;
        self.mem[s..s + SS].fill(0xFF);
        Ok(())
    }
}

/// The counter log's anchor, in RAM.
#[derive(Clone, Default)]
struct Mem {
    anchor: Option<Anchor>,
    fail_anchor: bool,
}

impl Env for Mem {
    fn anchor(&mut self) -> Result<Option<Anchor>, StorageError> {
        Ok(self.anchor)
    }
    fn put_anchor(&mut self, a: Anchor) -> Result<(), StorageError> {
        if self.fail_anchor {
            return Err(StorageError::WriteError);
        }
        if let Some(old) = self.anchor {
            if old.format_gen == a.format_gen && a.head_seq < old.head_seq {
                return Err(StorageError::IntegrityFailure);
            }
        }
        self.anchor = Some(a);
        Ok(())
    }
}

const SMK: [u8; 32] = [0x5A; 32];
const SID: [u8; 16] = [0x11; 16];

fn info(gen: [u32; 3]) -> MountInfo {
    info_for(SID, 1, gen)
}

fn info_for(sid: [u8; 16], format_gen: u32, gen: [u32; 3]) -> MountInfo {
    MountInfo {
        store_id: sid,
        format_gen,
        k_idx: derive_k_idx(&SMK, &sid, &[0x22; 32]),
        group_gen: gen,
    }
}

/// A store formatted and mounted on fresh media.
fn fresh(media: Media, sectors: usize) -> (Store<Sim>, Mem) {
    let mut st = Store::new(Sim::new(media, sectors));
    let mut env = Mem::default();
    assert!(st.is_blank().unwrap());
    st.format(info([0; 3]), &mut env).unwrap();
    st.mount(info([0; 3]), &mut env, false).unwrap();
    (st, env)
}

fn remount(st: &mut Store<Sim>, env: &mut Mem, gen: [u32; 3]) -> Result<Store<Sim>, Refusal> {
    let mut again = Store::new(st.flash_mut().reboot());
    again.mount(info(gen), env, false).map(|_| again)
}

/// The "sealed blob": key ID, seq and a payload tag, so a stale or moved
/// object is visible.
fn sealer(key_id: u32, tag: u8) -> impl FnMut(u64, &mut [u8]) -> Result<usize, StorageError> {
    move |seq, out| {
        let len = 64 + (tag as usize % 7) * 100;
        out[..4].copy_from_slice(&key_id.to_le_bytes());
        out[4..12].copy_from_slice(&seq.to_le_bytes());
        out[12..len].fill(tag);
        Ok(len)
    }
}

fn put(st: &mut Store<Sim>, env: &mut Mem, key_id: u32, tag: u8) -> Result<(), StorageError> {
    let meta = Meta {
        key_type: tag,
        algo: 0x13,
        flags: 0,
    };
    st.put(env, key_id, meta, &mut sealer(key_id, tag))
}

/// The tag stored for `key_id`, checking the blob matches its index entry.
fn get(st: &Store<Sim>, key_id: u32) -> Option<u8> {
    let mut out = vec![0u8; MAX_OBJECT_BLOB];
    match st.fetch_into(key_id, &mut out).unwrap() {
        Fetched::Missing => None,
        Fetched::Found { meta, seq, len } => {
            assert_eq!(u32::from_le_bytes(out[..4].try_into().unwrap()), key_id);
            assert_eq!(u64::from_le_bytes(out[4..12].try_into().unwrap()), seq);
            let tag = out[12];
            assert_eq!(meta.key_type, tag);
            assert_eq!(len, 64 + (tag as usize % 7) * 100);
            Some(tag)
        }
    }
}

fn state(st: &Store<Sim>) -> BTreeMap<u32, u8> {
    let mut ids = Vec::new();
    st.for_each(&mut |e| ids.push(e.key_id)).unwrap();
    let mut m = BTreeMap::new();
    for id in ids {
        assert!(
            m.insert(id, get(st, id).unwrap()).is_none(),
            "listed twice: {id:x}"
        );
    }
    m
}

// ─── Basics ──────────────────────────────────────────────────────────────────

#[test]
fn put_get_delete_survive_remount() {
    for media in [Media::Nor, Media::Sd] {
        let (mut st, mut env) = fresh(media, 96);
        put(&mut st, &mut env, 0x0000_0001, 1).unwrap();
        put(&mut st, &mut env, 0x0001_0005, 2).unwrap();
        put(&mut st, &mut env, 0x0000_0001, 3).unwrap();
        assert_eq!(get(&st, 1), Some(3));
        st.delete(&mut env, 0x0001_0005).unwrap();
        assert_eq!(get(&st, 0x0001_0005), None);
        let again = remount(&mut st, &mut env, [0; 3]).unwrap();
        assert_eq!(state(&again), BTreeMap::from([(1, 3)]));
    }
}

#[test]
fn checkpoints_and_ring_wraps_keep_the_state() {
    for media in [Media::Nor, Media::Sd] {
        let (mut st, mut env) = fresh(media, 160);
        let mut model = BTreeMap::new();
        // Thousands of records: several checkpoints and laps of the ring.
        for i in 0..3000u32 {
            let k = (i * 7) % 23;
            if i % 5 == 4 {
                st.delete(&mut env, k).unwrap();
                model.remove(&k);
            } else {
                let tag = (i % 200) as u8 + 1;
                put(&mut st, &mut env, k, tag).unwrap();
                model.insert(k, tag);
            }
            if i % 499 == 0 {
                st = remount(&mut st, &mut env, [0; 3]).unwrap();
            }
        }
        assert_eq!(state(&st), model);
        let again = remount(&mut st, &mut env, [0; 3]).unwrap();
        assert_eq!(state(&again), model, "{media:?}");
    }
}

#[test]
fn a_full_store_refuses_new_keys_but_deletes_updates_and_recovers() {
    let (mut st, mut env) = fresh(Media::Nor, 40);
    let mut n = 0u32;
    loop {
        match put(&mut st, &mut env, n, 9) {
            Ok(()) => n += 1,
            Err(StorageError::KeystoreFull) => break,
            Err(e) => panic!("{e:?}"),
        }
        assert!(n < 100);
    }
    assert!(n > 10, "only {n} fit");
    // An update of an existing key still works (CHANGE PIN on a full store).
    put(&mut st, &mut env, 0, 10).unwrap();
    // Deletes, checkpoints and ring wraps still work.
    for k in 0..n {
        st.delete(&mut env, k).unwrap();
    }
    for i in 0..600u32 {
        put(&mut st, &mut env, i % 5, (i % 100) as u8 + 1).unwrap();
    }
    let again = remount(&mut st, &mut env, [0; 3]).unwrap();
    assert_eq!(state(&again).len(), 5);
}

#[test]
fn many_keys_span_several_snapshot_sectors() {
    let (mut st, mut env) = fresh(Media::Nor, 600);
    let mut model = BTreeMap::new();
    for k in 0..450u32 {
        let id = k.wrapping_mul(0x9E37_79B1) & 0x00FF_FFFF;
        put(&mut st, &mut env, id, (k % 250) as u8 + 1).unwrap();
        model.insert(id, (k % 250) as u8 + 1);
    }
    st.checkpoint(&mut env).unwrap();
    let again = remount(&mut st, &mut env, [0; 3]).unwrap();
    assert_eq!(state(&again), model);
}

// ─── Power cuts ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Op {
    Put(u32, u8),
    Del(u32),
    Checkpoint,
}

fn apply(st: &mut Store<Sim>, env: &mut Mem, op: Op) -> Result<(), StorageError> {
    match op {
        Op::Put(k, t) => put(st, env, k, t),
        Op::Del(k) => st.delete(env, k),
        Op::Checkpoint => st.checkpoint(env),
    }
}

fn model_apply(m: &mut BTreeMap<u32, u8>, op: Op) {
    match op {
        Op::Put(k, t) => {
            m.insert(k, t);
        }
        Op::Del(k) => {
            m.remove(&k);
        }
        Op::Checkpoint => {}
    }
}

/// xorshift, deterministic.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn random_op(r: &mut Rng) -> Op {
    match r.next() % 10 {
        0..=5 => Op::Put((r.next() % 12) as u32, (r.next() % 250) as u8 + 1),
        6..=8 => Op::Del((r.next() % 12) as u32),
        _ => Op::Checkpoint,
    }
}

/// A cut at every write position of an operation leaves the old or the new
/// state, and the store keeps working: remount, more writes, remount.
fn power_cut_property(media: Media, seed: u64, rounds: usize) {
    let mut r = Rng(seed);
    let (mut st, mut env) = fresh(media, 80);
    let (mut saw_old, mut saw_new, mut cuts) = (0usize, 0usize, 0usize);
    let mut model = BTreeMap::new();
    // Warm up: some history, a checkpoint or two.
    for _ in 0..150 {
        let op = random_op(&mut r);
        apply(&mut st, &mut env, op).unwrap();
        model_apply(&mut model, op);
    }
    for _ in 0..rounds {
        let op = random_op(&mut r);
        // How many units does this op write without a cut?
        let probe_flash = st.flash_mut().reboot();
        let mut probe = Store::new(probe_flash);
        let mut probe_env = env.clone();
        probe.mount(info([0; 3]), &mut probe_env, false).unwrap();
        let before_units = units(probe.flash_mut());
        let _ = apply(&mut probe, &mut probe_env, op);
        let total = units(probe.flash_mut()) - before_units;
        let mut after = model.clone();
        model_apply(&mut after, op);
        // Cut at a spread of positions across the whole op (every one for
        // small ops), plus the last few units exactly.
        let step = (total / 60).max(1);
        let mut cuts_at: Vec<usize> = (0..=total).step_by(step).collect();
        // Every unit around the commit point (the journal record and the
        // anchor come last).
        cuts_at.extend(total.saturating_sub(48)..=total);
        cuts_at.sort_unstable();
        cuts_at.dedup();
        for cut in cuts_at {
            let mut f = st.flash_mut().reboot();
            f.budget = Some(cut);
            let mut s2 = Store::new(f);
            let mut e2 = env.clone();
            s2.mount(info([0; 3]), &mut e2, false).unwrap();
            // Re-arm the cut relative to now.
            s2.flash_mut().budget = Some(cut);
            let _ = apply(&mut s2, &mut e2, op);
            let mut s3 = match remount(&mut s2, &mut e2, [0; 3]) {
                Ok(s) => s,
                Err(e) => {
                    panic!("{media:?} seed {seed} op {op:?} cut {cut}/{total}: refused {e:?}")
                }
            };
            let got = state(&s3);
            cuts += 1;
            if got == model && got != after {
                saw_old += 1;
            }
            if got == after && got != model {
                saw_new += 1;
            }
            assert!(
                got == model || got == after,
                "{media:?} seed {seed} op {op:?} cut {cut}/{total}: {got:?} vs {model:?} / {after:?}"
            );
            // It keeps working: more writes, another remount.
            put(&mut s3, &mut e2, 99, 7).unwrap();
            let s4 = remount(&mut s3, &mut e2, [0; 3]).unwrap();
            assert_eq!(get(&s4, 99), Some(7));
        }
        // Move on with the op applied in full.
        apply(&mut st, &mut env, op).unwrap();
        model = after;
    }
    // The sweep must have cut both before and after commit points.
    std::println!("{media:?}: {cuts} cuts, {saw_old} kept the old state, {saw_new} the new");
    assert!(
        cuts > 500 && saw_old > 50 && saw_new > 20,
        "{cuts} {saw_old} {saw_new}"
    );
}

/// Bytes programmed + erases so far (the cut budget's unit).
fn units(f: &mut Sim) -> usize {
    f.written
}

#[test]
fn power_cuts_nor() {
    power_cut_property(Media::Nor, 0x1234_5678, 25);
}

#[test]
fn power_cuts_sd() {
    power_cut_property(Media::Sd, 0x8765_4321, 20);
}

#[test]
fn a_torn_tail_record_is_voided_and_the_store_goes_on() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    put(&mut st, &mut env, 1, 1).unwrap();
    // Cut inside the next PUT's journal record (after its object).
    for cut in 4090..4130 {
        let mut f = st.flash_mut().reboot();
        f.budget = Some(cut);
        let mut s2 = Store::new(f);
        let mut e2 = env.clone();
        s2.mount(info([0; 3]), &mut e2, false).unwrap();
        s2.flash_mut().budget = Some(cut);
        let _ = put(&mut s2, &mut e2, 2, 2);
        let mut s3 = remount(&mut s2, &mut e2, [0; 3]).unwrap();
        put(&mut s3, &mut e2, 3, 3).unwrap();
        let s4 = remount(&mut s3, &mut e2, [0; 3]).unwrap();
        assert_eq!(get(&s4, 1), Some(1));
        assert_eq!(get(&s4, 3), Some(3));
    }
}

#[test]
fn a_stuck_slot_is_voided_and_retried_r3() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    put(&mut st, &mut env, 1, 1).unwrap();
    // The next journal slot won't program: slot 2 of ring sector 0.
    let off = 32 * 3;
    st.flash_mut().stuck.push(off);
    put(&mut st, &mut env, 2, 2).unwrap();
    st.flash_mut().stuck.clear();
    let again = remount(&mut st, &mut env, [0; 3]).unwrap();
    assert_eq!(state(&again), BTreeMap::from([(1, 1), (2, 2)]));
}

// ─── Anchor and adversarial images ───────────────────────────────────────────

#[test]
fn an_old_image_is_refused_as_a_rollback() {
    for (media, sectors) in [(Media::Nor, 64), (Media::Sd, 128)] {
        let (mut st, mut env) = fresh(media, sectors);
        put(&mut st, &mut env, 1, 1).unwrap();
        let old = st.flash_mut().reboot();
        st.delete(&mut env, 1).unwrap();
        put(&mut st, &mut env, 2, 2).unwrap();
        let mut replay = Store::new(old);
        assert_eq!(
            replay.mount(info([0; 3]), &mut env, false),
            Err(Refusal::BehindAnchor(2)),
            "{media:?}"
        );
        // OPEN DEGRADED mounts it read-only.
        replay.mount(info([0; 3]), &mut env, true).unwrap();
        assert_eq!(get(&replay, 1), Some(1));
        assert!(put(&mut replay, &mut env, 3, 3).is_err());
    }
}

#[test]
fn the_fork_of_r1_is_refused() {
    // A cut after record R1 (anchor still behind it); the attacker blanks
    // R1's slot on a copy, the device commits R2 with the same seq one slot
    // later; the original card comes back: same seq, other slot → refused.
    let (mut st, mut env) = fresh(Media::Sd, 96);
    put(&mut st, &mut env, 1, 1).unwrap();
    let mut env_before = env.clone();
    // R1: a PUT committed to the journal but the anchor write "lost".
    env.fail_anchor = true;
    let _ = put(&mut st, &mut env, 2, 2);
    env.fail_anchor = false;
    let original = st.flash_mut().reboot();
    // The copy with R1's block blanked.
    let mut copy = original.clone();
    let mut probe = Store::new(original.clone());
    probe
        .mount(info([0; 3]), &mut env_before.clone(), true)
        .unwrap();
    // Ring sector 0: CHECKPOINT (slot 0), the first mount's VOID (1),
    // PUT 1 (2), R1 = PUT 2 (3); slot i is block i + 1 on SD.
    let off = (3 + 1) * 512;
    copy.mem[off..off + 512].fill(0xFF);
    let mut dev = Store::new(copy);
    dev.mount(info([0; 3]), &mut env_before, false).unwrap();
    st = dev;
    st.delete(&mut env_before, 1).unwrap(); // R2: same seq as R1
    let mut back = Store::new(original);
    assert!(matches!(
        back.mount(info([0; 3]), &mut env_before, false),
        Err(Refusal::BehindAnchor(_))
    ));
}

#[test]
fn a_moved_or_dropped_record_is_refused() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    for k in 1..6 {
        put(&mut st, &mut env, k, k as u8).unwrap();
    }
    let img = st.flash_mut().reboot();
    // Swap two records (slots 2 and 3 of ring sector 0).
    let mut swapped = img.clone();
    let (a, b) = (32 * 3, 32 * 4);
    let ra: Vec<u8> = swapped.mem[a..a + 32].to_vec();
    let rb: Vec<u8> = swapped.mem[b..b + 32].to_vec();
    swapped.mem[a..a + 32].copy_from_slice(&rb);
    swapped.mem[b..b + 32].copy_from_slice(&ra);
    assert!(matches!(
        Store::new(swapped).mount(info([0; 3]), &mut env.clone(), false),
        Err(Refusal::Corrupt(_))
    ));
    // Drop a record (VOID it): the seqs no longer run on.
    let mut dropped = img.clone();
    dropped.mem[a..a + 32].fill(0);
    assert!(matches!(
        Store::new(dropped).mount(info([0; 3]), &mut env.clone(), false),
        Err(Refusal::Corrupt(_))
    ));
}

#[test]
fn another_store_or_no_anchor_is_refused_and_nothing_is_written() {
    let (mut st, mut env) = fresh(Media::Sd, 96);
    put(&mut st, &mut env, 1, 1).unwrap();
    let img = st.flash_mut().reboot();
    let before = img.mem.clone();
    let mut other = Store::new(img.clone());
    assert_eq!(
        other.mount(info_for([0x99; 16], 1, [0; 3]), &mut env.clone(), false),
        Err(Refusal::WrongStore)
    );
    let mut no_anchor = Store::new(img.clone());
    assert_eq!(
        no_anchor.mount(info([0; 3]), &mut Mem::default(), false),
        Err(Refusal::NoAnchor)
    );
    assert_eq!(other.flash_mut().mem, before);
    assert_eq!(no_anchor.flash_mut().mem, before);
    // A blank card is blank, not formatted.
    let mut blank = Store::new(Sim::new(Media::Sd, 96));
    assert_eq!(
        blank.mount(info([0; 3]), &mut env.clone(), false),
        Err(Refusal::Blank)
    );
}

#[test]
fn a_tampered_snapshot_or_object_header_is_caught() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    for k in 1..4 {
        put(&mut st, &mut env, k, k as u8).unwrap();
    }
    st.checkpoint(&mut env).unwrap();
    let img = st.flash_mut().reboot();
    // Flip a byte in every non-ring sector that looks like a snapshot.
    let mut bad = img.clone();
    for s in 16..64 {
        if &bad.mem[s * SS..s * SS + 4] == b"P2S2" {
            bad.mem[s * SS + 70] ^= 1;
        }
    }
    assert!(matches!(
        Store::new(bad).mount(info([0; 3]), &mut env.clone(), false),
        Err(Refusal::Corrupt(_))
    ));
    // An object whose header says another seq: that key fails, not others.
    let mut bad = img.clone();
    let mut first_obj = None;
    for s in 16..64 {
        if &bad.mem[s * SS..s * SS + 4] == b"P2O2" {
            first_obj = Some(s);
            break;
        }
    }
    let s = first_obj.unwrap();
    let key = u32::from_le_bytes(bad.mem[s * SS + 20..s * SS + 24].try_into().unwrap());
    bad.mem[s * SS + 24] ^= 1; // seq
    let mut st2 = Store::new(bad);
    st2.mount(info([0; 3]), &mut env.clone(), false).unwrap();
    let mut out = vec![0u8; MAX_OBJECT_BLOB];
    assert_eq!(
        st2.fetch_into(key, &mut out).err(),
        Some(StorageError::IntegrityFailure)
    );
    for k in (1..4).filter(|&k| k != key) {
        assert_eq!(get(&st2, k), Some(k as u8));
    }
}

// ─── Groups and epochs ───────────────────────────────────────────────────────

#[test]
fn wipe_group_removes_only_that_group() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    put(&mut st, &mut env, 0x0000_0001, 1).unwrap(); // SC-HSM
    put(&mut st, &mut env, 0x0001_0001, 2).unwrap(); // PIV
    put(&mut st, &mut env, 0x0002_0001, 3).unwrap(); // OpenPGP
    put(&mut st, &mut env, 0x0010_0001, 4).unwrap(); // domain (SC-HSM group)
    let mut rotated = None;
    st.wipe_group(&mut env, 0, &mut |g| {
        rotated = Some(g);
        Ok(())
    })
    .unwrap();
    assert_eq!(rotated, Some(1));
    assert_eq!(
        state(&st),
        BTreeMap::from([(0x0001_0001, 2), (0x0002_0001, 3)])
    );
    let again = remount(&mut st, &mut env, [1, 0, 0]).unwrap();
    assert_eq!(
        state(&again),
        BTreeMap::from([(0x0001_0001, 2), (0x0002_0001, 3)])
    );
}

#[test]
fn a_rotation_cut_after_the_record_is_pending_at_mount_r7() {
    let (mut st, mut env) = fresh(Media::Nor, 64);
    put(&mut st, &mut env, 0x0001_0001, 2).unwrap();
    assert!(st
        .wipe_group(&mut env, 1, &mut |_| Err(StorageError::WriteError))
        .is_err());
    // No further commit in this session.
    assert!(put(&mut st, &mut env, 0x0002_0001, 3).is_err());
    // The binding still has generation 0 for PIV: the mount says what to
    // finish; with the binding written (gen 1), it mounts.
    assert_eq!(
        remount(&mut st, &mut env, [0; 3]).err(),
        Some(Refusal::PendingRotation { group: 1, gen: 1 })
    );
    let again = remount(&mut st, &mut env, [0, 1, 0]).unwrap();
    assert_eq!(state(&again), BTreeMap::new());
}

#[test]
fn keys_are_bound_to_store_group_epoch_and_full_key_id() {
    let e = [3u8; 32];
    let a = derive_k_obj(&SMK, &SID, &e, 0x0001_0001);
    assert_ne!(
        *a,
        *derive_k_obj(&SMK, &SID, &e, 0x0002_0001),
        "applet byte"
    );
    assert_ne!(
        *a,
        *derive_k_obj(&SMK, &SID, &e, 0x0101_0001),
        "partition byte"
    );
    assert_ne!(
        *a,
        *derive_k_obj(&SMK, &[0x12; 16], &e, 0x0001_0001),
        "store"
    );
    assert_ne!(
        *a,
        *derive_k_obj(&SMK, &SID, &[4; 32], 0x0001_0001),
        "epoch"
    );
    let _ = Zeroizing::new(0u8);
}
