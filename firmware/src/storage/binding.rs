//! Storage V2 binding block (docs/STORAGE_V2.md §8.1, §18 R8, R9, R14).
//!
//! The binding block ties a keystore to this device: the store's identity,
//! the epoch secrets its keys are derived from, the format generation the
//! counter-log anchor refers to, and the SC-HSM SO-PIN.
//! It lives on internal flash on every board, never on the removable card.
//!
//! # On flash
//! A ring of [`flash_layout::BINDING_SECTORS`](super::flash_layout) sectors;
//! each copy is one record at the start of a sector:
//!
//! ```text
//! "P2B2" | gen u32 | state u8 | rsv[3] | store_id[16] | format_gen u32 |
//! E_store, E_scHsm, E_piv, E_pgp [4 × 32] | group generations [3 × u32] |
//! SO-PIN salt[16] | SO-PIN verifier[32] | card fingerprint[8] |
//! HMAC-SHA256(K_bind, all of the above)[32]                 — 260 bytes LE
//! ```
//!
//! A write goes to the sector after the current one with `gen + 1`, is
//! read back and verified, and only then is the old copy erased: that
//! erase is what destroys a replaced epoch secret.  A cut at any point
//! leaves the old copy, the new one, or both (the higher `gen` wins).
//! Eight sectors, because applet resets write the binding and some can be
//! driven by the host without a secret (R8): ~800 000 writes.
//!
//! # SO-PIN
//! The SC-HSM SO-PIN lives here, not in the keystore, so it works while the
//! store is refused (recovery and FORMAT STORE need it, §9.3).  The verifier
//! is the SO-PIN's PBKDF2 hash encrypted under a key derived from `K_bind`
//! and the salt ([`seal_so_pin`]); the copy's HMAC protects it.  Reading it
//! takes `K_bind`, which also lets an attacker test guesses against a
//! `HMAC(K_bind, salt ‖ SO-PIN)` verifier: the two are equally strong, and
//! this one keeps the applet's double-checked comparison as it is.

use pico2hsm_core::error::StorageError;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::retry_counter::CounterFlash;
use crate::crypto::kdf::{hkdf_sha256, hmac_sha256};

const MAGIC: [u8; 4] = *b"P2B2";

/// Bytes of one encoded copy (HMAC included).
pub const ENCODED_LEN: usize = 228 + 32;

/// Applet groups with their own epoch (STORAGE_V2 §4).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// SC-HSM keys and domain records (applet bytes 0x00 and 0x10).
    ScHsm = 0,
    /// PIV (applet byte 0x01).
    Piv = 1,
    /// OpenPGP (applet byte 0x02).
    OpenPgp = 2,
}

/// Where a format or re-index stands (STORAGE_V2 §8.3, R2).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindState {
    /// A format is under way; finish it at boot with the same `store_id`.
    Formatting = 1,
    /// The store is in use.
    Active = 2,
    /// An ACCEPT STORE re-index is under way (R2); finish it at boot.
    Reindexing = 3,
}

impl BindState {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Formatting),
            2 => Some(Self::Active),
            3 => Some(Self::Reindexing),
            _ => None,
        }
    }
}

/// The binding block's content.  Holds secrets (the epochs): wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Binding {
    /// Copy generation: the highest valid one wins.  Set by
    /// [`BindingRing::write`].
    pub gen: u32,
    #[zeroize(skip)]
    pub state: BindState,
    /// The store's random identity (chosen at format).
    pub store_id: [u8; 16],
    /// Bumped by every format and re-index; the anchor carries its low 16
    /// bits.
    pub format_gen: u32,
    /// `E_store` (journal MAC key input), replaced on format and re-index.
    pub e_store: [u8; 32],
    /// `E_group` per [`Group`], replaced on format and that group's reset.
    pub e_group: [[u8; 32]; 3],
    /// Epoch generation per [`Group`] (a WIPE_OWNER above it is pending).
    pub group_gen: [u32; 3],
    /// SO-PIN salt.
    pub so_salt: [u8; 16],
    /// The SO-PIN's PBKDF2 hash, sealed by [`seal_so_pin`]; all zero: no
    /// SO-PIN set.
    pub so_verifier: [u8; 32],
    /// Fingerprint of the card being formatted (R14); zero on QMI boards.
    pub card_fingerprint: [u8; 8],
}

impl core::fmt::Debug for Binding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the epochs or the verifier.
        f.debug_struct("Binding")
            .field("gen", &self.gen)
            .field("state", &self.state)
            .field("format_gen", &self.format_gen)
            .finish_non_exhaustive()
    }
}

impl Binding {
    /// Serialise with the HMAC under `k_bind`.
    fn encode(&self, k_bind: &[u8; 32]) -> Zeroizing<[u8; ENCODED_LEN]> {
        let mut b = Zeroizing::new([0u8; ENCODED_LEN]);
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            b[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&MAGIC);
        put(&self.gen.to_le_bytes());
        put(&[self.state as u8, 0, 0, 0]);
        put(&self.store_id);
        put(&self.format_gen.to_le_bytes());
        put(&self.e_store);
        for e in &self.e_group {
            put(e);
        }
        for g in &self.group_gen {
            put(&g.to_le_bytes());
        }
        put(&self.so_salt);
        put(&self.so_verifier);
        put(&self.card_fingerprint);
        debug_assert_eq!(at, ENCODED_LEN - 32);
        let mac = hmac_sha256(k_bind, &b[..ENCODED_LEN - 32]);
        b[ENCODED_LEN - 32..].copy_from_slice(&mac);
        b
    }

    /// Parse and verify a copy (constant-time MAC check).
    fn decode(b: &[u8; ENCODED_LEN], k_bind: &[u8; 32]) -> Option<Self> {
        if b[0..4] != MAGIC {
            return None;
        }
        let mac = hmac_sha256(k_bind, &b[..ENCODED_LEN - 32]);
        if !bool::from(mac.ct_eq(&b[ENCODED_LEN - 32..])) {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let arr = |i: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b[i..i + 32]);
            a
        };
        let mut out = Binding {
            gen: u32_at(4),
            state: BindState::from_u8(b[8])?,
            format_gen: u32_at(28),
            e_store: arr(32),
            e_group: [arr(64), arr(96), arr(128)],
            group_gen: [u32_at(160), u32_at(164), u32_at(168)],
            ..Binding::default()
        };
        out.store_id.copy_from_slice(&b[12..28]);
        out.so_salt.copy_from_slice(&b[172..188]);
        out.so_verifier.copy_from_slice(&b[188..220]);
        out.card_fingerprint.copy_from_slice(&b[220..228]);
        Some(out)
    }
}

impl Default for Binding {
    fn default() -> Self {
        Binding {
            gen: 0,
            state: BindState::Formatting,
            store_id: [0; 16],
            format_gen: 0,
            e_store: [0; 32],
            e_group: [[0; 32]; 3],
            group_gen: [0; 3],
            so_salt: [0; 16],
            so_verifier: [0; 32],
            card_fingerprint: [0; 8],
        }
    }
}

/// `K_bind = HKDF-SHA256(SMK, info = "pico2hsm-bind-v2")` (STORAGE_V2 §4).
pub fn derive_k_bind(smk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    // HKDF-SHA256 with a 32-byte output cannot fail.
    let _ = hkdf_sha256(&[], smk, b"pico2hsm-bind-v2", &mut k[..]);
    k
}

/// The keystream that seals an SO-PIN hash: `HKDF(K_bind, salt,
/// "pico2hsm-sopin-v2")`.  A new salt with every SO-PIN, so never reused.
fn so_pin_pad(k_bind: &[u8; 32], salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut pad = Zeroizing::new([0u8; 32]);
    let _ = hkdf_sha256(salt, k_bind, b"pico2hsm-sopin-v2", &mut pad[..]);
    pad
}

/// The binding's SO-PIN verifier for a PBKDF2 `hash` with `salt`.
pub fn seal_so_pin(k_bind: &[u8; 32], salt: &[u8; 16], hash: &[u8; 32]) -> [u8; 32] {
    let pad = so_pin_pad(k_bind, salt);
    core::array::from_fn(|i| hash[i] ^ pad[i])
}

/// The PBKDF2 hash a binding's verifier holds; `None` when none is set.
pub fn open_so_pin(k_bind: &[u8; 32], b: &Binding) -> Option<Zeroizing<[u8; 32]>> {
    if b.so_verifier == [0u8; 32] {
        return None;
    }
    let pad = so_pin_pad(k_bind, &b.so_salt);
    Some(Zeroizing::new(core::array::from_fn(|i| {
        b.so_verifier[i] ^ pad[i]
    })))
}

/// What the ring holds (R9 needs "absent" and "unverifiable" apart).
// Returned once, at boot, and never stored: the size difference between
// the variants costs nothing (and there is no heap to box it on).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    /// Every sector blank: no binding was ever written.
    Blank,
    /// Something was written, but no copy verifies under this K_bind (a
    /// different device's flash, a changed SMK after OTP provisioning,
    /// damage).
    Unverifiable,
    /// The current binding.
    Valid(Binding),
}

/// The binding ring over a [`CounterFlash`] region of `sectors` sectors.
pub struct BindingRing<F: CounterFlash> {
    flash: F,
    sectors: u32,
    /// The sector and `gen` of the current copy.
    current: Option<(u32, u32)>,
}

const SECTOR: u32 = pico2hsm_core::flash::SECTOR_SIZE as u32;

impl<F: CounterFlash> BindingRing<F> {
    /// Scan the ring.  Two valid copies with the same `gen` and different
    /// content fail closed (`IntegrityFailure`, R14); identical ones are
    /// one copy.  Stale copies are left in place until the next
    /// [`Self::write`] or [`Self::tidy`].
    pub fn open(
        mut flash: F,
        sectors: u32,
        k_bind: &[u8; 32],
    ) -> Result<(Self, Scan), StorageError> {
        let mut best: Option<(u32, Binding)> = None;
        let mut written = false;
        let mut buf = Zeroizing::new([0u8; ENCODED_LEN]);
        for sector in 0..sectors {
            flash.read(sector * SECTOR, &mut buf[..])?;
            if buf.iter().all(|&b| b == 0xFF) {
                continue;
            }
            written = true;
            let Some(b) = Binding::decode(&buf, k_bind) else {
                continue;
            };
            match &best {
                Some((_, cur)) if b.gen < cur.gen => {}
                Some((_, cur)) if b.gen == cur.gen => {
                    if *cur != b {
                        return Err(StorageError::IntegrityFailure);
                    }
                }
                _ => best = Some((sector, b)),
            }
        }
        let current = best.as_ref().map(|(s, b)| (*s, b.gen));
        let scan = match best {
            Some((_, b)) => Scan::Valid(b),
            None if written => Scan::Unverifiable,
            None => Scan::Blank,
        };
        Ok((
            BindingRing {
                flash,
                sectors,
                current,
            },
            scan,
        ))
    }

    /// The underlying flash (tests inspect it).
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    fn erase_if_written(&mut self, sector: u32) -> Result<(), StorageError> {
        let mut probe = [0u8; ENCODED_LEN];
        self.flash.read(sector * SECTOR, &mut probe)?;
        if probe.iter().all(|&b| b == 0xFF) {
            return Ok(());
        }
        self.flash.erase_sector(sector)
    }

    /// Erase every sector but the current copy's (boot, after the copy was
    /// read): stale copies hold replaced epoch secrets.
    pub fn tidy(&mut self) -> Result<(), StorageError> {
        for sector in 0..self.sectors {
            if Some(sector) != self.current.map(|c| c.0) {
                self.erase_if_written(sector)?;
            }
        }
        Ok(())
    }

    /// Durably write `b` as the new current binding: `b.gen` becomes the
    /// current `gen + 1`, the copy goes to the next sector (erased and
    /// blank-checked first), is read back and verified, then the old copy
    /// is erased.  A failed sector is skipped with a further `gen`.  Refused
    /// (`WriteError`) when `gen` would overflow (R14).
    pub fn write(&mut self, b: &mut Binding, k_bind: &[u8; 32]) -> Result<(), StorageError> {
        let (start, mut gen) = match self.current {
            Some((sector, gen)) => ((sector + 1) % self.sectors, gen),
            None => (0, 0),
        };
        let old = self.current.map(|c| c.0);
        let mut last = Err(StorageError::WriteError);
        let mut readback = Zeroizing::new([0u8; ENCODED_LEN]);
        for k in 0..self.sectors {
            let sector = (start + k) % self.sectors;
            if Some(sector) == old {
                continue;
            }
            gen = gen.checked_add(1).ok_or(StorageError::WriteError)?;
            b.gen = gen;
            let enc = b.encode(k_bind);
            let attempt = (|| {
                self.flash.erase_sector(sector)?;
                self.flash.read(sector * SECTOR, &mut readback[..])?;
                if readback.iter().any(|&x| x != 0xFF) {
                    return Err(StorageError::EraseError);
                }
                self.flash.program(sector * SECTOR, &enc[..])?;
                self.flash.read(sector * SECTOR, &mut readback[..])?;
                if Binding::decode(&readback, k_bind).as_ref() != Some(&*b) {
                    return Err(StorageError::WriteError);
                }
                Ok(())
            })();
            match attempt {
                Ok(()) => {
                    self.current = Some((sector, gen));
                    // Destroy the replaced epochs.  If this erase fails the
                    // old copy (lower gen) stays until `tidy` at the next
                    // boot; the new copy already wins.
                    if let Some(o) = old {
                        let _ = self.flash.erase_sector(o);
                    }
                    return Ok(());
                }
                Err(e) => last = Err(e),
            }
        }
        last
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const SECTORS: u32 = 8;
    const SS: usize = pico2hsm_core::flash::SECTOR_SIZE;

    /// NOR flash with a power cut after a number of programmed bytes.
    #[derive(Clone)]
    struct Sim {
        mem: Vec<u8>,
        budget: Option<usize>,
        dead: bool,
        erases: Vec<u32>,
    }

    impl Sim {
        fn new() -> Self {
            Sim {
                mem: vec![0xFF; SECTORS as usize * SS],
                budget: None,
                dead: false,
                erases: Vec::new(),
            }
        }
        fn reboot(&self) -> Self {
            Sim {
                budget: None,
                dead: false,
                ..self.clone()
            }
        }
        fn written(&self) -> usize {
            (0..SECTORS as usize)
                .filter(|s| self.mem[s * SS..(s + 1) * SS].iter().any(|&b| b != 0xFF))
                .count()
        }
    }

    impl CounterFlash for Sim {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
            let o = offset as usize;
            buf.copy_from_slice(&self.mem[o..o + buf.len()]);
            Ok(())
        }
        fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
            if self.dead {
                return Err(StorageError::WriteError);
            }
            for (i, &d) in data.iter().enumerate() {
                if let Some(b) = self.budget.as_mut() {
                    if *b == 0 {
                        self.dead = true;
                        return Err(StorageError::WriteError);
                    }
                    *b -= 1;
                }
                self.mem[offset as usize + i] &= d;
            }
            Ok(())
        }
        fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
            if self.dead {
                return Err(StorageError::EraseError);
            }
            self.erases.push(sector);
            let s = sector as usize * SS;
            self.mem[s..s + SS].fill(0xFF);
            Ok(())
        }
    }

    const K: [u8; 32] = [7; 32];

    fn binding(tag: u8) -> Binding {
        Binding {
            state: BindState::Active,
            store_id: [tag; 16],
            format_gen: u32::from(tag),
            e_store: [tag ^ 1; 32],
            e_group: [[tag ^ 2; 32], [tag ^ 3; 32], [tag ^ 4; 32]],
            group_gen: [1, 2, 3],
            ..Binding::default()
        }
    }

    fn open(f: Sim) -> (BindingRing<Sim>, Scan) {
        BindingRing::open(f, SECTORS, &K).unwrap()
    }

    #[test]
    fn layout_is_260_bytes() {
        assert_eq!(binding(1).encode(&K).len(), ENCODED_LEN);
        assert_eq!(ENCODED_LEN, 260);
    }

    #[test]
    fn blank_ring_is_blank() {
        assert_eq!(open(Sim::new()).1, Scan::Blank);
    }

    #[test]
    fn write_round_trips_and_erases_the_old_copy() {
        let (mut ring, _) = open(Sim::new());
        let mut b = binding(1);
        ring.write(&mut b, &K).unwrap();
        assert_eq!(b.gen, 1);
        let mut b2 = binding(2);
        ring.write(&mut b2, &K).unwrap();
        assert_eq!(b2.gen, 2);
        assert_eq!(ring.flash_mut().written(), 1, "old copy erased");
        let (_, scan) = open(ring.flash_mut().reboot());
        assert_eq!(scan, Scan::Valid(b2));
    }

    #[test]
    fn writes_go_round_the_whole_ring() {
        let (mut ring, _) = open(Sim::new());
        for i in 0..(3 * SECTORS) {
            ring.write(&mut binding(i as u8), &K).unwrap();
        }
        let mut per_sector = [0usize; SECTORS as usize];
        for &s in &ring.flash_mut().erases {
            per_sector[s as usize] += 1;
        }
        // Every sector took its share of the erases (R8).
        assert!(per_sector.iter().all(|&n| n >= 4), "{per_sector:?}");
    }

    #[test]
    fn another_key_is_unverifiable_not_blank() {
        let (mut ring, _) = open(Sim::new());
        ring.write(&mut binding(1), &K).unwrap();
        let (_, scan) = BindingRing::open(ring.flash_mut().reboot(), SECTORS, &[8; 32]).unwrap();
        assert_eq!(scan, Scan::Unverifiable);
    }

    #[test]
    fn a_flipped_bit_is_unverifiable() {
        let (mut ring, _) = open(Sim::new());
        ring.write(&mut binding(1), &K).unwrap();
        let mut f = ring.flash_mut().reboot();
        f.mem[40] ^= 0x01; // inside E_store
        assert_eq!(open(f).1, Scan::Unverifiable);
    }

    #[test]
    fn a_cut_at_every_byte_keeps_the_old_or_the_new_binding() {
        let (mut ring, _) = open(Sim::new());
        let mut old = binding(1);
        ring.write(&mut old, &K).unwrap();
        let base = ring.flash_mut().reboot();
        for budget in 0..=ENCODED_LEN {
            let mut f = base.reboot();
            f.budget = Some(budget);
            let (mut r, _) = open(f);
            let mut new = binding(2);
            let wrote = r.write(&mut new, &K).is_ok();
            let (mut r2, scan) = open(r.flash_mut().reboot());
            match scan {
                Scan::Valid(b) if b == old => assert!(!wrote, "budget {budget}"),
                Scan::Valid(b) => assert_eq!(b.store_id, [2; 16], "budget {budget}"),
                other => panic!("budget {budget}: {other:?}"),
            }
            // Boot tidies the stale copies away.
            r2.tidy().unwrap();
            assert_eq!(r2.flash_mut().written(), 1, "budget {budget}");
        }
    }

    #[test]
    fn equal_gens_must_agree() {
        let (mut ring, _) = open(Sim::new());
        let mut b = binding(1);
        ring.write(&mut b, &K).unwrap();
        // The same copy in a second sector: one copy.
        let mut f = ring.flash_mut().reboot();
        let copy = f.mem[0..ENCODED_LEN].to_vec();
        f.mem[3 * SS..3 * SS + ENCODED_LEN].copy_from_slice(&copy);
        assert_eq!(open(f.reboot()).1, Scan::Valid(b.clone()));
        // A different binding with the same gen: fail closed.
        let mut other = binding(9);
        other.gen = b.gen;
        let enc = other.encode(&K);
        f.mem[5 * SS..5 * SS + ENCODED_LEN].copy_from_slice(&enc[..]);
        assert!(matches!(
            BindingRing::open(f, SECTORS, &K),
            Err(StorageError::IntegrityFailure)
        ));
    }

    #[test]
    fn gen_overflow_is_refused() {
        let (mut ring, _) = open(Sim::new());
        let mut b = binding(1);
        ring.write(&mut b, &K).unwrap();
        // Forge the current gen to the maximum.
        ring.current = Some((ring.current.unwrap().0, u32::MAX));
        assert_eq!(
            ring.write(&mut binding(2), &K),
            Err(StorageError::WriteError)
        );
    }

    #[test]
    fn the_so_pin_round_trips_and_is_bound_to_k_bind() {
        let mut b = binding(1);
        assert_eq!(open_so_pin(&K, &b), None, "none set");
        b.so_salt = [3; 16];
        b.so_verifier = seal_so_pin(&K, &b.so_salt, &[9; 32]);
        assert_ne!(b.so_verifier, [9; 32], "not stored in the clear");
        assert_eq!(*open_so_pin(&K, &b).unwrap(), [9; 32]);
        assert_ne!(*open_so_pin(&[8; 32], &b).unwrap(), [9; 32]);
        // Another salt, another pad.
        assert_ne!(seal_so_pin(&K, &[4; 16], &[9; 32]), b.so_verifier);
    }

    #[test]
    fn k_bind_is_bound_to_the_smk() {
        assert_ne!(*derive_k_bind(&[1; 32]), *derive_k_bind(&[2; 32]));
        assert_eq!(*derive_k_bind(&[1; 32]), *derive_k_bind(&[1; 32]));
    }
}
