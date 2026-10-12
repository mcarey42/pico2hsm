//! Core1 → core0 status snapshot for the display, and the SAS mailbox.
//!
//! Core1 owns the real state (authentication flags, retry counters, key
//! inventory, the outcome of the last command).  It publishes a compact
//! copy here at fixed points of `dispatcher_loop`; core0's display task
//! only reads it.  Core0 never guesses state from APDU bytes.
//!
//! Both mailboxes are seqlocks over plain `AtomicU32` words: one writer
//! (core1, or core0 at boot before core1 runs), any number of readers, no
//! lock that core1 could hold while core0 waits.  A reader that keeps
//! racing the writer gives up and keeps its previous copy.
//!
//! Everything here compiles on the host and is unit-tested there.
//!
//! See `docs/DISPLAY_ARCHITECTURE.md` for the word layout and the publish
//! points.

use core::sync::atomic::{fence, AtomicBool, AtomicU32, Ordering};

pub use pico2hsm_core::op::{Applet, OpCode, OpResult};

// ─── Seqlock ─────────────────────────────────────────────────────────────────

/// A single-writer seqlock over `N` words.
pub struct SeqLock<const N: usize> {
    seq: AtomicU32,
    w: [AtomicU32; N],
}

#[allow(clippy::declare_interior_mutable_const)] // only used as an array initialiser
const ZERO_WORD: AtomicU32 = AtomicU32::new(0);

impl<const N: usize> SeqLock<N> {
    /// All words zero.
    pub const fn new() -> Self {
        SeqLock {
            seq: AtomicU32::new(0),
            w: [ZERO_WORD; N],
        }
    }

    /// Publish `words`.  Single writer only.
    pub fn write(&self, words: [u32; N]) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        for (slot, v) in self.w.iter().zip(words) {
            slot.store(v, Ordering::Relaxed);
        }
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    /// A consistent copy, or `None` if the writer kept racing the read.
    pub fn read(&self) -> Option<[u32; N]> {
        for _ in 0..64 {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let mut out = [0u32; N];
            for (o, slot) in out.iter_mut().zip(self.w.iter()) {
                *o = slot.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return Some(out);
            }
        }
        None
    }

    /// Number of completed writes (0 = never published).
    pub fn writes(&self) -> u32 {
        self.seq.load(Ordering::Acquire) / 2
    }
}

// ─── Bit packing ─────────────────────────────────────────────────────────────

const fn mask(bits: u32) -> u32 {
    (1 << bits) - 1
}

fn put(word: &mut u32, shift: u32, bits: u32, v: u32) {
    *word |= (v & mask(bits)) << shift;
}

fn get(word: u32, shift: u32, bits: u32) -> u32 {
    (word >> shift) & mask(bits)
}

/// Authentication bits (W0).  All are live session state on core1.
pub mod auth {
    /// SC-HSM user PIN verified.
    pub const HSM_USER: u8 = 1 << 0;
    /// SC-HSM SO-PIN verified.
    pub const HSM_SO: u8 = 1 << 1;
    /// PIV PIN verified.
    pub const PIV_PIN: u8 = 1 << 2;
    /// PIV management key authenticated.
    pub const PIV_MGMT: u8 = 1 << 3;
    /// OpenPGP PW1 verified for signing (mode 81).
    pub const PGP_PW1_81: u8 = 1 << 4;
    /// OpenPGP PW1 verified for other operations (mode 82).
    pub const PGP_PW1_82: u8 = 1 << 5;
    /// OpenPGP PW3 (admin) verified.
    pub const PGP_PW3: u8 = 1 << 6;
    /// Administrator credentials: the ADMIN chip shows while any is live.
    pub const ADMIN: u8 = HSM_SO | PIV_MGMT | PGP_PW3;
}

/// One-shot authorisations (W0): armed for exactly one operation.
pub mod oneshot {
    /// PIV PIN-always slot 9C may sign once (`pin_always_ok`).
    pub const PIV_9C_ARMED: u8 = 1 << 0;
    /// OpenPGP single-signature mode (C4 = 00) with PW1-81 armed.
    pub const PGP_SIG_SINGLE: u8 = 1 << 1;
}

/// Health flags (W3).
pub mod health {
    /// The keystore failed to initialise at boot.
    pub const KS_INIT_FAILED: u8 = 1 << 0;
    /// No storage master key: the keystore refuses to store keys.
    pub const SMK_MISSING: u8 = 1 << 1;
    /// The last write to the keystore failed (sticky until one succeeds).
    pub const STORE_WRITE_FAILED: u8 = 1 << 2;
    /// SD card keystore missing.
    pub const SD_MISSING: u8 = 1 << 3;
    /// A mirrored store runs on one copy.
    pub const MIRROR_DEGRADED: u8 = 1 << 4;
    /// OTP holds a storage key (the device is provisioned).
    pub const PROVISIONED: u8 = 1 << 5;
}

/// Per-applet primary-credential bit in [`Session::blocked`].
pub mod blocked {
    /// SC-HSM user PIN.
    pub const HSM: u8 = 1 << 0;
    /// PIV PIN.
    pub const PIV: u8 = 1 << 1;
    /// OpenPGP PW1.
    pub const PGP: u8 = 1 << 2;
}

/// W0 — the host session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    /// Low byte of the `SESSION_EPOCH` this was built for.
    pub epoch_lo: u8,
    /// Active applet.
    pub applet: Applet,
    /// [`auth`] bits.
    pub auth: u8,
    /// [`oneshot`] bits.
    pub oneshot: u8,
    /// Tries left on the active applet's primary credential (≤ 15).
    pub pri_left: u8,
    /// Its maximum (≤ 15).
    pub pri_max: u8,
    /// [`blocked`] bits, one per applet.
    pub blocked: u8,
}

/// Progress of the tracked operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum OpState {
    /// Nothing tracked yet.
    #[default]
    Idle = 0,
    /// Core1 is running it.
    InProgress = 1,
    /// Finished; `result` is valid.
    Done = 2,
}

impl OpState {
    fn from_bits(v: u32) -> Self {
        match v & 3 {
            1 => OpState::InProgress,
            2 => OpState::Done,
            _ => OpState::Idle,
        }
    }
}

/// Small algorithm id for the debug activity line (four bits).
pub mod algo {
    /// Unknown / not applicable.
    pub const NONE: u8 = 0;
    /// NIST P-256.
    pub const P256: u8 = 1;
    /// NIST P-384.
    pub const P384: u8 = 2;
    /// NIST P-521.
    pub const P521: u8 = 3;
    /// secp256k1.
    pub const K256: u8 = 4;
    /// Brainpool (any size).
    pub const BRAINPOOL: u8 = 5;
    /// RSA (any size).
    pub const RSA: u8 = 6;
    /// AES.
    pub const AES: u8 = 7;
    /// Ed25519.
    pub const ED25519: u8 = 8;
    /// X25519.
    pub const X25519: u8 = 9;

    /// Display name.
    pub fn name(a: u8) -> &'static str {
        match a {
            P256 => "P-256",
            P384 => "P-384",
            P521 => "P-521",
            K256 => "K-256",
            BRAINPOOL => "BP",
            RSA => "RSA",
            AES => "AES",
            ED25519 => "Ed25519",
            X25519 => "X25519",
            _ => "",
        }
    }
}

/// W1 — the last tracked operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Activity {
    /// Bumped for every tracked operation (wraps).
    pub op_seq: u8,
    /// What it is.
    pub op: OpCode,
    /// Where it is.
    pub state: OpState,
    /// How it ended (valid when `state == Done`).
    pub result: OpResult,
    /// [`algo`] id (debug builds show it).
    pub algo: u8,
    /// Key reference (debug builds show it).
    pub key_ref: u8,
    /// [`hint`] after a signature that spent a one-shot authorisation.
    pub hint: u8,
}

/// Policy hints (W1) after a signature.
pub mod hint {
    /// Nothing to note.
    pub const NONE: u8 = 0;
    /// PIV slot 9C signed: verify the PIN again before the next one.
    pub const PIV_PIN_ALWAYS: u8 = 1;
    /// OpenPGP single-signature mode: PW1 was spent.
    pub const PGP_SINGLE_USE: u8 = 2;
}

/// Domain membership as the display shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum DomainState {
    /// No DKEK.
    #[default]
    None = 0,
    /// A DKEK, but this device holds no member certificate.
    SelfOnly = 1,
    /// A certified member of its domain.
    Member = 2,
    /// This device's certificate is revoked.
    Revoked = 3,
}

impl DomainState {
    fn from_bits(v: u32) -> Self {
        match v & 3 {
            1 => DomainState::SelfOnly,
            2 => DomainState::Member,
            3 => DomainState::Revoked,
            _ => DomainState::None,
        }
    }
}

/// W2 — what the device holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// SC-HSM user keys (no files, no firmware records).
    pub keys_hsm: u8,
    /// PIV keys (≤ 15).
    pub keys_piv: u8,
    /// OpenPGP keys (≤ 3).
    pub keys_pgp: u8,
    /// Domain membership.
    pub domain: DomainState,
    /// Member-list entries (≤ 63).
    pub members: u8,
}

/// W3 — health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    /// First two bytes of the domain ID.
    pub domain_id_hi16: u16,
    /// [`health`] bits.
    pub flags: u8,
}

/// Words in a published snapshot.  W0–W3 as in the design spec, plus W4
/// with the raw status word of the last tracked operation (debug builds
/// show it).
pub const SNAPSHOT_WORDS: usize = 5;

/// Everything the display may show about core1's state, decoded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// W0.
    pub session: Session,
    /// W1.
    pub activity: Activity,
    /// W2.
    pub inventory: Inventory,
    /// W3.
    pub health: Health,
    /// W4: status word of the last tracked operation.
    pub last_sw: u16,
}

impl Snapshot {
    /// Pack into wire words.  Fields wider than their slot are truncated
    /// (counts are saturated by the producer).
    pub fn pack(&self) -> [u32; SNAPSHOT_WORDS] {
        let mut w = [0u32; SNAPSHOT_WORDS];
        let s = &self.session;
        put(&mut w[0], 0, 8, u32::from(s.epoch_lo));
        put(&mut w[0], 8, 2, s.applet as u32);
        put(&mut w[0], 10, 7, u32::from(s.auth));
        put(&mut w[0], 17, 2, u32::from(s.oneshot));
        put(&mut w[0], 19, 4, u32::from(s.pri_left));
        put(&mut w[0], 23, 4, u32::from(s.pri_max));
        put(&mut w[0], 27, 3, u32::from(s.blocked));
        let a = &self.activity;
        put(&mut w[1], 0, 8, u32::from(a.op_seq));
        put(&mut w[1], 8, 5, a.op as u32);
        put(&mut w[1], 13, 2, a.state as u32);
        put(&mut w[1], 15, 2, a.result as u32);
        put(&mut w[1], 17, 4, u32::from(a.algo));
        put(&mut w[1], 21, 8, u32::from(a.key_ref));
        put(&mut w[1], 29, 2, u32::from(a.hint));
        let i = &self.inventory;
        put(&mut w[2], 0, 8, u32::from(i.keys_hsm));
        put(&mut w[2], 8, 4, u32::from(i.keys_piv));
        put(&mut w[2], 12, 2, u32::from(i.keys_pgp));
        put(&mut w[2], 14, 2, i.domain as u32);
        put(&mut w[2], 16, 6, u32::from(i.members));
        put(&mut w[3], 0, 16, u32::from(self.health.domain_id_hi16));
        put(&mut w[3], 16, 6, u32::from(self.health.flags));
        put(&mut w[4], 0, 16, u32::from(self.last_sw));
        w
    }

    /// Decode wire words.
    pub fn unpack(w: [u32; SNAPSHOT_WORDS]) -> Self {
        Snapshot {
            session: Session {
                epoch_lo: get(w[0], 0, 8) as u8,
                applet: Applet::from_bits(get(w[0], 8, 2)),
                auth: get(w[0], 10, 7) as u8,
                oneshot: get(w[0], 17, 2) as u8,
                pri_left: get(w[0], 19, 4) as u8,
                pri_max: get(w[0], 23, 4) as u8,
                blocked: get(w[0], 27, 3) as u8,
            },
            activity: Activity {
                op_seq: get(w[1], 0, 8) as u8,
                op: OpCode::from_bits(get(w[1], 8, 5)),
                state: OpState::from_bits(get(w[1], 13, 2)),
                result: OpResult::from_bits(get(w[1], 15, 2)),
                algo: get(w[1], 17, 4) as u8,
                key_ref: get(w[1], 21, 8) as u8,
                hint: get(w[1], 29, 2) as u8,
            },
            inventory: Inventory {
                keys_hsm: get(w[2], 0, 8) as u8,
                keys_piv: get(w[2], 8, 4) as u8,
                keys_pgp: get(w[2], 12, 2) as u8,
                domain: DomainState::from_bits(get(w[2], 14, 2)),
                members: get(w[2], 16, 6) as u8,
            },
            health: Health {
                domain_id_hi16: get(w[3], 0, 16) as u16,
                flags: get(w[3], 16, 6) as u8,
            },
            last_sw: get(w[4], 0, 16) as u16,
        }
    }
}

/// The published snapshot (written by core1; by core0 only at boot,
/// before core1 starts).
pub static SNAP: SeqLock<SNAPSHOT_WORDS> = SeqLock::new();

/// Publish `s`.
pub fn publish(s: &Snapshot) {
    SNAP.write(s.pack());
}

/// The latest snapshot; `None` before the first publish or if the read
/// kept racing the writer.
pub fn read() -> Option<Snapshot> {
    if SNAP.writes() == 0 {
        return None;
    }
    SNAP.read().map(Snapshot::unpack)
}

// ─── Core0-side inputs ───────────────────────────────────────────────────────

/// USB is configured by a host (set by core0's USB handler).
pub static USB_CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Core0 uptime (ms, low 32 bits, never 0) when the APDU in flight was
/// handed to core1; 0 while idle.
pub static APDU_STARTED_MS: AtomicU32 = AtomicU32::new(0);

/// Record the start (`Some(now_ms)`) or end (`None`) of an APDU.
pub fn set_apdu_started(now_ms: Option<u32>) {
    let v = match now_ms {
        Some(0) => 1,
        Some(t) => t,
        None => 0,
    };
    APDU_STARTED_MS.store(v, Ordering::Release);
}

// ─── SAS mailbox ─────────────────────────────────────────────────────────────

/// State of the short-authentication-string mailbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum SasState {
    /// Nothing to show.
    #[default]
    None = 0,
    /// A code is waiting for comparison.
    Pending = 1,
    /// The exchange completed.
    Enrolled = 2,
    /// The exchange was abandoned.
    Cancelled = 3,
    /// The code was not confirmed in time.
    Expired = 4,
}

impl SasState {
    fn from_bits(v: u32) -> Self {
        match v & 7 {
            1 => SasState::Pending,
            2 => SasState::Enrolled,
            3 => SasState::Cancelled,
            4 => SasState::Expired,
            _ => SasState::None,
        }
    }
}

/// This device's role in the enrollment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum SasRole {
    /// It sponsors the joiner.
    #[default]
    Sponsor = 0,
    /// It joins the sponsor's domain.
    Joiner = 1,
}

/// One SAS mailbox value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SasMail {
    /// Bumped for every new code.
    pub gen: u32,
    /// The code, `0..100_000_000`.
    pub digits: u32,
    /// This device's role.
    pub role: SasRole,
    /// First two bytes of SHA-256 of the peer's public key.
    pub peer_fp: u16,
    /// Mailbox state.
    pub state: SasState,
}

impl SasMail {
    fn pack(&self) -> [u32; 3] {
        let mut meta = 0;
        put(&mut meta, 0, 1, self.role as u32);
        put(&mut meta, 1, 16, u32::from(self.peer_fp));
        put(&mut meta, 17, 3, self.state as u32);
        [self.gen, self.digits, meta]
    }

    fn unpack(w: [u32; 3]) -> Self {
        SasMail {
            gen: w[0],
            digits: w[1] % 100_000_000,
            role: if get(w[2], 0, 1) == 1 {
                SasRole::Joiner
            } else {
                SasRole::Sponsor
            },
            peer_fp: get(w[2], 1, 16) as u16,
            state: SasState::from_bits(get(w[2], 17, 3)),
        }
    }
}

/// The SAS mailbox (written by core1 only).
pub static SAS_MAILBOX: SeqLock<3> = SeqLock::new();

/// The current mailbox value (all zero = nothing).
pub fn sas_read() -> SasMail {
    sas_read_from(&SAS_MAILBOX)
}

/// Show a new code.  It replaces any earlier one (a new `gen`); `digits`
/// is reduced modulo 10^8.  Core1 only.
pub fn sas_publish(digits: u32, role: SasRole, peer_fp: u16) {
    sas_publish_to(&SAS_MAILBOX, digits, role, peer_fp);
}

/// End a pending code with `state` (completion, failure, session end,
/// SELECT of another applet, INITIALIZE, a newly pinned peer).  No effect
/// when no code is pending.  Core1 only.
pub fn sas_clear(state: SasState) {
    sas_clear_in(&SAS_MAILBOX, state);
}

fn sas_read_from(mb: &SeqLock<3>) -> SasMail {
    mb.read().map(SasMail::unpack).unwrap_or_default()
}

fn sas_publish_to(mb: &SeqLock<3>, digits: u32, role: SasRole, peer_fp: u16) {
    let cur = sas_read_from(mb);
    mb.write(
        SasMail {
            gen: cur.gen.wrapping_add(1),
            digits: digits % 100_000_000,
            role,
            peer_fp,
            state: SasState::Pending,
        }
        .pack(),
    );
}

fn sas_clear_in(mb: &SeqLock<3>, state: SasState) {
    let cur = sas_read_from(mb);
    if cur.state != SasState::Pending {
        return;
    }
    mb.write(
        SasMail {
            digits: 0,
            state,
            ..cur
        }
        .pack(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot {
            session: Session {
                epoch_lo: 0xA5,
                applet: Applet::Pgp,
                auth: auth::PGP_PW3 | auth::HSM_USER,
                oneshot: oneshot::PGP_SIG_SINGLE,
                pri_left: 2,
                pri_max: 15,
                blocked: blocked::PIV,
            },
            activity: Activity {
                op_seq: 0xFE,
                op: OpCode::Enroll,
                state: OpState::Done,
                result: OpResult::Error,
                algo: algo::X25519,
                key_ref: 0x9C,
                hint: hint::PGP_SINGLE_USE,
            },
            inventory: Inventory {
                keys_hsm: 200,
                keys_piv: 15,
                keys_pgp: 3,
                domain: DomainState::Revoked,
                members: 63,
            },
            health: Health {
                domain_id_hi16: 0x3F9A,
                flags: health::PROVISIONED | health::STORE_WRITE_FAILED,
            },
            last_sw: 0x6581,
        }
    }

    #[test]
    fn pack_round_trip() {
        let s = sample();
        assert_eq!(Snapshot::unpack(s.pack()), s);
        assert_eq!(
            Snapshot::unpack(Snapshot::default().pack()),
            Snapshot::default()
        );
        // Every field at its maximum survives without bleeding.
        let words = s.pack();
        assert_eq!(words[0] >> 30, 0);
        assert_eq!(words[1] >> 31, 0);
        assert_eq!(words[2] >> 22, 0);
        assert_eq!(words[3] >> 22, 0);
    }

    #[test]
    fn seqlock_reads_what_was_written() {
        let l: SeqLock<3> = SeqLock::new();
        assert_eq!(l.writes(), 0);
        l.write([1, 2, 3]);
        l.write([4, 5, 6]);
        assert_eq!(l.read(), Some([4, 5, 6]));
        assert_eq!(l.writes(), 2);
    }

    #[test]
    fn seqlock_reader_gives_up_mid_write() {
        let l: SeqLock<1> = SeqLock::new();
        l.seq.store(1, Ordering::Relaxed); // a writer that never finishes
        assert_eq!(l.read(), None);
    }

    #[test]
    fn sas_mail_round_trip_and_clear() {
        let mb: SeqLock<3> = SeqLock::new();
        assert_eq!(sas_read_from(&mb).state, SasState::None);
        sas_clear_in(&mb, SasState::Cancelled); // nothing pending: no effect
        assert_eq!(sas_read_from(&mb).state, SasState::None);
        sas_publish_to(&mb, 1_234_567_890, SasRole::Joiner, 0x04AA);
        let m = sas_read_from(&mb);
        assert_eq!(m.state, SasState::Pending);
        assert_eq!(m.digits, 34_567_890);
        assert_eq!(m.role, SasRole::Joiner);
        assert_eq!(m.peer_fp, 0x04AA);
        let gen = m.gen;
        sas_publish_to(&mb, 12_345_678, SasRole::Sponsor, 0x7E21);
        assert_eq!(sas_read_from(&mb).gen, gen.wrapping_add(1));
        sas_clear_in(&mb, SasState::Expired);
        let m = sas_read_from(&mb);
        assert_eq!(m.state, SasState::Expired);
        assert_eq!(m.digits, 0, "the code never outlives its session");
        sas_clear_in(&mb, SasState::Cancelled); // not pending any more
        assert_eq!(sas_read_from(&mb).state, SasState::Expired);
    }

    #[test]
    fn apdu_start_never_reads_idle() {
        set_apdu_started(Some(0));
        assert_eq!(APDU_STARTED_MS.load(Ordering::Relaxed), 1);
        set_apdu_started(None);
        assert_eq!(APDU_STARTED_MS.load(Ordering::Relaxed), 0);
    }
}
