//! Sliceable RSA key generation (FIPS 186-5 Appendix A.1.3 with the
//! Appendix B.3 primality tests).
//!
//! The generator is a state machine.  [`KeyGen::step`] performs bounded
//! *units* of work — one Montgomery multiplication, one chunk of trial
//! division, one random draw — and asks its [`Budget`] before every unit
//! whether to stop.  All progress lives in the `KeyGen` itself (about
//! 9.5 KB, kept in static RAM by its owner, never on the stack), so the
//! caller can stop between any two units, run something else, and resume
//! later with the same result: for a given RNG stream the key does not
//! depend on where it was interrupted (host-tested).
//!
//! # Procedure (per prime, `k = nlen/2` bits)
//! 1. Draw `k` random bits from the DRBG, set the two top bits
//!    (A.1.3 step 4.2.1 — this makes `p ≥ ¾·2^k > √2·2^(k−1)`, step 4.4)
//!    and the low bit.  Every attempt is a fresh draw (A.1.3 step 4.2);
//!    there is no incremental search.
//! 2. `gcd(p − 1, e) = 1`, i.e. `p mod e ≠ 1` (`e = 65537` is prime; step
//!    4.5).  For `q` also `|p − q| > 2^(k−100)` (step 5.5).
//! 3. Trial division by the odd primes below 2^14 (B.3, "optional trial
//!    division", limit between 10^3 and 10^5).
//! 4. Miller-Rabin to base 2: an extra, cheap filter (not counted below).
//! 5. Miller-Rabin with `t` DRBG bases (B.3.1), `t` from FIPS 186-5
//!    Table B.1, the stricter column: 5 rounds for 1024-bit primes
//!    (error ≤ 2^-112), 4 for 1536-bit (≤ 2^-128), 4 for 2048-bit
//!    (≤ 2^-144).
//! 6. The Lucas test of B.3.3 (Baillie-PSW together with step 4), which
//!    Table B.1's note recommends when the M-R error definition "is not
//!    conservative enough".  The perfect-square check of B.3.3 step 1 is
//!    replaced by an equivalent bound: a square `C` has `(D/C) ∈ {0, 1}`
//!    for every `D`, so the search for `(D/C) = −1` gives up after
//!    [`MAX_LUCAS_D`] values and reports COMPOSITE — a square can never
//!    pass, and a prime is at worst rejected (and another one drawn).
//! 7. `d = e⁻¹ mod λ(n)`, `λ = lcm(p−1, q−1)`; regenerate unless
//!    `2^(nlen/2) < d` (B.3.1 / A.1.1).  `dP`, `dQ`, `qInv` are computed
//!    and each is checked by multiplying back.
//! 8. Pairwise-consistency test: a CRT signature `s` of a random message
//!    `m` with `(p, q, dP, dQ, qInv)`, verified as `s^e mod n == m` with a
//!    Montgomery context on `n` itself.  A key that fails is discarded.
//!
//! # Side channels
//! Everything done to the *final* primes and the private key is
//! constant-time — no branch, memory index or `UDIV`/`SDIV` (data-dependent
//! on the Cortex-M33) on secret data: Montgomery arithmetic; exponents in
//! fixed 4-bit windows over their full word length with a masked table
//! lookup; the Miller-Rabin squaring loop (a fixed [`MR_SQUARINGS`]
//! squarings whatever `a = ν2(w−1)` is, the outcome accumulated in a mask);
//! the Lucas chain (masked select per bit); `ν2(w−1)` and the shift by it;
//! `gcd(p−1, q−1)` (fixed-count binary GCD steps on the odd parts, the
//! common power of two by masked trailing-zero counts); `d`, dP, dQ (`m mod
//! e` and the division by `e` and by `g` multiply by a reciprocal; `e`'s
//! inverse modulo `m mod e` is Fermat's `r^(e−2)` with a public exponent);
//! qInv (Fermat, windowed); the `|p − q|` and `d > 2^(nlen/2)` checks
//! (borrow of a subtraction); the pairwise sign.
//!
//! What still depends on secret data, and why it is acceptable:
//! - **Rejection.**  Whether a candidate is rejected — and *where* (which
//!   trial-division prime divides it, which Miller-Rabin round or the
//!   Lucas test fails, the `gcd(p−1, e)` / `|p − q|` / `d` size checks) —
//!   is visible in the time a candidate takes.  A rejected candidate is
//!   discarded and independent of the next draw, so this reveals nothing
//!   about the key.  The accepted candidate always runs every step to the
//!   end.
//! - **Miller-Rabin base redraws.**  B.3.1 step 4.2 redraws a base outside
//!   `[2, w−2]`; how often depends on how far `w` is below `2^k` (at most
//!   25 % per draw here, `w ≥ ¾·2^k`) — a statistical hint about the top
//!   bits of `p`/`q` from 4–5 samples, far below anything usable.
//! - **The Lucas `D` search** (B.3.3 step 2): which `D` is selected depends
//!   on the Jacobi symbols `(D/w)` for `D = 5, −7, 9, …` — on average under
//!   two of them, i.e. a bit or two of quadratic-residue information about
//!   `p` mod small numbers.  The residues `w mod |D|` are computed in
//!   constant time; the small Jacobi computation is not.
//! - **DER lengths.**  PKCS#1 minimal INTEGER encoding makes the byte
//!   length of d, dP, dQ, qInv visible (it is in the stored key's length);
//!   this is inherent to the format and the same for every implementation.
//!
//! //! # Units
//! The largest units are one trial-division chunk (128 primes over the
//! candidate), one chunk of Montgomery setup (64 modular doublings), one
//! Lucas bit (5 modular multiplications) and the `d` derivation (a handful
//! of `nlen`-bit multiplications and divisions by small numbers).  See
//! `docs/SECURITY_SUMMARY.md` ("RSA key pool") for measured sizes.

// Index loops mirror the textbook algorithms (several arrays per index).
#![allow(clippy::needless_range_loop)]

use rand_core::RngCore;
use zeroize::Zeroize;

use super::bignum as bn;

/// Largest prime: 2048 bits (RSA-4096).
pub const MAX_PW: usize = 64;
/// Largest modulus: 4096 bits.
pub const MAX_NW: usize = 2 * MAX_PW;
/// The public exponent.
pub const E: u32 = 65_537;

/// Exponent window width.
const WINDOW: usize = 4;
/// Window table entries.
const TABLE: usize = 1 << WINDOW;
/// Scratch words: the window table, or the Lucas / GCD / verification
/// temporaries that share it.
const SCRATCH: usize = TABLE * MAX_PW;
/// Trial-division primes per unit.
const TD_CHUNK: usize = 128;
/// Modular doublings per Montgomery-setup unit.
const SETUP_CHUNK: usize = 64;
/// Binary-GCD iterations per unit.
const GCD_CHUNK: usize = 32;
/// Lucas `D` values tried before giving up (see the module docs, step 6).
pub const MAX_LUCAS_D: u32 = 1000;
/// Squarings after each Miller-Rabin exponentiation: always this many, so
/// the time does not reveal `a = ν2(w − 1)`.  A candidate with `a ≥ 64`
/// (probability 2^-63) can be wrongly rejected — never wrongly accepted.
pub const MR_SQUARINGS: usize = 64;
/// `ct_recip(E)`.
const E_RECIP: u32 = bn::ct_recip(E);
/// Keys discarded by an internal check before the generator gives up
/// (a fault, not bad luck: every check passes for a correct implementation).
const MAX_FAILURES: u32 = 3;

// ─── Trial-division primes ───────────────────────────────────────────────────

/// Trial-division bound (exclusive).
pub const TD_LIMIT: usize = 1 << 14;

const fn sieve() -> [bool; TD_LIMIT] {
    let mut composite = [false; TD_LIMIT];
    composite[0] = true;
    composite[1] = true;
    let mut i = 2;
    while i * i < TD_LIMIT {
        if !composite[i] {
            let mut j = i * i;
            while j < TD_LIMIT {
                composite[j] = true;
                j += i;
            }
        }
        i += 1;
    }
    composite
}

const fn count_odd_primes() -> usize {
    let c = sieve();
    let mut n = 0;
    let mut i = 3;
    while i < TD_LIMIT {
        if !c[i] {
            n += 1;
        }
        i += 2;
    }
    n
}

/// Number of odd primes below [`TD_LIMIT`].
pub const NUM_SMALL_PRIMES: usize = count_odd_primes();

const fn small_primes() -> [u16; NUM_SMALL_PRIMES] {
    let c = sieve();
    let mut out = [0u16; NUM_SMALL_PRIMES];
    let mut n = 0;
    let mut i = 3;
    while i < TD_LIMIT {
        if !c[i] {
            out[n] = i as u16;
            n += 1;
        }
        i += 2;
    }
    out
}

/// The odd primes below [`TD_LIMIT`], ascending.
pub static SMALL_PRIMES: [u16; NUM_SMALL_PRIMES] = small_primes();

const fn small_recips() -> [u32; NUM_SMALL_PRIMES] {
    let p = small_primes();
    let mut out = [0u32; NUM_SMALL_PRIMES];
    let mut i = 0;
    while i < NUM_SMALL_PRIMES {
        out[i] = u32::MAX / p[i] as u32;
        i += 1;
    }
    out
}

/// `floor((2^32−1)/p)` for each of [`SMALL_PRIMES`] (constant-time trial
/// division by multiplication).
static SMALL_RECIPS: [u32; NUM_SMALL_PRIMES] = small_recips();

// ─── Budget ──────────────────────────────────────────────────────────────────

/// Decides when [`KeyGen::step`] returns.
pub trait Budget {
    /// Asked before every unit of work: `true` stops the step there.
    fn should_yield(&mut self) -> bool;
}

/// Never yields (run to completion).
pub struct Unlimited;

impl Budget for Unlimited {
    fn should_yield(&mut self) -> bool {
        false
    }
}

/// Yields after a fixed number of units.
pub struct Units(pub u32);

impl Budget for Units {
    fn should_yield(&mut self) -> bool {
        if self.0 == 0 {
            return true;
        }
        self.0 -= 1;
        false
    }
}

/// Result of a [`KeyGen::step`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Stopped by the budget; call again.
    Pending,
    /// A key is ready ([`KeyGen::write_der`] and friends).
    Ready,
    /// Nothing to do (never started, or reset).
    Idle,
    /// Gave up: FIPS 186-5 A.1.3's iteration limit, or repeated failed
    /// self-checks.  [`KeyGen::reset`] before the next start.
    Failed,
}

/// Counters for benchmarks and the status APDU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Montgomery multiplications modulo a prime candidate or prime.
    pub modmul: u64,
    /// Montgomery squarings modulo a prime candidate or prime.
    pub modsqr: u64,
    /// Montgomery multiplications modulo `n` (pairwise test).
    pub modmul_n: u64,
    /// Candidates drawn.
    pub candidates: u32,
    /// Candidates that reached Miller-Rabin base 2.
    pub mr_base2: u32,
    /// Units performed.
    pub units: u64,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Draw,
    Trial,
    Setup,
    Base2Start,
    Base2,
    Base2Sq,
    MrDraw,
    Table,
    Exp,
    MrCheck,
    MrSq,
    LucasSetup,
    Lucas,
    Accept,
    GcdStart,
    Gcd,
    Derive,
    SqStart,
    SqDone,
    QinvStart,
    QinvDone,
    SpStart,
    SpDone,
    NSetup,
    VerifyStart,
    Verify,
    Ready,
    Failed,
}

/// The sliceable generator.  See the module docs.
pub struct KeyGen {
    /// Modulus bits (0 when idle).
    nlen: u32,
    /// Words per prime.
    pw: usize,
    phase: Phase,
    /// Generating `q` (else `p`).
    target_q: bool,
    /// Phase-local counters.
    idx: usize,
    sub: usize,
    /// Miller-Rabin round with a DRBG base.
    round: u32,
    /// Trailing zero bits of `w − 1` (secret: only used through masks).
    mr_a: u32,
    /// Miller-Rabin outcome so far: all-ones = passes.
    mr_pass: u32,
    /// Common power of two of `p − 1` and `q − 1` (secret).
    gcd_k: u32,
    /// Draws for the current prime (A.1.3 iteration limit).
    draws: u32,
    /// Internal-check failures since `start`.
    failures: u32,
    /// Phase after a Montgomery setup / exponentiation.
    after_setup: Phase,
    after_exp: Phase,
    /// Lucas `D`.
    lucas_d: i32,
    /// `gcd(p − 1, q − 1)`.
    g: u32,

    /// Current Montgomery modulus: the candidate, then `q` or `p`.
    w: [u32; MAX_PW],
    minv: u32,
    one: [u32; MAX_PW],
    rr: [u32; MAX_PW],
    mone: [u32; MAX_PW],
    acc: [u32; MAX_PW],
    base: [u32; MAX_PW],
    exp: [u32; MAX_PW],
    exp_bits: usize,
    scratch: [u32; SCRATCH],

    p: [u32; MAX_PW],
    q: [u32; MAX_PW],
    n: [u32; MAX_NW],
    d: [u32; MAX_NW],
    dp: [u32; MAX_PW],
    dq: [u32; MAX_PW],
    qinv: [u32; MAX_PW],
    msg: [u32; MAX_PW],
    sp: [u32; MAX_PW],
    sq: [u32; MAX_PW],

    /// Counters since `start`.
    pub stats: Stats,
}

/// `K` mutable, non-overlapping `stride`-word slices of `s`.
fn split<const K: usize>(s: &mut [u32], stride: usize) -> [&mut [u32]; K] {
    let mut it = s.chunks_mut(stride);
    core::array::from_fn(|_| it.next().expect("scratch too small"))
}

/// Miller-Rabin rounds with DRBG bases for a `bits`-bit prime: FIPS 186-5
/// Table B.1, the column with the lower error probability (2^-112 for
/// 1024-bit, 2^-128 for 1536-bit, 2^-144 for 2048-bit primes).  Smaller
/// primes (host tests only) get the 1024-bit count.
pub const fn mr_rounds(bits: usize) -> u32 {
    if bits >= 1536 {
        4
    } else {
        5
    }
}

impl KeyGen {
    /// An idle generator (all zero; fits a `static`).
    pub const fn new() -> Self {
        KeyGen {
            nlen: 0,
            pw: 0,
            phase: Phase::Idle,
            target_q: false,
            idx: 0,
            sub: 0,
            round: 0,
            mr_a: 0,
            mr_pass: 0,
            gcd_k: 0,
            draws: 0,
            failures: 0,
            after_setup: Phase::Idle,
            after_exp: Phase::Idle,
            lucas_d: 0,
            g: 0,
            w: [0; MAX_PW],
            minv: 0,
            one: [0; MAX_PW],
            rr: [0; MAX_PW],
            mone: [0; MAX_PW],
            acc: [0; MAX_PW],
            base: [0; MAX_PW],
            exp: [0; MAX_PW],
            exp_bits: 0,
            scratch: [0; SCRATCH],
            p: [0; MAX_PW],
            q: [0; MAX_PW],
            n: [0; MAX_NW],
            d: [0; MAX_NW],
            dp: [0; MAX_PW],
            dq: [0; MAX_PW],
            qinv: [0; MAX_PW],
            msg: [0; MAX_PW],
            sp: [0; MAX_PW],
            sq: [0; MAX_PW],
            stats: Stats {
                modmul: 0,
                modsqr: 0,
                modmul_n: 0,
                candidates: 0,
                mr_base2: 0,
                units: 0,
            },
        }
    }

    /// Begin a new key of `nlen` bits (a multiple of 128, 512..=4096),
    /// discarding (and wiping) any progress.
    pub fn start(&mut self, nlen: u32) -> bool {
        if nlen % 128 != 0 || !(512..=4096).contains(&nlen) {
            return false;
        }
        self.wipe();
        self.nlen = nlen;
        self.pw = nlen as usize / 64;
        self.phase = Phase::Draw;
        true
    }

    /// Modulus bits of the key in progress (0 if idle).
    pub fn nlen(&self) -> u32 {
        if matches!(self.phase, Phase::Idle | Phase::Failed) {
            0
        } else {
            self.nlen
        }
    }

    /// Whether a key is ready to be taken.
    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    /// Whether the generator is working on a key (started, not ready).
    pub fn is_busy(&self) -> bool {
        !matches!(self.phase, Phase::Idle | Phase::Ready | Phase::Failed)
    }

    /// Wipe everything and go idle.
    pub fn reset(&mut self) {
        self.wipe();
    }

    /// Zeroize every array that can hold key material (candidates,
    /// primes, exponents, CRT values, Montgomery contexts, temporaries).
    fn wipe_secrets(&mut self) {
        self.w.zeroize();
        self.one.zeroize();
        self.rr.zeroize();
        self.mone.zeroize();
        self.acc.zeroize();
        self.base.zeroize();
        self.exp.zeroize();
        self.scratch.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.n.zeroize();
        self.d.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        self.msg.zeroize();
        self.sp.zeroize();
        self.sq.zeroize();
        self.minv = 0;
        self.g = 0;
        self.gcd_k = 0;
        self.mr_a = 0;
        self.mr_pass = 0;
        self.lucas_d = 0;
    }

    /// Every key-material array is zero (test probe).
    #[cfg(test)]
    pub(crate) fn holds_no_secrets(&self) -> bool {
        [
            &self.w[..],
            &self.one,
            &self.rr,
            &self.mone,
            &self.acc,
            &self.base,
            &self.exp,
            &self.scratch,
            &self.p,
            &self.q,
            &self.n,
            &self.d,
            &self.dp,
            &self.dq,
            &self.qinv,
            &self.msg,
            &self.sp,
            &self.sq,
        ]
        .iter()
        .all(|a| a.iter().all(|&x| x == 0))
            && self.g == 0
            && self.minv == 0
    }

    fn wipe(&mut self) {
        self.wipe_secrets();
        self.nlen = 0;
        self.pw = 0;
        self.phase = Phase::Idle;
        self.target_q = false;
        self.idx = 0;
        self.sub = 0;
        self.round = 0;
        self.mr_a = 0;
        self.mr_pass = 0;
        self.gcd_k = 0;
        self.draws = 0;
        self.failures = 0;
        self.exp_bits = 0;
        self.after_setup = Phase::Idle;
        self.after_exp = Phase::Idle;
        self.stats = Stats::default();
    }

    /// Run units until the budget says stop or the key is ready.
    pub fn step(&mut self, rng: &mut dyn RngCore, budget: &mut dyn Budget) -> Poll {
        loop {
            match self.phase {
                Phase::Idle => return Poll::Idle,
                Phase::Ready => return Poll::Ready,
                Phase::Failed => return Poll::Failed,
                _ => {}
            }
            if budget.should_yield() {
                return Poll::Pending;
            }
            self.stats.units += 1;
            self.unit(rng);
        }
    }

    // ── helpers ──

    fn mul(&mut self, which: Op) {
        let pw = self.pw;
        self.stats.modsqr += 1;
        match which {
            Op::AccSqr => bn::mont_sqr_assign(&mut self.acc[..pw], &self.w[..pw], self.minv),
        }
    }

    /// `out = x · R mod w` (into Montgomery form, in `base`).
    fn load_base(&mut self, x: &[u32; MAX_PW]) {
        let pw = self.pw;
        self.stats.modmul += 1;
        bn::mont_mul(
            &mut self.base[..pw],
            &x[..pw],
            &self.rr[..pw],
            &self.w[..pw],
            self.minv,
        );
    }

    fn fail_restart(&mut self) {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            let failures = self.failures;
            self.wipe();
            self.failures = failures;
            self.phase = Phase::Failed;
            return;
        }
        self.restart_key();
    }

    /// Discard every secret of the attempt and begin again (keeps
    /// `failures` and stats).
    fn restart_key(&mut self) {
        self.wipe_secrets();
        self.target_q = false;
        self.draws = 0;
        self.phase = Phase::Draw;
    }

    fn reject_candidate(&mut self) {
        self.phase = Phase::Draw;
    }

    fn begin_setup(&mut self, next: Phase) {
        self.after_setup = next;
        self.idx = 0;
        self.phase = Phase::Setup;
    }

    fn begin_exp(&mut self, next: Phase) {
        // Base (Montgomery form) and exponent are in place.
        self.after_exp = next;
        self.idx = 0;
        self.phase = Phase::Table;
    }

    // ── one unit ──

    fn unit(&mut self, rng: &mut dyn RngCore) {
        let pw = self.pw;
        let k = 32 * pw; // prime bits
        match self.phase {
            Phase::Idle | Phase::Ready | Phase::Failed => {}

            Phase::Draw => {
                self.draws += 1;
                self.stats.candidates += 1;
                // A.1.3 steps 4.7 / 5.8.
                let limit = if self.target_q {
                    10 * self.nlen
                } else {
                    5 * self.nlen
                };
                if self.draws > limit {
                    self.wipe();
                    self.phase = Phase::Failed;
                    return;
                }
                let mut bytes = [0u8; 4 * MAX_PW];
                rng.fill_bytes(&mut bytes[..4 * pw]);
                bn::from_be_bytes(&mut self.w[..pw], &bytes[..4 * pw]);
                bytes.zeroize();
                self.w[pw - 1] |= 0xC000_0000;
                self.w[0] |= 1;
                // gcd(w − 1, e) = 1  ⇔  w mod e ≠ 1 (e prime).  Constant-time
                // remainder; the branch only rejects.
                if bn::ct_rem_small(&self.w[..pw], E, E_RECIP) == 1 {
                    return;
                }
                if self.target_q && !self.far_from_p() {
                    return;
                }
                self.idx = 0;
                self.phase = Phase::Trial;
            }

            Phase::Trial => {
                // Constant-time remainders (reciprocal multiplication, no
                // UDIV on the candidate).  The early exit happens only for a
                // candidate that is rejected; the accepted one is divided by
                // every prime.
                let end = (self.idx + TD_CHUNK).min(NUM_SMALL_PRIMES);
                for i in self.idx..end {
                    let r = bn::ct_rem_small(
                        &self.w[..pw],
                        u32::from(SMALL_PRIMES[i]),
                        SMALL_RECIPS[i],
                    );
                    if r == 0 {
                        self.reject_candidate();
                        return;
                    }
                }
                self.idx = end;
                if end == NUM_SMALL_PRIMES {
                    self.begin_setup(Phase::Base2Start);
                }
            }

            Phase::Setup => {
                // R mod w and R² mod w by modular doubling.  With the top
                // bit set (every real candidate) R mod w = R − w directly;
                // otherwise (host tests on small numbers) start from 1.
                let fast = self.w[pw - 1] >> 31 == 1;
                let total = if fast { 32 * pw } else { 64 * pw };
                if self.idx == 0 {
                    self.minv = bn::neg_inv32(self.w[0]);
                    if fast {
                        bn::r_mod(&self.w[..pw], &mut self.one[..pw]);
                        self.rr[..pw].copy_from_slice(&self.one[..pw]);
                    } else {
                        self.rr[..pw].fill(0);
                        self.rr[0] = 1;
                    }
                }
                let end = (self.idx + SETUP_CHUNK).min(total);
                for i in self.idx..end {
                    if !fast && i == 32 * pw {
                        self.one[..pw].copy_from_slice(&self.rr[..pw]);
                    }
                    bn::mod_double(&mut self.rr[..pw], &self.w[..pw]);
                }
                self.idx = end;
                if end == total {
                    // mone = w − one  (−1 in Montgomery form)
                    self.mone[..pw].copy_from_slice(&self.w[..pw]);
                    bn::sub_assign(&mut self.mone[..pw], &self.one[..pw]);
                    self.phase = self.after_setup;
                }
            }

            Phase::Base2Start => {
                self.stats.mr_base2 += 1;
                // exp = (w − 1) / 2^a
                self.exp[..pw].copy_from_slice(&self.w[..pw]);
                bn::sub_small(&mut self.exp[..pw], 1);
                self.mr_a = bn::ct_tz(&self.exp[..pw]);
                bn::ct_shr(&mut self.exp[..pw], self.mr_a);
                self.exp_bits = k;
                self.acc[..pw].copy_from_slice(&self.one[..pw]);
                self.idx = k;
                self.phase = Phase::Base2;
            }

            Phase::Base2 => {
                // acc = acc² · 2^bit  (left to right, every bit, masked).
                self.mul(Op::AccSqr);
                let b = bn::bit(&self.exp[..pw], self.idx - 1);
                bn::mod_double_if(&mut self.acc[..pw], &self.w[..pw], b);
                self.idx -= 1;
                if self.idx == 0 {
                    self.begin_squarings(Phase::Base2Sq);
                }
            }

            Phase::Base2Sq | Phase::MrSq => {
                // z_j = z_{j−1}², j = 1 .. MR_SQUARINGS−1; the round passes
                // if z_0 = ±1 or z_j = −1 for some j < a.  (Once z = 1 it
                // stays 1, so the textbook "z = 1: composite" exit adds
                // nothing.)  Every squaring is done; `j < a` is a mask.
                self.mul(Op::AccSqr);
                let active = bn::ct_lt_mask_u32(self.sub as u32, self.mr_a);
                self.mr_pass |= active & bn::ct_eq_mask(&self.acc[..pw], &self.mone[..pw]);
                self.sub += 1;
                if self.sub == MR_SQUARINGS {
                    let pass = self.mr_pass != 0;
                    self.mr_pass = 0;
                    if !pass {
                        self.reject_candidate();
                    } else if self.phase == Phase::Base2Sq {
                        self.begin_random_rounds();
                    } else {
                        self.next_round();
                    }
                }
            }

            Phase::MrDraw => {
                // B.3.1 steps 4.1–4.2: wlen DRBG bits, 1 < b < w − 1.
                let mut bytes = [0u8; 4 * MAX_PW];
                rng.fill_bytes(&mut bytes[..4 * pw]);
                let mut b = [0u32; MAX_PW];
                bn::from_be_bytes(&mut b[..pw], &bytes[..4 * pw]);
                bytes.zeroize();
                // Keep wlen = len(w) bits: all of them for every real
                // candidate (its top bit is set — public); the bit length is
                // computed only for the small numbers of the host tests.
                let wlen = if self.w[pw - 1] >> 31 == 1 {
                    32 * pw
                } else {
                    bn::bit_len(&self.w[..pw])
                };
                for (i, word) in b[..pw].iter_mut().enumerate() {
                    let lo = 32 * i;
                    if lo >= wlen {
                        *word = 0;
                    } else if wlen - lo < 32 {
                        *word &= (1u32 << (wlen - lo)) - 1;
                    }
                }
                let mut wm1 = [0u32; MAX_PW];
                wm1[..pw].copy_from_slice(&self.w[..pw]);
                bn::sub_small(&mut wm1[..pw], 1);
                let mut two = [0u32; MAX_PW];
                two[0] = 2;
                // Constant-time range check; the branch only redraws (see the
                // module docs on base redraws).
                let ok = !bn::ct_lt(&b[..pw], &two[..pw]) & bn::ct_lt(&b[..pw], &wm1[..pw]);
                if ok != 0 {
                    self.load_base(&b);
                    // exp still holds (w − 1) / 2^a from Base2Start.
                    self.exp_bits = k;
                    self.begin_exp(Phase::MrCheck);
                }
                b.zeroize();
            }

            Phase::Table => {
                // table[i] = base^i (Montgomery form), stride pw.
                let i = self.idx;
                let t = &mut self.scratch[..TABLE * pw];
                if i == 0 {
                    t[..pw].copy_from_slice(&self.one[..pw]);
                    t[pw..2 * pw].copy_from_slice(&self.base[..pw]);
                    self.idx = 2;
                } else {
                    let (lo, hi) = t.split_at_mut(i * pw);
                    bn::mont_mul(
                        &mut hi[..pw],
                        &lo[(i - 1) * pw..i * pw],
                        &self.base[..pw],
                        &self.w[..pw],
                        self.minv,
                    );
                    self.stats.modmul += 1;
                    self.idx += 1;
                }
                if self.idx == TABLE {
                    // First (top) window: acc = table[window].
                    let windows = self.exp_bits.div_ceil(WINDOW);
                    let top = self.window(windows - 1);
                    bn::select_from_table(
                        &mut self.acc[..pw],
                        &self.scratch[..TABLE * pw],
                        TABLE,
                        top,
                    );
                    self.idx = windows - 1; // windows still to process
                    self.sub = 0;
                    self.phase = if self.idx == 0 {
                        self.after_exp
                    } else {
                        Phase::Exp
                    };
                }
            }

            Phase::Exp => {
                if self.sub < WINDOW {
                    self.mul(Op::AccSqr);
                    self.sub += 1;
                } else {
                    let win = self.window(self.idx - 1);
                    let mut t = [0u32; MAX_PW];
                    bn::select_from_table(&mut t[..pw], &self.scratch[..TABLE * pw], TABLE, win);
                    bn::mont_mul_assign(&mut self.acc[..pw], &t[..pw], &self.w[..pw], self.minv);
                    self.stats.modmul += 1;
                    t.zeroize();
                    self.idx -= 1;
                    self.sub = 0;
                    if self.idx == 0 {
                        self.phase = self.after_exp;
                    }
                }
            }

            Phase::MrCheck => self.begin_squarings(Phase::MrSq),

            Phase::LucasSetup => self.lucas_setup(),
            Phase::Lucas => self.lucas_bit(),

            Phase::Accept => {
                if self.target_q {
                    self.q[..pw].copy_from_slice(&self.w[..pw]);
                    self.phase = Phase::GcdStart;
                } else {
                    self.p[..pw].copy_from_slice(&self.w[..pw]);
                    self.target_q = true;
                    self.draws = 0;
                    self.phase = Phase::Draw;
                }
            }

            Phase::GcdStart => {
                // gcd(p−1, q−1) = 2^min(sa, sb) · gcd(odd parts), all
                // constant-time: masked trailing-zero counts and shifts,
                // then fixed-count binary-GCD steps.
                let [a, b] = split::<2>(&mut self.scratch[..2 * MAX_PW], MAX_PW);
                let (a, b) = (&mut a[..pw], &mut b[..pw]);
                a.copy_from_slice(&self.p[..pw]);
                b.copy_from_slice(&self.q[..pw]);
                bn::sub_small(a, 1);
                bn::sub_small(b, 1);
                let sa = bn::ct_tz(a);
                let sb = bn::ct_tz(b);
                bn::ct_shr(a, sa);
                bn::ct_shr(b, sb);
                self.gcd_k = sb ^ ((sa ^ sb) & bn::ct_lt_mask_u32(sa, sb));
                self.idx = 0;
                self.phase = Phase::Gcd;
            }

            Phase::Gcd => {
                let [a, b] = split::<2>(&mut self.scratch[..2 * MAX_PW], MAX_PW);
                let (a, b) = (&mut a[..pw], &mut b[..pw]);
                let total = 2 * 32 * pw;
                let end = (self.idx + GCD_CHUNK).min(total);
                for _ in self.idx..end {
                    bn::ct_gcd_step(a, b);
                }
                self.idx = end;
                if end == total {
                    // b = gcd of the odd parts; g = b · 2^k must be below
                    // 2^17 (the small-divisor routines).  The test is a
                    // mask; the branch only rejects q (practically never).
                    let k = self.gcd_k;
                    let high = bn::ct_is_zero(&b[1..]);
                    let g64 = u64::from(b[0]) << (k & 31);
                    let small = high
                        & bn::ct_lt_mask_u32(k, 17)
                        & bn::ct_zero_mask_u32((g64 >> 17) as u32 | (g64 >> 49) as u32);
                    if small != 0 {
                        self.g = g64 as u32;
                        self.phase = Phase::Derive;
                    } else {
                        self.q.zeroize();
                        self.draws = 0;
                        self.phase = Phase::Draw;
                    }
                    a.zeroize();
                    b.zeroize();
                }
            }

            Phase::Derive => self.derive(rng),

            Phase::SqStart => {
                let msg = self.msg;
                self.load_base(&msg);
                self.exp[..pw].copy_from_slice(&self.dq[..pw]);
                self.exp_bits = k;
                self.begin_exp(Phase::SqDone);
            }

            Phase::SqDone => {
                bn::from_mont(&mut self.acc[..pw], &self.w[..pw], self.minv);
                self.sq[..pw].copy_from_slice(&self.acc[..pw]);
                self.w[..pw].copy_from_slice(&self.p[..pw]);
                self.begin_setup(Phase::QinvStart);
            }

            Phase::QinvStart => {
                // base = q mod p (q < 2p: at most one subtraction).
                let mut qm = [0u32; MAX_PW];
                qm[..pw].copy_from_slice(&self.q[..pw]);
                reduce_once(&mut qm[..pw], &self.p[..pw]);
                self.load_base(&qm);
                qm.zeroize();
                // exp = p − 2 (Fermat: q^(p−2) = q⁻¹ mod p).
                self.exp[..pw].copy_from_slice(&self.p[..pw]);
                bn::sub_small(&mut self.exp[..pw], 2);
                self.exp_bits = k;
                self.begin_exp(Phase::QinvDone);
            }

            Phase::QinvDone => {
                bn::from_mont(&mut self.acc[..pw], &self.w[..pw], self.minv);
                self.qinv[..pw].copy_from_slice(&self.acc[..pw]);
                // Check qInv · q ≡ 1 (mod p).
                let mut qm = [0u32; MAX_PW];
                qm[..pw].copy_from_slice(&self.q[..pw]);
                reduce_once(&mut qm[..pw], &self.p[..pw]);
                let mut x = [0u32; MAX_PW];
                bn::mont_mul(
                    &mut x[..pw],
                    &self.qinv[..pw],
                    &self.rr[..pw],
                    &self.w[..pw],
                    self.minv,
                );
                bn::mont_mul_assign(&mut x[..pw], &qm[..pw], &self.w[..pw], self.minv);
                self.stats.modmul += 2;
                let mut one = [0u32; MAX_PW];
                one[0] = 1;
                let ok = bn::ct_eq(&x[..pw], &one[..pw]);
                qm.zeroize();
                x.zeroize();
                if ok {
                    self.phase = Phase::SpStart;
                } else {
                    self.fail_restart();
                }
            }

            Phase::SpStart => {
                let msg = self.msg;
                self.load_base(&msg);
                self.exp[..pw].copy_from_slice(&self.dp[..pw]);
                self.exp_bits = k;
                self.begin_exp(Phase::SpDone);
            }

            Phase::SpDone => {
                bn::from_mont(&mut self.acc[..pw], &self.w[..pw], self.minv);
                self.sp[..pw].copy_from_slice(&self.acc[..pw]);
                self.combine();
                self.idx = 0;
                self.phase = Phase::NSetup;
            }

            Phase::NSetup => {
                let nw = 2 * pw;
                let [none, nrr, _s, _sm, _acc] =
                    split::<5>(&mut self.scratch[..5 * MAX_NW], MAX_NW);
                let (none, nrr) = (&mut none[..nw], &mut nrr[..nw]);
                if self.idx == 0 {
                    bn::r_mod(&self.n[..nw], none);
                    nrr.copy_from_slice(none);
                }
                let total = 32 * nw;
                let end = (self.idx + SETUP_CHUNK).min(total);
                for _ in self.idx..end {
                    bn::mod_double(nrr, &self.n[..nw]);
                }
                self.idx = end;
                if end == total {
                    self.phase = Phase::VerifyStart;
                }
            }

            Phase::VerifyStart => {
                let nw = 2 * pw;
                let ninv = bn::neg_inv32(self.n[0]);
                let [_none, nrr, s, sm, acc] = split::<5>(&mut self.scratch[..5 * MAX_NW], MAX_NW);
                bn::mont_mul(&mut sm[..nw], &s[..nw], &nrr[..nw], &self.n[..nw], ninv);
                acc[..nw].copy_from_slice(&sm[..nw]);
                self.stats.modmul_n += 1;
                self.idx = 16; // e = 2^16 + 1
                self.phase = Phase::Verify;
            }

            Phase::Verify => {
                let nw = 2 * pw;
                let ninv = bn::neg_inv32(self.n[0]);
                let [_none, _nrr, _s, sm, acc] =
                    split::<5>(&mut self.scratch[..5 * MAX_NW], MAX_NW);
                let (sm, acc) = (&mut sm[..nw], &mut acc[..nw]);
                self.stats.modmul_n += 1;
                if self.idx > 0 {
                    bn::mont_sqr_assign(acc, &self.n[..nw], ninv);
                    self.idx -= 1;
                    return;
                }
                bn::mont_mul_assign(acc, sm, &self.n[..nw], ninv);
                bn::from_mont(acc, &self.n[..nw], ninv);
                let mut m = [0u32; MAX_NW];
                m[..pw].copy_from_slice(&self.msg[..pw]);
                let ok = bn::ct_eq(acc, &m[..nw]);
                m.zeroize();
                self.scratch.zeroize();
                if ok {
                    self.phase = Phase::Ready;
                } else {
                    self.fail_restart();
                }
            }
        }
    }

    /// After a Miller-Rabin exponentiation: record `z_0 = ±1` in the pass
    /// mask and start the fixed squaring loop.
    fn begin_squarings(&mut self, next: Phase) {
        let pw = self.pw;
        self.mr_pass = bn::ct_eq_mask(&self.acc[..pw], &self.one[..pw])
            | bn::ct_eq_mask(&self.acc[..pw], &self.mone[..pw]);
        self.sub = 1;
        self.phase = next;
    }

    /// Value of exponent window `i` (bits `4i .. 4i+4`).
    fn window(&self, i: usize) -> u32 {
        let mut v = 0;
        for b in 0..WINDOW {
            let pos = i * WINDOW + b;
            if pos < self.exp_bits {
                v |= bn::bit(&self.exp[..self.pw], pos) << b;
            }
        }
        v
    }

    fn begin_random_rounds(&mut self) {
        self.round = 0;
        self.phase = Phase::MrDraw;
    }

    fn next_round(&mut self) {
        self.round += 1;
        if self.round >= mr_rounds(32 * self.pw) {
            self.phase = Phase::LucasSetup;
        } else {
            self.phase = Phase::MrDraw;
        }
    }

    /// `|w − p| > 2^(k−100)` (A.1.3 step 5.5), constant-time.
    fn far_from_p(&self) -> bool {
        let pw = self.pw;
        let mut d1 = [0u32; MAX_PW];
        let mut d2 = [0u32; MAX_PW];
        d1[..pw].copy_from_slice(&self.w[..pw]);
        let br = bn::sub_assign(&mut d1[..pw], &self.p[..pw]); // w − p
        d2[..pw].copy_from_slice(&self.p[..pw]);
        bn::sub_assign(&mut d2[..pw], &self.w[..pw]); // p − w
        let mut diff = [0u32; MAX_PW];
        bn::ct_select(&mut diff[..pw], &d2[..pw], &d1[..pw], 0u32.wrapping_sub(br));
        let mut limit = [0u32; MAX_PW];
        let lb = 32 * pw - 100; // 2^(k−100)
        limit[lb / 32] = 1 << (lb % 32);
        let far = bn::ct_lt(&limit[..pw], &diff[..pw]);
        d1.zeroize();
        d2.zeroize();
        diff.zeroize();
        far != 0
    }

    /// B.3.3 step 2 (with the bound of the module docs) and the chain set-up.
    fn lucas_setup(&mut self) {
        let pw = self.pw;
        let w = &self.w[..pw];
        let mut found = None;
        let mut d: i32 = 5;
        for _ in 0..MAX_LUCAS_D {
            let a = d.unsigned_abs();
            // Constant-time residue; the small Jacobi symbol is not (see the
            // module docs).
            let r = bn::ct_rem_small(w, a, bn::ct_recip(a));
            // (D/w) = (±1/w)·(a/w);  (−1/w) = (−1)^((w−1)/2).
            let mut j = jacobi_small_over_big(a, r, w[0]);
            if d < 0 && w[0] & 3 == 3 {
                j = -j;
            }
            if j == 0 {
                // a shares a factor with w (w > a): composite.
                break;
            }
            if j == -1 {
                // gcd(w, (1 − D)/4) = 1
                let qd = ((1 - i64::from(d)) / 4).unsigned_abs() as u32;
                if qd <= 1 || bn::ct_gcd_u32(bn::ct_rem_small(w, qd, bn::ct_recip(qd)), qd) == 1 {
                    found = Some(d);
                    break;
                }
            }
            d = if d > 0 { -(d + 2) } else { -d + 2 };
        }
        let Some(d) = found else {
            self.reject_candidate();
            return;
        };
        self.lucas_d = d;
        // K = w + 1
        self.exp[..pw].copy_from_slice(w);
        bn::add_small(&mut self.exp[..pw], 1);
        // K < 2^k with bit k−1 set for every real candidate (top bit set —
        // public; w + 1 cannot carry out of an odd prime); the bit length is
        // computed only for the small numbers of the host tests.
        self.exp_bits = if self.w[pw - 1] >> 31 == 1 {
            32 * pw
        } else {
            bn::bit_len(&self.exp[..pw])
        };
        let [u, v, dm, ..] = split::<7>(&mut self.scratch[..7 * MAX_PW], MAX_PW);
        u[..pw].copy_from_slice(&self.one[..pw]);
        v[..pw].copy_from_slice(&self.one[..pw]);
        let mut a = [0u32; MAX_PW];
        a[0] = d.unsigned_abs();
        bn::mont_mul(
            &mut dm[..pw],
            &a[..pw],
            &self.rr[..pw],
            &self.w[..pw],
            self.minv,
        );
        self.stats.modmul += 1;
        if d < 0 {
            let mut z = [0u32; MAX_PW];
            z[..pw].copy_from_slice(&dm[..pw]);
            dm[..pw].fill(0);
            bn::mod_sub(&mut dm[..pw], &z[..pw], &self.w[..pw]);
        }
        self.idx = self.exp_bits - 1; // bits r−1 .. 0 still to process
        self.phase = Phase::Lucas;
    }

    /// One step of B.3.3 step 6 (for bit `idx − 1`).
    fn lucas_bit(&mut self) {
        let pw = self.pw;
        if self.idx == 0 {
            let [u, ..] = split::<7>(&mut self.scratch[..7 * MAX_PW], MAX_PW);
            let prime = bn::ct_is_zero(&u[..pw]) != 0;
            if prime {
                self.phase = Phase::Accept;
            } else {
                self.reject_candidate();
            }
            return;
        }
        let i = self.idx - 1;
        let kbit = bn::bit(&self.exp[..pw], i);
        let m = &self.w[..pw];
        let minv = self.minv;
        let [u, v, dm, ut, vt, x, y] = split::<7>(&mut self.scratch[..7 * MAX_PW], MAX_PW);
        let (u, v, dm, ut, vt, x, y) = (
            &mut u[..pw],
            &mut v[..pw],
            &mut dm[..pw],
            &mut ut[..pw],
            &mut vt[..pw],
            &mut x[..pw],
            &mut y[..pw],
        );
        // Utemp = U·V
        bn::mont_mul(ut, u, v, m, minv);
        // Vtemp = (V² + D·U²) / 2
        bn::mont_sqr(x, u, m, minv);
        bn::mont_mul_assign(x, dm, m, minv);
        bn::mont_sqr(vt, v, m, minv);
        bn::mod_add(vt, x, m);
        bn::mod_half(vt, m);
        // Bit set: U = (Utemp + Vtemp)/2, V = (Vtemp + D·Utemp)/2.
        y.copy_from_slice(ut);
        bn::mod_add(y, vt, m);
        bn::mod_half(y, m);
        bn::mont_mul(x, dm, ut, m, minv);
        bn::mod_add(x, vt, m);
        bn::mod_half(x, m);
        let mk = 0u32.wrapping_sub(kbit);
        for j in 0..pw {
            u[j] = (y[j] & mk) | (ut[j] & !mk);
            v[j] = (x[j] & mk) | (vt[j] & !mk);
        }
        self.stats.modmul += 3;
        self.stats.modsqr += 2;
        self.idx -= 1;
    }

    /// λ, d, dP, dQ, n and their checks (A.1.1 / B.3.1); then the PCT.
    fn derive(&mut self, rng: &mut dyn RngCore) {
        let pw = self.pw;
        let nw = 2 * pw;
        let nlen = self.nlen as usize;
        let g = self.g;

        // n = p · q, exactly nlen bits (n is public: variable-time is fine).
        bn::mul_into(&mut self.n[..nw], &self.p[..pw], &self.q[..pw]);
        if bn::bit_len(&self.n[..nw]) != nlen {
            self.fail_restart();
            return;
        }

        let [pm1, qm1g, lam, tmp] = split::<4>(&mut self.scratch[..4 * (MAX_NW + 1)], MAX_NW + 1);
        let (pm1, qm1g) = (&mut pm1[..pw], &mut qm1g[..pw]);
        let (lam, tmp) = (&mut lam[..nw + 1], &mut tmp[..nw + 1]);
        pm1.copy_from_slice(&self.p[..pw]);
        bn::sub_small(pm1, 1);
        qm1g.copy_from_slice(&self.q[..pw]);
        bn::sub_small(qm1g, 1);
        let r = bn::ct_divrem_small(qm1g, g, bn::ct_recip(g));
        // λ = (p − 1) · ((q − 1) / g)
        bn::mul_into(&mut lam[..nw], pm1, qm1g);
        lam[nw] = 0;
        if r != 0 {
            self.fail_restart();
            return;
        }

        // d = (k·λ + 1) / e with k·λ ≡ −1 (mod e), so 0 < d < λ.
        let ok_d = inverse_of_e(&lam[..nw], tmp, &mut self.d[..nw]);
        // dP = e⁻¹ mod (p − 1), dQ = e⁻¹ mod (q − 1) (each equals d mod p−1, q−1).
        let mut t2 = [0u32; MAX_PW + 1];
        let ok_dp = inverse_of_e(pm1, &mut t2[..pw + 1], &mut self.dp[..pw]);
        qm1g.copy_from_slice(&self.q[..pw]);
        bn::sub_small(qm1g, 1);
        let ok_dq = inverse_of_e(qm1g, &mut t2[..pw + 1], &mut self.dq[..pw]);
        t2.zeroize();
        if !(ok_d && ok_dp && ok_dq) {
            self.scratch.zeroize();
            self.fail_restart();
            return;
        }
        self.scratch.zeroize();

        // 2^(nlen/2) < d (B.3.1); otherwise new primes.  Constant-time
        // compare; the branch only restarts.
        let half = nlen / 2;
        let mut pow = [0u32; MAX_NW];
        pow[half / 32] = 1 << (half % 32);
        let big_enough = bn::ct_lt(&pow[..nw], &self.d[..nw]) != 0;
        if !big_enough {
            self.d.zeroize();
            self.dp.zeroize();
            self.dq.zeroize();
            self.restart_key();
            return;
        }

        // Pairwise-consistency message: 2 ≤ m < 2^(k−8) (below p and q).
        let mut bytes = [0u8; 4 * MAX_PW];
        rng.fill_bytes(&mut bytes[..4 * pw]);
        bn::from_be_bytes(&mut self.msg[..pw], &bytes[..4 * pw]);
        bytes.zeroize();
        self.msg[pw - 1] &= 0x00FF_FFFF;
        self.msg[0] |= 2;

        // Sign with CRT, starting modulo q.
        self.w[..pw].copy_from_slice(&self.q[..pw]);
        self.begin_setup(Phase::SqStart);
    }

    /// `s = sq + q · (qInv · (sp − sq) mod p)` into scratch (verify slot).
    fn combine(&mut self) {
        let pw = self.pw;
        let nw = 2 * pw;
        let p = &self.w[..pw]; // context is p
        let mut sqp = [0u32; MAX_PW];
        sqp[..pw].copy_from_slice(&self.sq[..pw]);
        reduce_once(&mut sqp[..pw], p);
        let mut diff = [0u32; MAX_PW];
        diff[..pw].copy_from_slice(&self.sp[..pw]);
        bn::mod_sub(&mut diff[..pw], &sqp[..pw], p);
        let mut qi = [0u32; MAX_PW];
        bn::mont_mul(
            &mut qi[..pw],
            &self.qinv[..pw],
            &self.rr[..pw],
            p,
            self.minv,
        );
        let mut h = [0u32; MAX_PW];
        bn::mont_mul(&mut h[..pw], &qi[..pw], &diff[..pw], p, self.minv);
        self.stats.modmul += 2;
        let [_none, _nrr, s, _sm, _acc] = split::<5>(&mut self.scratch[..5 * MAX_NW], MAX_NW);
        bn::mul_into(&mut s[..nw], &h[..pw], &self.q[..pw]);
        let mut sqw = [0u32; MAX_NW];
        sqw[..pw].copy_from_slice(&self.sq[..pw]);
        bn::add_assign(&mut s[..nw], &sqw[..nw]);
        sqp.zeroize();
        diff.zeroize();
        qi.zeroize();
        h.zeroize();
        sqw.zeroize();
    }

    // ── output ──

    /// The modulus, big-endian (`nlen / 8` bytes).
    pub fn write_modulus<const N: usize>(&self, out: &mut heapless::Vec<u8, N>) -> Result<(), ()> {
        if !self.is_ready() {
            return Err(());
        }
        let len = self.nlen as usize / 8;
        out.clear();
        out.resize(len, 0).map_err(|_| ())?;
        bn::to_be_bytes(&self.n[..2 * self.pw], out);
        Ok(())
    }

    /// PKCS#1 `RSAPrivateKey` (RFC 8017 A.1.2), DER:
    /// `SEQUENCE { 0, n, e, d, p, q, dP, dQ, qInv }`.
    pub fn write_der<const N: usize>(&self, out: &mut heapless::Vec<u8, N>) -> Result<(), ()> {
        if !self.is_ready() {
            return Err(());
        }
        let pw = self.pw;
        let nw = 2 * pw;
        let e = [E];
        let fields: [&[u32]; 8] = [
            &self.n[..nw],
            &e,
            &self.d[..nw],
            &self.p[..pw],
            &self.q[..pw],
            &self.dp[..pw],
            &self.dq[..pw],
            &self.qinv[..pw],
        ];
        let mut content = 3; // INTEGER 0
        for f in fields {
            content += der_int_len(f);
        }
        out.clear();
        out.push(0x30).map_err(|_| ())?;
        push_len(out, content)?;
        out.extend_from_slice(&[0x02, 0x01, 0x00]).map_err(|_| ())?;
        for f in fields {
            push_int(out, f)?;
        }
        Ok(())
    }
}

impl Default for KeyGen {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyGen {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Copy)]
enum Op {
    AccSqr,
}

/// `x = x − m` if `x ≥ m` (masked; for `x < 2m`).
fn reduce_once(x: &mut [u32], m: &[u32]) {
    let n = m.len();
    let mut t = [0u32; MAX_PW];
    t[..n].copy_from_slice(x);
    let br = bn::sub_assign(&mut t[..n], m);
    let keep = 0u32.wrapping_sub(br); // borrow: x < m, keep x
    for j in 0..n {
        x[j] = (x[j] & keep) | (t[j] & !keep);
    }
    t.zeroize();
}

/// `out = e⁻¹ mod m` for even `m` coprime to `e`: with `k = −m⁻¹ mod e`,
/// `out = (k·m + 1) / e`, then checked by multiplying back.  `tmp` has
/// `m.len() + 1` words; `out` has at least `m.len()`.  Constant-time in
/// `m`: `m mod e` and the division by `e` multiply by a reciprocal, and
/// `(m mod e)⁻¹ mod e` is Fermat's `r^(e−2)` (`e` is a public prime).
fn inverse_of_e(m: &[u32], tmp: &mut [u32], out: &mut [u32]) -> bool {
    let len = m.len();
    let r = bn::ct_rem_small(m, E, E_RECIP);
    let inv = bn::ct_inv_mod_small_prime(r, E, E_RECIP); // 0 if e | m
    let k = E - inv; // in 1..e−1 when inv ≠ 0 (inv = 0 fails below)
    tmp[..len].copy_from_slice(m);
    tmp[len] = bn::mul_small(&mut tmp[..len], k);
    bn::add_small(&mut tmp[..len + 1], 1);
    let rem = bn::ct_divrem_small(&mut tmp[..len + 1], E, E_RECIP);
    let mut ok =
        bn::ct_zero_mask_u32(rem) & bn::ct_zero_mask_u32(tmp[len]) & !bn::ct_zero_mask_u32(inv);
    out.fill(0);
    out[..len].copy_from_slice(&tmp[..len]);
    // Multiply back: out · e − 1 ≡ 0 (mod m), i.e. out·e = k·m + 1.
    tmp[..len].copy_from_slice(&out[..len]);
    tmp[len] = bn::mul_small(&mut tmp[..len], E);
    bn::sub_small(&mut tmp[..len + 1], 1);
    let mut km = [0u32; MAX_NW + 1];
    km[..len].copy_from_slice(m);
    km[len] = bn::mul_small(&mut km[..len], k);
    ok &= bn::ct_eq_mask(&tmp[..len + 1], &km[..len + 1]) & !bn::ct_is_zero(&out[..len]);
    km.zeroize();
    tmp.zeroize();
    ok != 0
}

/// `(a / w)` for odd `w` given `r = w mod a` and odd `a` (reciprocity:
/// `(a/w) = (w/a) · (−1)^((a−1)/2 · (w−1)/2)`).
fn jacobi_small_over_big(a: u32, r: u32, w0: u32) -> i32 {
    let mut j = bn::jacobi_u32(r, a);
    if a & 3 == 3 && w0 & 3 == 3 {
        j = -j;
    }
    j
}

/// Bytes of a DER INTEGER (tag + length + content) for an unsigned value.
fn der_int_len(x: &[u32]) -> usize {
    let content = der_int_content_len(x);
    1 + der_len_len(content) + content
}

fn der_int_content_len(x: &[u32]) -> usize {
    // Constant-time count; the resulting length is part of the encoding
    // (see the module docs on DER lengths).
    let bits = bn::ct_bit_len(x) as usize;
    if bits == 0 {
        return 1;
    }
    // A leading zero byte when the top bit of the top byte is set.
    bits / 8 + 1
}

fn der_len_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else {
        3
    }
}

fn push_len<const N: usize>(out: &mut heapless::Vec<u8, N>, len: usize) -> Result<(), ()> {
    if len < 0x80 {
        out.push(len as u8).map_err(|_| ())
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]).map_err(|_| ())
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8])
            .map_err(|_| ())
    }
}

fn push_int<const N: usize>(out: &mut heapless::Vec<u8, N>, x: &[u32]) -> Result<(), ()> {
    let content = der_int_content_len(x);
    out.push(0x02).map_err(|_| ())?;
    push_len(out, content)?;
    let start = out.len();
    out.resize(start + content, 0).map_err(|_| ())?;
    bn::to_be_bytes(x, &mut out[start..]);
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::BigUint;
    use std::boxed::Box;
    use std::vec::Vec;

    /// Deterministic test DRBG (SplitMix64).
    pub(crate) struct TestRng(pub u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn generate(nlen: u32, seed: u64, slice: Option<u32>) -> (Vec<u8>, Stats) {
        let mut kg = Box::new(KeyGen::new());
        assert!(kg.start(nlen));
        let mut rng = TestRng(seed);
        loop {
            let poll = match slice {
                Some(n) => kg.step(&mut rng, &mut Units(n)),
                None => kg.step(&mut rng, &mut Unlimited),
            };
            match poll {
                Poll::Ready => break,
                Poll::Pending => continue,
                other => panic!("keygen stopped: {other:?}"),
            }
        }
        let mut der: heapless::Vec<u8, 2400> = heapless::Vec::new();
        kg.write_der(&mut der).unwrap();
        (der.to_vec(), kg.stats)
    }

    fn probably_prime(x: &BigUint) -> bool {
        num_prime(x)
    }

    fn num_prime(x: &BigUint) -> bool {
        // Fermat to several bases suffices as an independent sanity check
        // next to the generator's own tests.
        for b in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29] {
            if BigUint::from(b).modpow(&(x - 1u32), x) != BigUint::from(1u8) {
                return false;
            }
        }
        true
    }

    fn check_key(der: &[u8], nlen: usize) {
        let key = rsa::RsaPrivateKey::from_pkcs1_der(der).expect("rsa crate parses and validates");
        key.validate().unwrap();
        let n = key.n();
        let e = key.e();
        assert_eq!(n.bits(), nlen);
        assert_eq!(*e, BigUint::from(E));
        let primes = key.primes();
        let (p, q) = (&primes[0], &primes[1]);
        assert_eq!(p.bits(), nlen / 2);
        assert_eq!(q.bits(), nlen / 2);
        assert!(probably_prime(p) && probably_prime(q));
        // √2 · 2^(k−1) ≤ p, q: the top two bits are set.
        assert!(p >> (nlen / 2 - 2) == BigUint::from(3u8));
        assert!(q >> (nlen / 2 - 2) == BigUint::from(3u8));
        // |p − q| > 2^(nlen/2 − 100)
        let diff = if p > q { p - q } else { q - p };
        assert!(diff > (BigUint::from(1u8) << (nlen / 2 - 100)));
        // gcd(e, p−1) = gcd(e, q−1) = 1
        assert!((p - 1u32) % E != BigUint::from(0u8));
        assert!((q - 1u32) % E != BigUint::from(0u8));
        // d = e⁻¹ mod λ, 2^(nlen/2) < d < λ
        let pm1 = p - 1u32;
        let qm1 = q - 1u32;
        let g = num_integer_gcd(&pm1, &qm1);
        let lam = &pm1 * &qm1 / &g;
        let d = key.d();
        assert!(*d < lam);
        assert!(*d > (BigUint::from(1u8) << (nlen / 2)));
        assert_eq!((d * e) % &lam, BigUint::from(1u8));
        // The CRT values in the DER match the rsa crate's own.
        assert_eq!(key.to_pkcs1_der().unwrap().as_bytes(), der);
    }

    fn num_integer_gcd(a: &BigUint, b: &BigUint) -> BigUint {
        let (mut a, mut b) = (a.clone(), b.clone());
        while b != BigUint::from(0u8) {
            let r = &a % &b;
            a = b;
            b = r;
        }
        a
    }

    #[test]
    fn small_primes_table() {
        assert_eq!(SMALL_PRIMES[0], 3);
        assert_eq!(SMALL_PRIMES[NUM_SMALL_PRIMES - 1], 16381);
        assert_eq!(NUM_SMALL_PRIMES, 1900 - 1);
    }

    #[test]
    fn rsa_512_keys_meet_every_check() {
        for seed in 0..6 {
            let (der, _) = generate(512, seed, None);
            check_key(&der, 512);
        }
    }

    #[test]
    fn rsa_2048_key_meets_every_check() {
        let (der, stats) = generate(2048, 42, None);
        check_key(&der, 2048);
        assert!(stats.modmul > 0 && stats.modsqr > stats.modmul && stats.modmul_n == 18);
    }

    #[test]
    fn interrupting_at_every_unit_gives_the_same_key() {
        for seed in [1u64, 2, 3] {
            let (a, sa) = generate(1024, seed, None);
            let (b, sb) = generate(1024, seed, Some(1));
            let (c, _) = generate(1024, seed, Some(7));
            assert_eq!(a, b);
            assert_eq!(a, c);
            assert_eq!(sa.modmul, sb.modmul);
            check_key(&a, 1024);
        }
    }

    /// Host benchmark against the `rsa` crate's keygen.  Run with
    /// `cargo test --release ... -- --ignored --nocapture bench_keygen`.
    #[test]
    #[ignore]
    fn bench_keygen() {
        use std::time::Instant;
        let seeds: u64 = std::env::var("BENCH_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        for nlen in [2048u32, 3072, 4096] {
            let mut total = std::time::Duration::ZERO;
            let mut mm: u64 = 0;
            let mut ms: u64 = 0;
            let mut mmn: u64 = 0;
            let mut cands: u64 = 0;
            let mut mr2: u64 = 0;
            let mut units: u64 = 0;
            for seed in 0..seeds {
                let t = Instant::now();
                let (der, st) = generate(nlen, 1000 + seed, None);
                total += t.elapsed();
                check_key(&der, nlen as usize);
                mm += st.modmul;
                ms += st.modsqr;
                mmn += st.modmul_n;
                cands += u64::from(st.candidates);
                mr2 += u64::from(st.mr_base2);
                units += st.units;
            }
            let mut rsa_total = std::time::Duration::ZERO;
            let rsa_runs = seeds.min(if nlen == 4096 { 3 } else { 5 });
            for seed in 0..rsa_runs {
                let mut rng = TestRng(5000 + seed);
                let t = Instant::now();
                let _k = rsa::RsaPrivateKey::new(&mut RngWrap(&mut rng), nlen as usize).unwrap();
                rsa_total += t.elapsed();
            }
            std::println!(
                "RSA-{nlen}: sliced {:?}/key, modmul(p) {} modsqr(p) {} modmul(n) {} candidates {} mr_base2 {} units {} | rsa crate {:?}/key",
                total / seeds as u32,
                mm / seeds,
                ms / seeds,
                mmn / seeds,
                cands / seeds,
                mr2 / seeds,
                units / seeds,
                rsa_total / rsa_runs as u32
            );
        }
    }

    /// CRC-32 of the DER for fixed seeds: the same values come out of the
    /// generator compiled for the Cortex-M33 (QEMU mps2-an505), which shows
    /// the ARM build computes the same keys.
    #[test]
    #[ignore]
    fn reference_crcs() {
        for (nlen, seed) in [
            (1024u32, 1u64),
            (2048, 42),
            (2048, 43),
            (3072, 7),
            (4096, 9),
        ] {
            let (der, st) = generate(nlen, seed, None);
            std::println!(
                "RSA-{nlen} seed {seed}: modmul {} modsqr {} units {} der_len {} crc {:08x}",
                st.modmul,
                st.modsqr,
                st.units,
                der.len(),
                crc32fast::hash(&der)
            );
        }
    }

    struct RngWrap<'a>(&'a mut TestRng);
    impl rsa::rand_core::RngCore for RngWrap<'_> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            self.0.fill_bytes(d)
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.0.fill_bytes(d);
            Ok(())
        }
    }
    impl rsa::rand_core::CryptoRng for RngWrap<'_> {}

    #[test]
    fn same_seed_same_key_different_seed_different_key() {
        let (a, _) = generate(512, 9, None);
        let (b, _) = generate(512, 9, Some(3));
        let (c, _) = generate(512, 10, None);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn reset_wipes_and_idles() {
        let mut kg = Box::new(KeyGen::new());
        let mut rng = TestRng(5);
        assert_eq!(kg.step(&mut rng, &mut Unlimited), Poll::Idle);
        assert!(kg.start(1024));
        assert_eq!(kg.step(&mut rng, &mut Units(500)), Poll::Pending);
        assert!(kg.is_busy());
        kg.reset();
        assert!(!kg.is_busy());
        assert!(kg.p.iter().chain(kg.scratch.iter()).all(|&w| w == 0));
        assert_eq!(kg.step(&mut rng, &mut Unlimited), Poll::Idle);
        assert!(!kg.start(1000));
    }

    /// Timing regression: the work the primality pipeline does on a prime
    /// (multiplications and squarings — the constant-time units) does not
    /// depend on `ν2(p − 1)`: the Miller-Rabin squaring loop always runs
    /// [`MR_SQUARINGS`] times.
    #[test]
    fn miller_rabin_work_does_not_depend_on_nu2() {
        let mut kg = Box::new(KeyGen::new());
        let mut rng = TestRng(91);
        let p1 = 0xFFFF_FFFF_FFFF_FFC5u64; // ν2(p − 1) = 2
        let mut k = (1u64 << 43) | 1;
        let p2 = loop {
            let c = (k << 20) + 1; // ν2(c − 1) = 20, top bit set
            if num_prime(&BigUint::from(c)) {
                break c;
            }
            k += 2;
        };
        assert!(kg.test_candidate(p1, &mut rng));
        let s1 = kg.stats;
        assert!(kg.test_candidate(p2, &mut rng));
        let s2 = kg.stats;
        assert_eq!((s1.modmul, s1.modsqr), (s2.modmul, s2.modsqr));
    }

    #[test]
    fn primality_pipeline_on_known_numbers() {
        let mut kg = Box::new(KeyGen::new());
        let mut rng = TestRng(77);
        // Lucas pseudoprimes for Selfridge's parameters (OEIS A217120): the
        // B.3.3 test alone passes them, the full pipeline (M-R base 2
        // first) rejects them.
        for c in [323u64, 377, 1159, 1829, 3827, 5459, 5777, 9071, 9179, 10877] {
            assert!(kg.test_lucas(c, &mut rng), "Lucas pseudoprime {c}");
            assert!(!kg.test_candidate(c, &mut rng), "{c}");
        }
        // Strong pseudoprimes to base 2 (some to several bases),
        // Carmichael numbers, squares and products of primes.
        for c in [
            2047u64,
            3277,
            4033,
            561,
            1105,
            41_041,
            25_326_001,
            3_215_031_751,
            2_152_302_898_747,
            3_474_749_660_383,
            341_550_071_728_321,
            65_537 * 3,
            46_337 * 46_337,
            4_294_967_291 * 4_294_967_279,
        ] {
            assert!(!kg.test_candidate(c, &mut rng), "composite {c}");
        }
        // (5 itself is rejected: B.3.3's first D is 5 and (5/5) = 0.)
        for c in [
            13u64,
            65_537,
            2_147_483_647,
            4_294_967_291,
            0xFFFF_FFFF_FFFF_FFC5,
            1_000_000_007,
        ] {
            assert!(kg.test_candidate(c, &mut rng), "prime {c}");
            assert!(kg.test_lucas(c, &mut rng), "Lucas on prime {c}");
        }
    }

    impl KeyGen {
        fn test_setup(&mut self, c: u64, then: Phase) {
            self.wipe();
            self.nlen = 128;
            self.pw = 2;
            self.w[0] = c as u32;
            self.w[1] = (c >> 32) as u32;
            self.begin_setup(then);
        }

        fn test_run(&mut self, rng: &mut dyn RngCore) -> bool {
            loop {
                match self.phase {
                    Phase::Accept => return true,
                    Phase::Draw => return false,
                    _ => self.unit(rng),
                }
            }
        }

        /// The whole primality pipeline (test hook).
        fn test_candidate(&mut self, c: u64, rng: &mut dyn RngCore) -> bool {
            self.test_setup(c, Phase::Base2Start);
            self.test_run(rng)
        }

        /// The B.3.3 Lucas test alone (test hook).
        fn test_lucas(&mut self, c: u64, rng: &mut dyn RngCore) -> bool {
            self.test_setup(c, Phase::LucasSetup);
            self.test_run(rng)
        }
    }
}
