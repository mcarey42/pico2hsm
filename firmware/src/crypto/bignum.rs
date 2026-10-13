//! Runtime-width multi-precision arithmetic for RSA key generation.
//!
//! Numbers are little-endian slices of 32-bit words (word 0 is the least
//! significant).  Every function works on whatever length its slices have,
//! up to [`MAX_WORDS`]; one compiled copy serves RSA-2048, -3072 and -4096
//! (and the small sizes the host tests use).  Nothing allocates.
//!
//! # Montgomery multiplication
//! SOS (separated operand scanning; Koç, Acar, Kaliski, "Analyzing and
//! comparing Montgomery multiplication algorithms", IEEE Micro 1996): the
//! full product into a `2·len` buffer, then Montgomery reduction.
//! [`mont_mul`] costs `2·len²` 32×32→64 multiply-accumulates,
//! [`mont_sqr`] `1.5·len² + len` (each cross product once, then doubled).
//! Every inner loop is [`mac_row`], unrolled by four with no bounds checks:
//! this is where key generation spends its time.  The final conditional
//! subtraction is a mask select, so the instruction sequence and memory
//! accesses depend only on `len`, never on the operands.
//!
//! # Constant time
//! Constant-time in the operands (no data-dependent branch, memory index
//! or `UDIV`/`SDIV` — the Cortex-M33's divider takes 2–11 cycles depending
//! on its operands): the modular primitives (`mont_*`, `mod_*`,
//! [`select_from_table`]), [`add_small`] / [`sub_small`] (full length, no
//! early exit), and every `ct_*` function: masks, comparisons, trailing
//! zeros, shifts by a secret amount, division / remainder by a small
//! divisor (multiplication by a reciprocal), the inverse modulo a small
//! prime, and binary-GCD steps.
//!
//! Variable-time, and **only for public values** (the modulus, test code,
//! public divisors computed once): [`cmp`], [`bit_len`],
//! [`trailing_zeros`], [`is_zero`], [`div_small`], [`rem_small`],
//! [`inv_mod_u32`], [`jacobi_u32`] (the one secret use, the Lucas `D`
//! search, is argued in `rsa_keygen`).  `shr` / `shl` take a public shift
//! amount (constant-time in the value).

// Index loops mirror the textbook algorithms (several arrays per index).
#![allow(clippy::needless_range_loop)]

use core::cmp::Ordering;

/// Largest operand: a 4096-bit modulus.
pub const MAX_WORDS: usize = 128;

#[inline(always)]
fn mac(a: u32, b: u32, c: u32, carry: u32) -> (u32, u32) {
    let t = u64::from(a) * u64::from(b) + u64::from(c) + u64::from(carry);
    (t as u32, (t >> 32) as u32)
}

#[inline(always)]
fn adc(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let t = u64::from(a) + u64::from(b) + u64::from(carry);
    (t as u32, (t >> 32) as u32)
}

#[inline(always)]
fn sbb(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let t = u64::from(a)
        .wrapping_sub(u64::from(b))
        .wrapping_sub(u64::from(borrow));
    (t as u32, ((t >> 32) as u32) & 1)
}

/// All-ones if `bit` is 1, zero if 0 (`bit` must be 0 or 1).
#[inline(always)]
const fn mask(bit: u32) -> u32 {
    0u32.wrapping_sub(bit)
}

// ─── Plain arithmetic ────────────────────────────────────────────────────────

/// `a += b` (same length); returns the carry.
pub fn add_assign(a: &mut [u32], b: &[u32]) -> u32 {
    let mut c = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (s, c2) = adc(*x, y, c);
        *x = s;
        c = c2;
    }
    c
}

/// `a -= b` (same length); returns the borrow.
pub fn sub_assign(a: &mut [u32], b: &[u32]) -> u32 {
    let mut br = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d, b2) = sbb(*x, y, br);
        *x = d;
        br = b2;
    }
    br
}

/// `a += k` for a small `k`; returns the carry.  Full length (no early
/// exit when the carry dies), so constant-time in `a`.
pub fn add_small(a: &mut [u32], k: u32) -> u32 {
    let mut c = k;
    for x in a.iter_mut() {
        let (s, c2) = adc(*x, c, 0);
        *x = s;
        c = c2;
    }
    c
}

/// `a -= k` for a small `k`; returns the borrow.  Full length.
pub fn sub_small(a: &mut [u32], k: u32) -> u32 {
    let mut br = k;
    for x in a.iter_mut() {
        let (d, b2) = sbb(*x, br, 0);
        *x = d;
        br = b2;
    }
    br
}

/// `a *= k`; returns the carry word.
pub fn mul_small(a: &mut [u32], k: u32) -> u32 {
    let mut c = 0;
    for x in a.iter_mut() {
        let (lo, hi) = mac(*x, k, 0, c);
        *x = lo;
        c = hi;
    }
    c
}

/// `a /= k` in place; returns `a mod k`.  `k` must be non-zero.
/// Variable-time (64-bit software division): public values only.
pub fn div_small(a: &mut [u32], k: u32) -> u32 {
    let k = u64::from(k);
    let mut r: u64 = 0;
    for x in a.iter_mut().rev() {
        let cur = (r << 32) | u64::from(*x);
        *x = (cur / k) as u32;
        r = cur % k;
    }
    r as u32
}

/// `a mod k` (`k` non-zero).  Variable-time: public values only.
pub fn rem_small(a: &[u32], k: u32) -> u32 {
    let k = u64::from(k);
    let mut r: u64 = 0;
    for &x in a.iter().rev() {
        r = ((r << 32) | u64::from(x)) % k;
    }
    r as u32
}

/// `out = a · b` (schoolbook); `out.len()` must be `a.len() + b.len()`.
pub fn mul_into(out: &mut [u32], a: &[u32], b: &[u32]) {
    debug_assert_eq!(out.len(), a.len() + b.len());
    out.fill(0);
    for (i, &bi) in b.iter().enumerate() {
        let mut c = 0;
        for (j, &aj) in a.iter().enumerate() {
            let (lo, hi) = mac(aj, bi, out[i + j], c);
            out[i + j] = lo;
            c = hi;
        }
        out[i + a.len()] = c;
    }
}

/// Shift right by one bit.
pub fn shr1(a: &mut [u32]) {
    let mut carry = 0;
    for x in a.iter_mut().rev() {
        let next = *x & 1;
        *x = (*x >> 1) | (carry << 31);
        carry = next;
    }
}

/// Shift right by `n` bits (`n` < 32·len).
pub fn shr(a: &mut [u32], n: usize) {
    let words = n / 32;
    let bits = n % 32;
    let len = a.len();
    for i in 0..len {
        let lo = a.get(i + words).copied().unwrap_or(0);
        let hi = a.get(i + words + 1).copied().unwrap_or(0);
        a[i] = if bits == 0 {
            lo
        } else {
            (lo >> bits) | (hi << (32 - bits))
        };
    }
}

/// Shift left by `n` bits, dropping what overflows.
pub fn shl(a: &mut [u32], n: usize) {
    let words = n / 32;
    let bits = n % 32;
    for i in (0..a.len()).rev() {
        let lo = if i >= words { a[i - words] } else { 0 };
        let lo2 = if i > words { a[i - words - 1] } else { 0 };
        a[i] = if bits == 0 {
            lo
        } else {
            (lo << bits) | (lo2 >> (32 - bits))
        };
    }
}

/// Bit `i` of `a` (0 or 1).
#[inline]
pub fn bit(a: &[u32], i: usize) -> u32 {
    (a[i / 32] >> (i % 32)) & 1
}

/// Number of significant bits (0 for zero).  Variable-time: public values
/// only (see [`ct_bit_len`]).
pub fn bit_len(a: &[u32]) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return 32 * i + 32 - a[i].leading_zeros() as usize;
        }
    }
    0
}

/// Number of trailing zero bits (0 for zero).  Variable-time: public
/// values only (see [`ct_tz`]).
pub fn trailing_zeros(a: &[u32]) -> usize {
    for (i, &x) in a.iter().enumerate() {
        if x != 0 {
            return 32 * i + x.trailing_zeros() as usize;
        }
    }
    0
}

/// `a == 0`.  Variable-time: public values only (see [`ct_is_zero`]).
pub fn is_zero(a: &[u32]) -> bool {
    a.iter().all(|&x| x == 0)
}

/// Compare equal-length numbers.  Variable-time (early exit): public
/// values only (see [`ct_lt`]).
pub fn cmp(a: &[u32], b: &[u32]) -> Ordering {
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            o => return o,
        }
    }
    Ordering::Equal
}

/// Constant-time equality of equal-length numbers.
pub fn ct_eq(a: &[u32], b: &[u32]) -> bool {
    ct_eq_mask(a, b) != 0
}

// ─── Constant-time helpers ───────────────────────────────────────────────────

/// All-ones if `x == 0`, else 0 (no comparison instruction on `x`).
#[inline(always)]
pub fn ct_zero_mask_u32(x: u32) -> u32 {
    mask(((x | x.wrapping_neg()) >> 31) ^ 1)
}

/// All-ones if `a < b`, for `a, b < 2^31`.
#[inline(always)]
pub fn ct_lt_mask_u32(a: u32, b: u32) -> u32 {
    mask(a.wrapping_sub(b) >> 31)
}

/// All-ones if `a == b` (equal-length numbers).
pub fn ct_eq_mask(a: &[u32], b: &[u32]) -> u32 {
    let mut acc = 0;
    for (&x, &y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    ct_zero_mask_u32(acc)
}

/// All-ones if `a == 0`.
pub fn ct_is_zero(a: &[u32]) -> u32 {
    let mut acc = 0;
    for &x in a {
        acc |= x;
    }
    ct_zero_mask_u32(acc)
}

/// All-ones if `a < b` (equal-length numbers): the borrow of `a − b`.
pub fn ct_lt(a: &[u32], b: &[u32]) -> u32 {
    let mut br = 0;
    for (&x, &y) in a.iter().zip(b) {
        let (_, b2) = sbb(x, y, br);
        br = b2;
    }
    mask(br)
}

/// `out = m ? a : b` word by word (`m` all-ones or zero).
pub fn ct_select(out: &mut [u32], a: &[u32], b: &[u32], m: u32) {
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        *o = (x & m) | (y & !m);
    }
}

/// Number of trailing zero bits (0 for zero), constant-time.
pub fn ct_tz(a: &[u32]) -> u32 {
    let mut tz = 0;
    let mut found = 0;
    for (i, &w) in a.iter().enumerate() {
        let nz = !ct_zero_mask_u32(w);
        // RBIT + CLZ on the M33 (TZCNT on x86): constant-time.
        let t = (32 * i as u32).wrapping_add(w.trailing_zeros());
        tz |= t & nz & !found;
        found |= nz;
    }
    tz
}

/// Number of significant bits, constant-time.
pub fn ct_bit_len(a: &[u32]) -> u32 {
    let mut len = 0;
    for (i, &w) in a.iter().enumerate() {
        let nz = !ct_zero_mask_u32(w);
        // CLZ is constant-time; later (higher) non-zero words override.
        let l = (32 * i as u32 + 32).wrapping_sub(w.leading_zeros());
        len = (l & nz) | (len & !nz);
    }
    len
}

/// Shift right by a secret amount `sh` (< 32·len): a barrel shifter of
/// masked public-amount shifts.
pub fn ct_shr(a: &mut [u32], sh: u32) {
    let n = a.len();
    let mut t = [0u32; MAX_WORDS];
    let mut stage = 0;
    while (1usize << stage) < 32 * n {
        let m = mask((sh >> stage) & 1);
        t[..n].copy_from_slice(a);
        shr(&mut t[..n], 1 << stage);
        for (x, &y) in a.iter_mut().zip(&t[..n]) {
            *x = (y & m) | (*x & !m);
        }
        stage += 1;
    }
    crate::security::zeroize::wipe_words(&mut t[..n]);
}

/// `floor((2^32 − 1) / d)` for `0 < d < 2^17`, by a fixed 32-step restoring
/// division (no `UDIV`: `d` may be secret).
pub const fn ct_recip(d: u32) -> u32 {
    let mut rem: u32 = 0;
    let mut q: u32 = 0;
    let mut i = 32;
    while i > 0 {
        i -= 1;
        rem = (rem << 1) | 1; // the bits of 2^32 − 1
        let ge = !mask(rem.wrapping_sub(d) >> 31); // rem ≥ d (both < 2^18)
        rem = rem.wrapping_sub(d & ge);
        q |= (ge & 1) << i;
    }
    q
}

/// `(x / d, x mod d)` for `x < 2^32` and `0 < d < 2^17` with `recip =
/// ct_recip(d)`: multiply by the reciprocal (`UMULL`), one masked
/// correction.  `x·recip / 2^32` undershoots the quotient by at most one.
#[inline(always)]
fn ct_divrem32(x: u32, d: u32, recip: u32) -> (u32, u32) {
    let mut q = ((u64::from(x) * u64::from(recip)) >> 32) as u32;
    let mut r = x.wrapping_sub(q.wrapping_mul(d)); // < 2d
    let ge = !mask(r.wrapping_sub(d) >> 31);
    r = r.wrapping_sub(d & ge);
    q = q.wrapping_add(ge & 1);
    (q, r)
}

/// `a mod d` for `0 < d < 2^17`, constant-time in `a` and `d` (`recip =
/// ct_recip(d)`).  Each word goes in 2 + 15 + 15-bit pieces so that
/// `(r << bits) | piece` stays below 2^32.
pub fn ct_rem_small(a: &[u32], d: u32, recip: u32) -> u32 {
    let mut r = 0;
    for &w in a.iter().rev() {
        r = ct_divrem32((r << 2) | (w >> 30), d, recip).1;
        r = ct_divrem32((r << 15) | ((w >> 15) & 0x7FFF), d, recip).1;
        r = ct_divrem32((r << 15) | (w & 0x7FFF), d, recip).1;
    }
    r
}

/// `a /= d` in place, returning `a mod d`, for `0 < d < 2^17`;
/// constant-time in `a` and `d` (`recip = ct_recip(d)`).
pub fn ct_divrem_small(a: &mut [u32], d: u32, recip: u32) -> u32 {
    let mut r = 0;
    for w in a.iter_mut().rev() {
        let (q0, r0) = ct_divrem32((r << 2) | (*w >> 30), d, recip);
        let (q1, r1) = ct_divrem32((r0 << 15) | ((*w >> 15) & 0x7FFF), d, recip);
        let (q2, r2) = ct_divrem32((r1 << 15) | (*w & 0x7FFF), d, recip);
        *w = (q0 << 30) | (q1 << 15) | q2;
        r = r2;
    }
    r
}

/// `r⁻¹ mod p` for a prime `p < 2^17` (`recip = ct_recip(p)`), by Fermat:
/// `r^(p−2)`, square-and-multiply over the public exponent.  0 for `r ≡ 0`.
pub fn ct_inv_mod_small_prime(r: u32, p: u32, recip: u32) -> u32 {
    let mulmod = |x: u32, y: u32| {
        let t = u64::from(x) * u64::from(y);
        ct_rem_small(&[t as u32, (t >> 32) as u32], p, recip)
    };
    let e = p - 2;
    let mut acc = 1u32;
    let base = ct_rem_small(&[r], p, recip);
    let mut i = 32 - e.leading_zeros();
    while i > 0 {
        i -= 1;
        acc = mulmod(acc, acc);
        if (e >> i) & 1 == 1 {
            // The exponent is public.
            acc = mulmod(acc, base);
        }
    }
    acc
}

/// `gcd(a, b)` of small numbers (`b < 2^17` public or secret), by a fixed
/// number of binary-GCD steps; constant-time.
pub fn ct_gcd_u32(a: u32, b: u32) -> u32 {
    // gcd(a, b) = gcd(a mod b, b); both below 2^17, then 2·17 steps of the
    // odd-v binary GCD after taking out the common power of two.
    let mut u = a;
    let mut v = b;
    let zu = (u | 0x0002_0000).trailing_zeros();
    let zv = (v | 0x0002_0000).trailing_zeros();
    let k = zv ^ ((zu ^ zv) & ct_lt_mask_u32(zu, zv)); // min
    u >>= zu & 31;
    v >>= zv & 31;
    // v odd (unless b == 0, which callers never pass).
    for _ in 0..80 {
        let odd = mask(u & 1);
        let lt = ct_lt_mask_u32(u, v);
        let d = u.wrapping_sub(v);
        let nd = v.wrapping_sub(u);
        let swap = odd & lt;
        let nv = (u & swap) | (v & !swap);
        let diff = (nd & lt) | (d & !lt);
        u = ((diff & odd) | (u & !odd)) >> 1;
        v = nv;
    }
    v << k
}

/// One step of constant-time binary GCD for `v` odd: if `u` is odd,
/// `(u, v) = (|u − v|, min(u, v))`; then `u >>= 1`.  `2·bits` steps take
/// any `u` to 0, leaving `gcd` in `v`.
pub fn ct_gcd_step(u: &mut [u32], v: &mut [u32]) {
    let n = u.len();
    let odd = mask(u[0] & 1);
    let mut d = [0u32; MAX_WORDS];
    let mut nd = [0u32; MAX_WORDS];
    d[..n].copy_from_slice(u);
    let br = sub_assign(&mut d[..n], v); // u − v
    nd[..n].copy_from_slice(v);
    sub_assign(&mut nd[..n], u); // v − u
    let lt = mask(br);
    let swap = odd & lt;
    for j in 0..n {
        let new_v = (u[j] & swap) | (v[j] & !swap);
        let diff = (nd[j] & lt) | (d[j] & !lt);
        u[j] = (diff & odd) | (u[j] & !odd);
        v[j] = new_v;
    }
    shr1(u);
    crate::security::zeroize::wipe_words(&mut d[..n]);
    crate::security::zeroize::wipe_words(&mut nd[..n]);
}

/// Load a big-endian byte string into `out` (zero-extended; excess high
/// bytes are dropped).
pub fn from_be_bytes(out: &mut [u32], bytes: &[u8]) {
    out.fill(0);
    for (i, &b) in bytes.iter().rev().enumerate() {
        if i / 4 < out.len() {
            out[i / 4] |= u32::from(b) << (8 * (i % 4));
        }
    }
}

/// Write `a` big-endian into `out` (exactly `out.len()` bytes, high bytes
/// dropped or zero-padded).
pub fn to_be_bytes(a: &[u32], out: &mut [u8]) {
    let n = out.len();
    for (i, o) in out.iter_mut().enumerate() {
        let byte = n - 1 - i;
        *o = if byte / 4 < a.len() {
            (a[byte / 4] >> (8 * (byte % 4))) as u8
        } else {
            0
        };
    }
}

// ─── Modular arithmetic (constant-time in the operands) ──────────────────────

/// `-m⁻¹ mod 2³²` for odd `m0` (Newton iteration: 3 → 6 → 12 → 24 → 48 bits).
pub fn neg_inv32(m0: u32) -> u32 {
    let mut x = m0;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// `x = (x + y) mod m` for `x, y < m`.
pub fn mod_add(x: &mut [u32], y: &[u32], m: &[u32]) {
    let n = m.len();
    let mut s = [0u32; MAX_WORDS];
    let s = &mut s[..n];
    s.copy_from_slice(x);
    let carry = add_assign(s, y);
    // x := s - m
    let mut br = 0;
    for j in 0..n {
        let (d, b2) = sbb(s[j], m[j], br);
        x[j] = d;
        br = b2;
    }
    // Keep s when it is below m: no carry out of the add and a borrow.
    let keep_s = mask((carry ^ 1) & br);
    for j in 0..n {
        x[j] = (s[j] & keep_s) | (x[j] & !keep_s);
    }
    crate::security::zeroize::wipe_words(s);
}

/// `x = (x - y) mod m` for `x, y < m`.
pub fn mod_sub(x: &mut [u32], y: &[u32], m: &[u32]) {
    let br = sub_assign(x, y);
    let mk = mask(br);
    let mut c = 0;
    for j in 0..m.len() {
        let (s, c2) = adc(x[j], m[j] & mk, c);
        x[j] = s;
        c = c2;
    }
}

/// `x = 2x mod m` for `x < m`.
pub fn mod_double(x: &mut [u32], m: &[u32]) {
    let n = m.len();
    let mut d = [0u32; MAX_WORDS];
    let d = &mut d[..n];
    d.copy_from_slice(x);
    let carry = add_assign(d, x);
    let mut br = 0;
    for j in 0..n {
        let (v, b2) = sbb(d[j], m[j], br);
        x[j] = v;
        br = b2;
    }
    let keep_d = mask((carry ^ 1) & br);
    for j in 0..n {
        x[j] = (d[j] & keep_d) | (x[j] & !keep_d);
    }
    crate::security::zeroize::wipe_words(d);
}

/// `x = 2x mod m` if `bit` is 1, else `x` unchanged (`x < m`; constant
/// time: the same passes either way, the choice is a mask).
pub fn mod_double_if(x: &mut [u32], m: &[u32], bit: u32) {
    let n = m.len();
    // Pass 1: carry out of 2x, and whether 2x − m borrows.
    let mut carry = 0;
    let mut br = 0;
    for (&xj, &mj) in x[..n].iter().zip(m) {
        let s = (xj << 1) | carry;
        carry = xj >> 31;
        let (_, b2) = sbb(s, mj, br);
        br = b2;
    }
    // Subtract m when 2x ≥ m (a carry out, or no borrow).
    let reduce = (carry | (br ^ 1)) & 1;
    let take = mask(bit & 1);
    let sub = mask(reduce) & take;
    // Pass 2: x = bit ? (2x − (reduce ? m : 0)) : x.
    let mut c = 0;
    let mut br = 0;
    for (xj, &mj) in x[..n].iter_mut().zip(m) {
        let s = (*xj << 1) | c;
        c = *xj >> 31;
        let (d, b2) = sbb(s, mj & sub, br);
        br = b2;
        *xj = (d & take) | (*xj & !take);
    }
}

/// `x = x / 2 mod m` for odd `m` and `x < m`.
pub fn mod_half(x: &mut [u32], m: &[u32]) {
    let odd = mask(x[0] & 1);
    let mut c = 0;
    for j in 0..m.len() {
        let (s, c2) = adc(x[j], m[j] & odd, c);
        x[j] = s;
        c = c2;
    }
    shr1(x);
    let top = m.len() - 1;
    x[top] |= c << 31;
}

/// `out = R mod m` with `R = 2^(32·len)`, for an `m` whose top bit is set
/// (then `R − m < m`, so the two's complement of `m` is the residue).
pub fn r_mod(m: &[u32], out: &mut [u32]) {
    debug_assert!(m[m.len() - 1] >> 31 == 1);
    for (o, &w) in out.iter_mut().zip(m) {
        *o = !w;
    }
    add_small(out, 1);
}

/// `t[j] += a[j] · b` over `t.len() == a.len()` words, plus `c` into
/// `t[0]`; returns the carry out of the top word.
///
/// On the RP2350 (Cortex-M33 with the DSP extension) the loop is two
/// `UMAAL`s per iteration — `RdHi:RdLo = Rn·Rm + RdHi + RdLo`, exactly one
/// multiply-accumulate-with-carry step — about 7.8 cycles per word.  Most
/// rows now go through the two-row [`mac2`]; this one finishes odd rows.
/// `UMAAL` is constant-time.
/// The portable version below is what the host tests run; the M33 build is
/// checked against it in QEMU (`-cpu cortex-m33`): identical keys for the
/// same DRBG stream.
#[cfg(target_arch = "arm")]
#[inline(always)]
fn mac_row(t: &mut [u32], a: &[u32], b: u32, mut c: u32) -> u32 {
    let n = t.len().min(a.len());
    let pairs = n / 2;
    if pairs > 0 {
        // SAFETY: `tp` and `ap` walk exactly `2·pairs ≤ n` words of `t` and
        // `a` (both at least `n` long); `t` is exclusively borrowed and does
        // not overlap `a`.  The asm touches no other memory and no stack.
        unsafe {
            // t0, t1 / c / a0, a1 / b in fixed registers.
            core::arch::asm!(
                "2:",
                "ldrd r8, r10, [r0], #8",
                "ldrd r2, r12, [r1]",
                "umaal r2, r4, r8, r5",
                "umaal r12, r4, r10, r5",
                "strd r2, r12, [r1], #8",
                "subs r3, r3, #1",
                "bne 2b",
                inout("r0") a.as_ptr() => _,
                inout("r1") t.as_mut_ptr() => _,
                inout("r3") pairs => _,
                inout("r4") c,
                in("r5") b,
                out("r8") _,
                out("r10") _,
                out("r2") _,
                out("r12") _,
                options(nostack),
            );
        }
    }
    if n % 2 == 1 {
        let i = n - 1;
        let (l, h) = mac(a[i], b, t[i], c);
        t[i] = l;
        c = h;
    }
    c
}

/// Portable [`mac_row`] (host builds), unrolled by four.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn mac_row(t: &mut [u32], a: &[u32], b: u32, mut c: u32) -> u32 {
    let mut tc = t.chunks_exact_mut(4);
    let mut ac = a.chunks_exact(4);
    for (tq, aq) in (&mut tc).zip(&mut ac) {
        if let ([t0, t1, t2, t3], [a0, a1, a2, a3]) = (tq, aq) {
            let (l, h) = mac(*a0, b, *t0, c);
            *t0 = l;
            let (l, h) = mac(*a1, b, *t1, h);
            *t1 = l;
            let (l, h) = mac(*a2, b, *t2, h);
            *t2 = l;
            let (l, h) = mac(*a3, b, *t3, h);
            *t3 = l;
            c = h;
        }
    }
    for (tj, &aj) in tc.into_remainder().iter_mut().zip(ac.remainder()) {
        let (l, h) = mac(aj, b, *tj, c);
        *tj = l;
        c = h;
    }
    c
}

/// Two rows of multiply-accumulate at once, offset by one word: for each
/// `j`, `t[j] += p·b1 + c1` and then `t[j] += a[j]·b0 + c0`, where `p` is
/// `a[j−1]` (`prev` for `j = 0`).  Returns the carries and the last `a`
/// word, `(c0, c1, a[len−1])`, for the caller to finish the rows (which
/// only depend on `c0 + c1`, not on how the carry is split).
///
/// Every `t` word is loaded and stored once per two multiplies, and every
/// `a` word loaded once for both rows: half the memory traffic of two
/// [`mac_row`] passes, which is where their time goes (UMAAL itself is
/// single-cycle on the M33; SRAM accesses cost ~1.5 cycles each).
#[inline(always)]
fn mac2(t: &mut [u32], a: &[u32], b0: u32, b1: u32, c: (u32, u32), prev: u32) -> (u32, u32, u32) {
    #[cfg(target_arch = "arm")]
    {
        mac2_m33(t, a, b0, b1, c, prev)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        mac2_portable(t, a, b0, b1, c, prev)
    }
}

/// Portable [`mac2`]: what the host tests run, and the reference the
/// device checks the M33 version against (`80 FE 21`).
#[inline(always)]
pub(crate) fn mac2_portable(
    t: &mut [u32],
    a: &[u32],
    b0: u32,
    b1: u32,
    (mut c0, mut c1): (u32, u32),
    mut prev: u32,
) -> (u32, u32, u32) {
    for (tj, &aj) in t.iter_mut().zip(a) {
        // Row 1's term first (as the M33 version, which so avoids waiting
        // on the `a` load); the callers only use c0 + c1.
        let (l, h) = mac(prev, b1, *tj, c1);
        c1 = h;
        let (l, h) = mac(aj, b0, l, c0);
        c0 = h;
        *tj = l;
        prev = aj;
    }
    (c0, c1, prev)
}

/// [`mac2`] on the Cortex-M33: UMAAL (`RdHi:RdLo = Rn·Rm + RdHi + RdLo`)
/// twice per word.  Fixed-length, branch-free per word: constant-time.
/// Measured (RP2350, 150 MHz): ~4.4 cycles per multiply-accumulate; the
/// one-row loop it replaces took ~7.8.
#[cfg(target_arch = "arm")]
#[inline(never)]
// Run from SRAM (copied at boot with .data): measured ~5% faster than
// from flash through the XIP cache.
#[link_section = ".data.ramfunc.mac2_m33"]
pub(crate) fn mac2_m33(
    t: &mut [u32],
    a: &[u32],
    b0: u32,
    b1: u32,
    (mut c0, mut c1): (u32, u32),
    mut prev: u32,
) -> (u32, u32, u32) {
    let n = t.len().min(a.len());
    let pairs = n / 2;
    if pairs > 0 {
        // SAFETY: `ap` and `tp` walk exactly `2·pairs ≤ n` words of `a` and
        // `t` (both at least `n` long); `t` is exclusively borrowed and
        // does not overlap `a`.  No other memory, no stack.
        unsafe {
            core::arch::asm!(
                // Two words per iteration, the roles of the two `a`
                // registers swapped (x = a[j], p = a[j−1], then p = a[j+1],
                // x = a[j]) so no move is needed.  Row 1's UMAAL comes first
                // in each word, and each load has an instruction between it
                // and its first use (the M33's load-use stall).
                // (LDRD pairs measured no faster: the loop is bound by the
                // number of memory accesses, ~1.5 cycles each.)
                "2:",
                "ldr {y}, [{tp}]",
                "ldr {x}, [{ap}], #4",
                "umaal {y}, {c1}, {p}, {b1}",
                "umaal {y}, {c0}, {x}, {b0}",
                "str {y}, [{tp}], #4",
                "ldr {y}, [{tp}]",
                "ldr {p}, [{ap}], #4",
                "umaal {y}, {c1}, {x}, {b1}",
                "umaal {y}, {c0}, {p}, {b0}",
                "str {y}, [{tp}], #4",
                "subs {n}, {n}, #1",
                "bne 2b",
                ap = inout(reg) a.as_ptr() => _,
                tp = inout(reg) t.as_mut_ptr() => _,
                n = inout(reg) pairs => _,
                c0 = inout(reg) c0,
                c1 = inout(reg) c1,
                p = inout(reg) prev,
                b0 = in(reg) b0,
                b1 = in(reg) b1,
                x = out(reg) _,
                y = out(reg) _,
                options(nostack),
            );
        }
    }
    if n % 2 == 1 {
        return mac2_portable(&mut t[n - 1..n], &a[n - 1..n], b0, b1, (c0, c1), prev);
    }
    (c0, c1, prev)
}

/// Words of the double-width product buffer.
const WIDE: usize = 2 * MAX_WORDS + 1;

/// Montgomery reduction of the `2n`-word `t` (`t < m·R`) into `out`:
/// `out = t · R⁻¹ mod m`.  Wipes `t`.
fn redc(out: &mut [u32], t: &mut [u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut top = 0;
    let mut i = 0;
    // Two rows at a time.  Row i+1's multiplier depends on t[i+1] after
    // row i has added into it, so row i's first two words, and row i+1's
    // first, are done here; `mac2` runs both rows over the rest.
    while i + 1 < n {
        let u0 = t[i].wrapping_mul(minv);
        let (_, c0) = mac(m[0], u0, t[i], 0); // t[i] becomes 0
        let (y, c0) = mac(m[1], u0, t[i + 1], c0);
        let u1 = y.wrapping_mul(minv);
        let (_, c1) = mac(m[0], u1, y, 0); // t[i+1] becomes 0
        t[i] = 0;
        t[i + 1] = 0;
        let (c0, c1, last) = mac2(&mut t[i + 2..i + n], &m[2..], u0, u1, (c0, c1), m[1]);
        // t[i+n]: row i's carry and the incoming top; row i+1's last word.
        let (lo, hi) = mac(last, u1, t[i + n], c1);
        let (lo, k) = adc(lo, c0, top);
        t[i + n] = lo;
        // t[i+n+1]: row i+1's carry; what overflows is the next top.
        let (s, k2) = adc(t[i + n + 1], hi, k);
        t[i + n + 1] = s;
        top = k2;
        i += 2;
    }
    if i < n {
        let u = t[i].wrapping_mul(minv);
        let c = mac_row(&mut t[i..i + n], m, u, 0);
        let (s, c2) = adc(t[i + n], c, top);
        t[i + n] = s;
        top = c2;
    }
    // t[n..2n] + top·R < 2m: subtract m unless it is already below m.
    let hi = &t[n..2 * n];
    let mut br = 0;
    for ((o, &tj), &mj) in out.iter_mut().zip(hi).zip(m) {
        let (d, b2) = sbb(tj, mj, br);
        *o = d;
        br = b2;
    }
    let keep_t = mask((top ^ 1) & br);
    for (o, &tj) in out.iter_mut().zip(hi) {
        *o = (tj & keep_t) | (*o & !keep_t);
    }
    // The buffer held a product of (possibly secret) operands.
    crate::security::zeroize::wipe_words(t);
}

/// `t = a · b` (`t` has `2n` words).
fn mul_wide(t: &mut [u32], a: &[u32], b: &[u32]) {
    let n = a.len();
    t.fill(0);
    let mut i = 0;
    // Two rows at a time; t[i+n] and t[i+n+1] are still zero here.
    while i + 1 < n {
        let (c0, c1, last) = mac2(&mut t[i..i + n], a, b[i], b[i + 1], (0, 0), 0);
        let (lo, hi) = mac(last, b[i + 1], c0, c1);
        t[i + n] = lo;
        t[i + n + 1] = hi;
        i += 2;
    }
    if i < n {
        t[i + n] = mac_row(&mut t[i..i + n], a, b[i], 0);
    }
}

/// `t = a²` (`t` has `2n` words): each cross product once, doubled, plus
/// the squares on the diagonal.
fn sqr_wide(t: &mut [u32], a: &[u32]) {
    let n = a.len();
    t.fill(0);
    // Cross products a[i]·a[j], i < j: row i adds a[i+1..]·a[i] at
    // t[2i+1..]; t[i+n] is still zero when it gets the row's carry.
    let mut i = 0;
    // Rows i and i+1 together (i+1 ≤ n−2): row i's first word here, then
    // `mac2` with row i+1 one word behind (its first term lands at t[2i+3]).
    while i + 2 < n {
        let (l, c0) = mac(a[i + 1], a[i], t[2 * i + 1], 0);
        t[2 * i + 1] = l;
        let (c0, c1, last) = mac2(
            &mut t[2 * i + 2..i + n],
            &a[i + 2..],
            a[i],
            a[i + 1],
            (c0, 0),
            0,
        );
        let (lo, hi) = mac(last, a[i + 1], c0, c1);
        t[i + n] = lo;
        t[i + n + 1] = hi;
        i += 2;
    }
    if i + 1 < n {
        t[i + n] = mac_row(&mut t[2 * i + 1..i + n], &a[i + 1..], a[i], 0);
    }
    let mut carry = 0;
    for x in t.iter_mut() {
        let next = *x >> 31;
        *x = (*x << 1) | carry;
        carry = next;
    }
    let mut c = 0u32;
    for (i, &ai) in a.iter().enumerate() {
        let (lo, hi) = mac(ai, ai, t[2 * i], c);
        t[2 * i] = lo;
        let (s, c2) = adc(t[2 * i + 1], hi, 0);
        t[2 * i + 1] = s;
        c = c2;
    }
}

/// `out = a · b · R⁻¹ mod m`.  `a, b < m`, `m` odd.
pub fn mont_mul(out: &mut [u32], a: &[u32], b: &[u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut buf = [0u32; WIDE];
    let t = &mut buf[..2 * n];
    mul_wide(t, &a[..n], &b[..n]);
    redc(&mut out[..n], t, m, minv);
}

/// `out = a² · R⁻¹ mod m` (`a < m`).
pub fn mont_sqr(out: &mut [u32], a: &[u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut buf = [0u32; WIDE];
    let t = &mut buf[..2 * n];
    sqr_wide(t, &a[..n]);
    redc(&mut out[..n], t, m, minv);
}

/// `x = x · y · R⁻¹ mod m` (in place: the product is formed before `x`
/// is written).
pub fn mont_mul_assign(x: &mut [u32], y: &[u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut buf = [0u32; WIDE];
    let t = &mut buf[..2 * n];
    mul_wide(t, &x[..n], &y[..n]);
    redc(&mut x[..n], t, m, minv);
}

/// `x = x² · R⁻¹ mod m` (in place).
pub fn mont_sqr_assign(x: &mut [u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut buf = [0u32; WIDE];
    let t = &mut buf[..2 * n];
    sqr_wide(t, &x[..n]);
    redc(&mut x[..n], t, m, minv);
}

/// Convert out of Montgomery form: `x = x · R⁻¹ mod m`.
pub fn from_mont(x: &mut [u32], m: &[u32], minv: u32) {
    let n = m.len();
    let mut one = [0u32; MAX_WORDS];
    one[0] = 1;
    mont_mul_assign(x, &one[..n], m, minv);
}

/// `out = table[idx]` where `table` holds `entries` numbers of `out.len()`
/// words each, reading every entry (the index is secret).
pub fn select_from_table(out: &mut [u32], table: &[u32], entries: usize, idx: u32) {
    let n = out.len();
    out.fill(0);
    for e in 0..entries {
        let hit = ct_zero_mask_u32(e as u32 ^ idx);
        let row = &table[e * n..e * n + n];
        for j in 0..n {
            out[j] |= row[j] & hit;
        }
    }
}

// ─── Small-integer helpers ───────────────────────────────────────────────────

/// `a⁻¹ mod m` for coprime `a`, `m` (`m` > 1).  Variable-time (extended
/// Euclid): public values only — secrets use [`ct_inv_mod_small_prime`].
pub fn inv_mod_u32(a: u32, m: u32) -> Option<u32> {
    let (mut r0, mut r1) = (i64::from(m), i64::from(a % m));
    let (mut t0, mut t1) = (0i64, 1i64);
    while r1 != 0 {
        let q = r0 / r1;
        (r0, r1) = (r1, r0 - q * r1);
        (t0, t1) = (t1, t0 - q * t1);
    }
    if r0 != 1 {
        return None;
    }
    Some(t0.rem_euclid(i64::from(m)) as u32)
}

/// Jacobi symbol `(a / n)` for odd `n` > 0.  Variable-time (see the Lucas
/// `D` search in `rsa_keygen` for its one use on a secret residue).
pub fn jacobi_u32(mut a: u32, mut n: u32) -> i32 {
    debug_assert!(n & 1 == 1);
    a %= n;
    let mut t = 1;
    while a != 0 {
        while a & 1 == 0 {
            a >>= 1;
            if n % 8 == 3 || n % 8 == 5 {
                t = -t;
            }
        }
        core::mem::swap(&mut a, &mut n);
        if a % 4 == 3 && n % 4 == 3 {
            t = -t;
        }
        a %= n;
    }
    if n == 1 {
        t
    } else {
        0
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use rsa::BigUint;
    use std::vec;
    use std::vec::Vec;

    fn big(a: &[u32]) -> BigUint {
        BigUint::from_slice(a)
    }

    fn words(x: &BigUint, n: usize) -> Vec<u32> {
        let bytes = x.to_bytes_le();
        let mut v = vec![0u32; n.max(bytes.len().div_ceil(4))];
        for (i, b) in bytes.iter().enumerate() {
            v[i / 4] |= u32::from(*b) << (8 * (i % 4));
        }
        v.truncate(n);
        v
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn fill(&mut self, n: usize) -> Vec<u32> {
            (0..n).map(|_| self.next()).collect()
        }
    }

    fn odd_modulus(rng: &mut Lcg, n: usize) -> Vec<u32> {
        let mut m = rng.fill(n);
        m[0] |= 1;
        m[n - 1] |= 0x8000_0000;
        m
    }

    // The one-row-at-a-time versions the two-row (`mac2`) code replaced:
    // the new code must produce exactly the same words.
    fn ref_mul_wide(t: &mut [u32], a: &[u32], b: &[u32]) {
        let n = a.len();
        t.fill(0);
        for (i, &bi) in b.iter().enumerate() {
            t[i + n] = mac_row(&mut t[i..i + n], a, bi, 0);
        }
    }

    fn ref_sqr_wide(t: &mut [u32], a: &[u32]) {
        let n = a.len();
        t.fill(0);
        for i in 0..n.saturating_sub(1) {
            t[i + n] = mac_row(&mut t[2 * i + 1..i + n], &a[i + 1..], a[i], 0);
        }
        let mut carry = 0;
        for x in t.iter_mut() {
            let next = *x >> 31;
            *x = (*x << 1) | carry;
            carry = next;
        }
        let mut c = 0u32;
        for (i, &ai) in a.iter().enumerate() {
            let (lo, hi) = mac(ai, ai, t[2 * i], c);
            t[2 * i] = lo;
            let (s, c2) = adc(t[2 * i + 1], hi, 0);
            t[2 * i + 1] = s;
            c = c2;
        }
    }

    fn ref_redc(out: &mut [u32], t: &mut [u32], m: &[u32], minv: u32) {
        let n = m.len();
        let mut top = 0;
        for i in 0..n {
            let u = t[i].wrapping_mul(minv);
            let c = mac_row(&mut t[i..i + n], m, u, 0);
            let (s, c2) = adc(t[i + n], c, top);
            t[i + n] = s;
            top = c2;
        }
        let hi = &t[n..2 * n];
        let mut br = 0;
        for ((o, &tj), &mj) in out.iter_mut().zip(hi).zip(m) {
            let (d, b2) = sbb(tj, mj, br);
            *o = d;
            br = b2;
        }
        let keep_t = mask((top ^ 1) & br);
        for (o, &tj) in out.iter_mut().zip(hi) {
            *o = (tj & keep_t) | (*o & !keep_t);
        }
    }

    #[test]
    fn two_row_products_match_one_row() {
        let mut rng = Lcg(23);
        for n in 1usize..=40 {
            for round in 0..6 {
                // Round 0: all-ones operands (every carry chain at its limit).
                let (a, b) = if round == 0 {
                    (vec![u32::MAX; n], vec![u32::MAX; n])
                } else {
                    (rng.fill(n), rng.fill(n))
                };
                let (mut t, mut r) = (vec![7u32; 2 * n], vec![9u32; 2 * n]);
                mul_wide(&mut t, &a, &b);
                ref_mul_wide(&mut r, &a, &b);
                assert_eq!(t, r, "mul_wide n={n}");
                assert_eq!(big(&t), big(&a) * big(&b), "mul_wide value n={n}");
                sqr_wide(&mut t, &a);
                ref_sqr_wide(&mut r, &a);
                assert_eq!(t, r, "sqr_wide n={n}");
                assert_eq!(big(&t), big(&a) * big(&a), "sqr_wide value n={n}");
            }
        }
    }

    #[test]
    fn two_row_redc_matches_one_row() {
        let mut rng = Lcg(29);
        for n in 1usize..=40 {
            for round in 0..6 {
                let m = if round == 0 {
                    vec![u32::MAX; n]
                } else {
                    odd_modulus(&mut rng, n)
                };
                let mb = big(&m);
                // t < m·R: a product of two residues.
                let a = words(&(big(&rng.fill(n)) % &mb), n);
                let b = if round == 1 {
                    let mut x = m.clone();
                    x[0] -= 1; // m − 1
                    x
                } else {
                    words(&(big(&rng.fill(n)) % &mb), n)
                };
                let minv = neg_inv32(m[0]);
                let mut t = vec![0u32; 2 * n];
                mul_wide(&mut t, &a, &b);
                let mut t2 = t.clone();
                let (mut out, mut r) = (vec![0u32; n], vec![0u32; n]);
                redc(&mut out, &mut t, &m, minv);
                ref_redc(&mut r, &mut t2, &m, minv);
                assert_eq!(out, r, "redc n={n} round={round}");
            }
        }
    }

    #[test]
    fn mont_mul_matches_reference() {
        let mut rng = Lcg(1);
        for &n in &[1usize, 2, 8, 32, 64, 128] {
            for _ in 0..4 {
                let m = odd_modulus(&mut rng, n);
                let mb = big(&m);
                let a = words(&(big(&rng.fill(n)) % &mb), n);
                let b = words(&(big(&rng.fill(n)) % &mb), n);
                let minv = neg_inv32(m[0]);
                let mut out = vec![0u32; n];
                mont_mul(&mut out, &a, &b, &m, minv);
                let r = BigUint::from(1u8) << (32 * n);
                let rinv = r.modpow(&(&mb - 2u32), &mb); // m prime not required: check a*b == out*R
                let _ = rinv;
                // out·R ≡ a·b (mod m)
                assert_eq!((big(&out) * &r) % &mb, (big(&a) * big(&b)) % &mb);
                assert!(big(&out) < mb);
            }
        }
    }

    #[test]
    fn mont_sqr_matches_mont_mul() {
        let mut rng = Lcg(11);
        for n in 1usize..=20 {
            for _ in 0..8 {
                let m = odd_modulus(&mut rng, n);
                let mb = big(&m);
                let a = words(&(big(&rng.fill(n)) % &mb), n);
                let minv = neg_inv32(m[0]);
                let mut s = vec![0u32; n];
                let mut p = vec![0u32; n];
                mont_sqr(&mut s, &a, &m, minv);
                mont_mul(&mut p, &a, &a, &m, minv);
                assert_eq!(s, p, "n={n}");
            }
        }
        for &n in &[32usize, 48, 64, 128] {
            let m = odd_modulus(&mut rng, n);
            let mb = big(&m);
            let a = words(&(big(&rng.fill(n)) % &mb), n);
            let minv = neg_inv32(m[0]);
            let mut s = vec![0u32; n];
            mont_sqr(&mut s, &a, &m, minv);
            let r = BigUint::from(1u8) << (32 * n);
            assert_eq!((big(&s) * &r) % &mb, (big(&a) * big(&a)) % &mb);
        }
        // Extremes: m − 1 squared, all-ones modulus.
        let m = vec![u32::MAX; 8];
        let mut a = m.clone();
        a[0] -= 1;
        let minv = neg_inv32(m[0]);
        let (mut s, mut p) = (vec![0u32; 8], vec![0u32; 8]);
        mont_sqr(&mut s, &a, &m, minv);
        mont_mul(&mut p, &a, &a, &m, minv);
        assert_eq!(s, p);
    }

    #[test]
    fn neg_inv_is_inverse() {
        for m0 in [1u32, 3, 0xFFFF_FFFF, 0x1234_5679, 0x8000_0001] {
            assert_eq!(m0.wrapping_mul(neg_inv32(m0)), u32::MAX);
        }
    }

    #[test]
    fn modular_helpers_match_reference() {
        let mut rng = Lcg(7);
        for &n in &[1usize, 4, 33] {
            for _ in 0..20 {
                let m = odd_modulus(&mut rng, n);
                let mb = big(&m);
                let x = words(&(big(&rng.fill(n)) % &mb), n);
                let y = words(&(big(&rng.fill(n)) % &mb), n);

                let mut s = x.clone();
                mod_add(&mut s, &y, &m);
                assert_eq!(big(&s), (big(&x) + big(&y)) % &mb);

                let mut d = x.clone();
                mod_sub(&mut d, &y, &m);
                assert_eq!(big(&d), (big(&x) + &mb - big(&y)) % &mb);

                let mut dd = x.clone();
                mod_double(&mut dd, &m);
                assert_eq!(big(&dd), (big(&x) * 2u32) % &mb);

                for bit in [0u32, 1] {
                    let mut c = x.clone();
                    mod_double_if(&mut c, &m, bit);
                    let want = if bit == 1 {
                        (big(&x) * 2u32) % &mb
                    } else {
                        big(&x)
                    };
                    assert_eq!(big(&c), want);
                }

                let mut h = x.clone();
                mod_half(&mut h, &m);
                assert_eq!((big(&h) * 2u32) % &mb, big(&x));

                let mut r = vec![0u32; n];
                r_mod(&m, &mut r);
                assert_eq!(big(&r), (BigUint::from(1u8) << (32 * n)) % &mb);
            }
        }
    }

    #[test]
    fn small_divisors_and_shifts() {
        let mut rng = Lcg(3);
        for _ in 0..50 {
            let a = rng.fill(9);
            let k = rng.next() | 1;
            let p = (rng.next() as u16) | 1;
            assert_eq!(BigUint::from(rem_small(&a, k)), big(&a) % k);
            let d = (rng.next() % 131_071) + 1; // < 2^17
            let rc = ct_recip(d);
            assert_eq!(rc, u32::MAX / d);
            assert_eq!(BigUint::from(ct_rem_small(&a, d, rc)), big(&a) % d);
            let mut qa = a.clone();
            let rr = ct_divrem_small(&mut qa, d, rc);
            assert_eq!(big(&qa) * d + rr, big(&a));
            let _ = p;
            let mut q = a.clone();
            let r = div_small(&mut q, k);
            assert_eq!(big(&q) * k + r, big(&a));
            for s in [0usize, 1, 31, 32, 33, 100] {
                let mut x = a.clone();
                shr(&mut x, s);
                assert_eq!(big(&x), big(&a) >> s);
                let mut y = a.clone();
                shl(&mut y, s);
                assert_eq!(big(&y), (big(&a) << s) % (BigUint::from(1u8) << (32 * 9)));
            }
            let mut prod = vec![0u32; 18];
            let b = rng.fill(9);
            mul_into(&mut prod, &a, &b);
            assert_eq!(big(&prod), big(&a) * big(&b));
        }
    }

    #[test]
    fn constant_time_helpers_match_reference() {
        let mut rng = Lcg(19);
        for _ in 0..200 {
            let n = (rng.next() % 9 + 1) as usize;
            let a = rng.fill(n);
            let mut b = rng.fill(n);
            assert_eq!(ct_lt(&a, &b) != 0, big(&a) < big(&b));
            assert_eq!(ct_eq_mask(&a, &a), u32::MAX);
            b[0] ^= 1 << (rng.next() % 32);
            assert_eq!(ct_eq_mask(&a, &b) != 0, a == b);
            let mut z = a.clone();
            let sh = rng.next() % 32;
            z[0] &= !((1u32 << sh) - 1);
            z[0] |= 1 << sh;
            assert_eq!(ct_tz(&z) as usize, trailing_zeros(&z));
            assert_eq!(ct_bit_len(&a) as usize, bit_len(&a));
            assert_eq!(ct_is_zero(&a) != 0, is_zero(&a));
            let s = rng.next() % (32 * n as u32);
            let mut x = a.clone();
            ct_shr(&mut x, s);
            let mut y = a.clone();
            shr(&mut y, s as usize);
            assert_eq!(x, y);
        }
        assert_eq!(ct_tz(&[0, 0]), 0);
        assert_eq!(ct_bit_len(&[0, 0]), 0);
        for p in [3u32, 5, 65_537, 131_071] {
            let rc = ct_recip(p);
            for r in [1u32, 2, p - 1, p / 2 + 1, 12_345 % p] {
                if r == 0 {
                    continue;
                }
                let inv = ct_inv_mod_small_prime(r, p, rc);
                assert_eq!(
                    u64::from(inv) * u64::from(r) % u64::from(p),
                    1,
                    "{r} mod {p}"
                );
            }
        }
        for (a, b) in [
            (12u32, 18u32),
            (17, 5),
            (0, 7),
            (65_536, 6),
            (1, 1),
            (96, 64),
        ] {
            let g = {
                let (mut x, mut y) = (a, b);
                while y != 0 {
                    (x, y) = (y, x % y);
                }
                x
            };
            assert_eq!(ct_gcd_u32(a, b), g, "gcd({a},{b})");
        }
        // Multi-word GCD steps against the reference.
        for _ in 0..50 {
            let u = rng.fill(4);
            let mut v = rng.fill(4);
            v[0] |= 1;
            let want = {
                let (mut x, mut y) = (big(&u), big(&v));
                while y != BigUint::from(0u8) {
                    let r = &x % &y;
                    x = y;
                    y = r;
                }
                x
            };
            let (mut uu, mut vv) = (u.clone(), v.clone());
            for _ in 0..2 * 128 {
                ct_gcd_step(&mut uu, &mut vv);
            }
            assert!(is_zero(&uu));
            assert_eq!(big(&vv), want);
        }
    }

    #[test]
    fn small_number_theory() {
        assert_eq!(
            inv_mod_u32(3, 65537).map(|i| u64::from(i) * 3 % 65537),
            Some(1)
        );
        assert_eq!(inv_mod_u32(65537 * 2, 65537), None);
        // Jacobi against Euler's criterion for a prime modulus.
        let p = 1_000_003u32;
        for a in 1..200u32 {
            let e = BigUint::from(a).modpow(&BigUint::from((p - 1) / 2), &BigUint::from(p));
            let expect = if e == BigUint::from(1u8) { 1 } else { -1 };
            assert_eq!(jacobi_u32(a, p), expect);
        }
        assert_eq!(jacobi_u32(9, 15), 0);
    }

    #[test]
    fn table_select_and_bytes() {
        let table: Vec<u32> = (0..48).collect();
        let mut out = [0u32; 3];
        select_from_table(&mut out, &table, 16, 5);
        assert_eq!(out, [15, 16, 17]);
        let mut w = [0u32; 3];
        from_be_bytes(&mut w, &[1, 2, 3, 4, 5]);
        assert_eq!(w, [0x0203_0405, 1, 0]);
        let mut b = [0u8; 6];
        to_be_bytes(&w, &mut b);
        assert_eq!(b, [0, 1, 2, 3, 4, 5]);
    }
}
