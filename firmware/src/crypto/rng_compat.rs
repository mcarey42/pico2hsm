//! Bridge from the firmware's `rand_core` 0.6 RNGs to the `rand_core` 0.10
//! traits that the RustCrypto 0.14 ECC crates (`elliptic-curve`, `ecdsa`)
//! take.
//!
//! Every public crypto function keeps its 0.6 RNG bounds (the TRNG wrapper
//! `FwRng`, RSA and the dalek crates are all still on 0.6) and wraps its RNG
//! in [`Compat`] only where it calls into a 0.14 API.

use core::convert::Infallible;

/// Borrowed `rand_core` 0.6 RNG presented as a `rand_core` 0.10 crypto RNG.
///
/// Draws delegate to the inner RNG's infallible `fill_bytes` / `next_u*`,
/// which is what the 0.13 crates called: `FwRng` resets the chip on a TRNG
/// failure rather than return, so the 0.10 error type is `Infallible`.
pub struct Compat<'a, R>(pub &'a mut R);

impl<R> rand_core_010::TryRng for Compat<'_, R>
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R> rand_core_010::TryCryptoRng for Compat<'_, R> where
    R: rand_core::RngCore + rand_core::CryptoRng
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::asymmetric::generate_ec_keypair;
    use elliptic_curve::Generate;
    use pico2hsm_core::key::KeyType;
    use rand_core::{CryptoRng, RngCore};

    /// Same counter-hash stream as the ECC known-answer tests.
    #[derive(Clone)]
    struct CounterRng(u64);

    impl RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }

        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15u64);
                let v = self.0.wrapping_mul(0x6c62272e07bb0142u64) ^ 0xbf58476d1ce4e5b9u64;
                let vb = v.to_le_bytes();
                chunk.copy_from_slice(&vb[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for CounterRng {}

    #[test]
    fn compat_feeds_0_14_keygen() {
        let nz = p256::NonZeroScalar::generate_from_rng(&mut Compat(&mut CounterRng(1)));
        let direct = p256::SecretKey::from(nz);
        let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut CounterRng(1)).unwrap();
        assert_eq!(direct.to_bytes().as_slice(), pair.private_key.as_slice());
    }

    #[test]
    fn compat_draws_from_the_inner_rng() {
        use rand_core_010::Rng;

        let mut inner = CounterRng(42);
        let mut reference = inner.clone();
        let mut compat = Compat(&mut inner);

        let mut a = [0u8; 37];
        let mut b = [0u8; 37];
        compat.fill_bytes(&mut a);
        reference.fill_bytes(&mut b);
        assert_eq!(a, b);

        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        a.copy_from_slice(&compat.next_u64().to_le_bytes());
        reference.fill_bytes(&mut b);
        assert_eq!(a, b);
    }
}
