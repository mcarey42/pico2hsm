# Security Policy

## Supported versions

| Version | Status |
|---------|--------|
| 2.0.x | In development on `main` (Storage V2, partition tables; breaking, not yet tagged) |
| 1.0.x | Current release series (`v1.0.1`) |
| 0.9.x | Pre-release series; not supported |

## Threat model summary

pico2hsm protects against several classes of attack: network-level key theft is prevented by DKEK-encrypted key export (AES-256-CBC with key-check values); unauthorized key usage requires PIN or SO-PIN authentication with configurable retry lockout; firmware tampering is detected via secure boot once the device is provisioned (`docs/PROVISIONING.md`); and USB passive eavesdropping is mitigated by OS-level access control on the CCID interface (the device does not implement wireless transport).

pico2hsm does **not** protect against: physical attackers with flash-read hardware (the RP2350 is a general-purpose microcontroller, not a certified secure element -- OTP row locking improves but does not eliminate the physical attack surface); side-channel attacks on the Cortex-M33 (ECC operations use software implementations without masking or constant-time guarantees beyond what the RustCrypto crates provide, and there is no hardware ECC accelerator); or denial-of-service via USB (any process with USB device access can send arbitrary CCID commands to the device).

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory feature:

1. Go to https://github.com/mcarey42/pico2hsm/security/advisories
2. Click "New draft security advisory"
3. Describe the vulnerability, affected versions, and a proof-of-concept if available
4. We will acknowledge receipt within 72 hours and aim for a fix within 30 days for critical issues

For encrypted communication, a GPG key or Signal contact can be provided on request via the advisory channel.

## Disclosure policy

- We follow responsible disclosure. Please allow 90 days for us to develop and release a patch before public disclosure.
- Researchers will be credited in the release notes unless anonymity is requested.
- We do not currently offer a bug bounty program.

## Known limitations (not considered vulnerabilities)

These are documented design limitations within the current threat model, not bugs:

- **PIN hashing without a per-device salt.** PINs are hashed with PBKDF2-HMAC-SHA256 (10,000 iterations) and a random 16-byte salt per credential, but the device-identity part of the salt is a fixed string, not derived from hardware identity. The PIN records are themselves encrypted under the device's storage key, so an offline dictionary attack against short PINs needs both the flash contents and the OTP storage secret. Physical extraction of both is outside the current threat model. See PUNCHOUT for tracking.

- **DKEK exchange requires an enrolled peer.** The DKEK exchange (EXTRAS P1=0x35..0x38; ephemeral P-256 ECDH, not full Noise_XX) authenticates the peer by its device identity key (SC-HSM key ref 0xFE, generated from the TRNG at INITIALIZE), which must be enrolled with the SO-PIN before the first transfer (P1=0x3D; PUNCHOUT C1, resolved). The unauthenticated V1 exchange (P1=0x31..0x33) is removed and returns 6D00.

- **No side-channel hardening.** Cryptographic operations (ECDSA sign, ECDH, RSA) use unmasked software implementations. Timing and power analysis attacks are feasible for an attacker with physical access to the device.
