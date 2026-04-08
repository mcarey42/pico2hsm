# Security Policy

## Supported versions

| Version | Status |
|---------|--------|
| 0.9.x | Current development series -- receives security fixes |
| < 0.9 | No longer maintained |

## Threat model summary

pico2hsm protects against several classes of attack: network-level key theft is prevented by DKEK-encrypted key export (AES-256-CBC with key-check values); unauthorized key usage requires PIN or SO-PIN authentication with configurable retry lockout; firmware tampering is detected via secure boot when the firmware signing key and OTP row locking are applied; and USB passive eavesdropping is mitigated by OS-level access control on the CCID interface (the device does not implement wireless transport).

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

- **PIN hashing without per-device salt.** PIN verification uses PBKDF2 but does not incorporate a per-device salt derived from hardware identity. An attacker who can extract flash contents could mount an offline dictionary attack against short PINs. Physical flash extraction is outside the current threat model. See PUNCHOUT for tracking.

- **V1 Noise exchange provides no mutual authentication.** The V1 DKEK exchange (P1=0x30..0x34) uses unauthenticated ephemeral ECDH. It is deprecated; use V2 (P1=0x35..0x38) for new deployments. Note that V2 mutual authentication signature verification is not yet implemented (see PUNCHOUT C1) and must be completed before v1.0.

- **Self-signed TLS in anonymous mode.** The Python daemon's standalone DKEK exchange mode uses TLS with `CERT_NONE` verification, which encrypts but does not authenticate peers. For network deployments, configure mutual TLS with a CA-signed certificate (see PUNCHOUT C2).

- **No side-channel hardening.** Cryptographic operations (ECDSA sign, ECDH, RSA) use unmasked software implementations. Timing and power analysis attacks are feasible for an attacker with physical access to the device.
