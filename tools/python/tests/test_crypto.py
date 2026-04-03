"""Unit tests for host-side cryptographic helpers in pico2hsm.crypto.

No hardware required.  Tests cover key wrapping, DKEK derivation,
certificate generation, and utility functions.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pico2hsm.crypto import (
    DKEK_SALT_SIZE,
    WRAP_KEY_BYTES,
    WrappedKey,
    _kdf,
    _pkcs7_pad,
    _pkcs7_unpad,
    decrypt_aes_gcm,
    derive_dkek_share,
    encrypt_aes_gcm,
    generate_ec_keypair,
    generate_rsa_keypair,
    generate_self_signed_cert,
    load_certificate,
    unwrap_key,
    wrap_key,
    xor_dkek_shares,
)


# ---------------------------------------------------------------------------
# Key wrapping / unwrapping
# ---------------------------------------------------------------------------

class TestWrapKey:
    def test_wrap_returns_wrapped_key(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        assert isinstance(wrapped, WrappedKey)

    def test_wrapped_blob_has_correct_version(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        assert wrapped.version == 0x01

    def test_wrapped_blob_iv_is_16_bytes(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        assert len(wrapped.iv) == 16

    def test_wrapped_blob_mac_is_32_bytes(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        assert len(wrapped.mac) == 32

    def test_wrap_different_dkek_gives_different_blob(self, sample_aes_key):
        dkek1 = bytes(range(32))
        dkek2 = bytes(range(1, 33))
        w1 = wrap_key(sample_aes_key, dkek1)
        w2 = wrap_key(sample_aes_key, dkek2)
        assert w1.ciphertext != w2.ciphertext

    def test_wrap_rejects_short_dkek(self, sample_aes_key):
        with pytest.raises(ValueError, match="DKEK must be"):
            wrap_key(sample_aes_key, b"\x00" * 16)

    def test_flags_stored_in_blob(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek, flags=0xDEADBEEF)
        assert wrapped.flags == 0xDEADBEEF


class TestUnwrapKey:
    def test_roundtrip(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        recovered = unwrap_key(wrapped, sample_dkek)
        assert recovered == sample_aes_key

    def test_roundtrip_various_key_sizes(self, sample_dkek):
        for key_size in (16, 24, 32, 48, 64):
            key = os.urandom(key_size)
            wrapped = wrap_key(key, sample_dkek)
            recovered = unwrap_key(wrapped, sample_dkek)
            assert recovered == key

    def test_wrong_dkek_raises_mac_error(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        wrong_dkek = bytes([b ^ 0xFF for b in sample_dkek])
        with pytest.raises(ValueError, match="MAC verification failed"):
            unwrap_key(wrapped, wrong_dkek)

    def test_tampered_ciphertext_raises_mac_error(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        raw = bytearray(wrapped.raw)
        # Flip a byte in the ciphertext area
        raw[WrappedKey.HEADER_SIZE] ^= 0xFF
        tampered = WrappedKey(bytes(raw))
        with pytest.raises(ValueError, match="MAC verification failed"):
            unwrap_key(tampered, sample_dkek)

    def test_wrong_version_raises(self, sample_dkek, sample_aes_key):
        wrapped = wrap_key(sample_aes_key, sample_dkek)
        raw = bytearray(wrapped.raw)
        raw[0] = 0xFF  # corrupt version byte
        bad = WrappedKey(bytes(raw))
        with pytest.raises(ValueError, match="version"):
            unwrap_key(bad, sample_dkek)

    def test_short_blob_raises(self):
        with pytest.raises(ValueError):
            WrappedKey(b"\x00" * 10)


# ---------------------------------------------------------------------------
# DKEK share derivation
# ---------------------------------------------------------------------------

class TestDeriveDkekShare:
    def test_returns_32_byte_key(self):
        key, salt = derive_dkek_share("password")
        assert len(key) == WRAP_KEY_BYTES
        assert len(salt) == DKEK_SALT_SIZE

    def test_deterministic_with_same_salt(self):
        salt = os.urandom(DKEK_SALT_SIZE)
        key1, _ = derive_dkek_share("password", salt=salt)
        key2, _ = derive_dkek_share("password", salt=salt)
        assert key1 == key2

    def test_different_passwords_give_different_keys(self):
        salt = os.urandom(DKEK_SALT_SIZE)
        key1, _ = derive_dkek_share("password1", salt=salt)
        key2, _ = derive_dkek_share("password2", salt=salt)
        assert key1 != key2

    def test_different_salts_give_different_keys(self):
        salt1 = os.urandom(DKEK_SALT_SIZE)
        salt2 = os.urandom(DKEK_SALT_SIZE)
        key1, _ = derive_dkek_share("password", salt=salt1)
        key2, _ = derive_dkek_share("password", salt=salt2)
        assert key1 != key2

    def test_random_salt_generated_if_not_provided(self):
        _, salt1 = derive_dkek_share("password")
        _, salt2 = derive_dkek_share("password")
        # Overwhelmingly likely to differ
        assert salt1 != salt2


class TestXorDkekShares:
    def test_single_share_identity(self):
        share = bytes(range(32))
        assert xor_dkek_shares(share) == share

    def test_two_shares_xor(self):
        share1 = bytes([0xAA] * 32)
        share2 = bytes([0x55] * 32)
        result = xor_dkek_shares(share1, share2)
        assert result == bytes([0xFF] * 32)

    def test_three_shares_reconstruct(self):
        dkek = os.urandom(32)
        share1 = os.urandom(32)
        share2 = os.urandom(32)
        share3 = bytes([dkek[i] ^ share1[i] ^ share2[i] for i in range(32)])
        reconstructed = xor_dkek_shares(share1, share2, share3)
        assert reconstructed == dkek

    def test_mismatched_share_lengths_raises(self):
        with pytest.raises(ValueError, match="same length"):
            xor_dkek_shares(bytes(32), bytes(16))

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="No shares"):
            xor_dkek_shares()


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

class TestGenerateSelfSignedCert:
    def test_generates_valid_der(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key)
        assert isinstance(der, bytes)
        assert len(der) > 100

    def test_cert_is_parseable(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key)
        cert = load_certificate(der)
        assert cert is not None

    def test_common_name_set(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key, subject_name="mytestdevice")
        cert = load_certificate(der)
        from cryptography.x509.oid import NameOID
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        assert cn.value == "mytestdevice"

    def test_self_signed_issuer_equals_subject(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key)
        cert = load_certificate(der)
        assert cert.subject == cert.issuer

    def test_validity_period(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key, validity_days=365)
        cert = load_certificate(der)
        import datetime
        # not_valid_after_utc is cryptography >=42; fall back to not_valid_after
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        # Strip tzinfo if one is aware and the other is not (older cryptography)
        if hasattr(after, "tzinfo") and after.tzinfo and not (hasattr(before, "tzinfo") and before.tzinfo):
            after = after.replace(tzinfo=None)
        delta = after - before
        assert 364 <= delta.days <= 366  # allow ±1 day for time skew

    def test_rsa_key(self, sample_rsa_private_key):
        der = generate_self_signed_cert(sample_rsa_private_key, subject_name="rsa-test")
        cert = load_certificate(der)
        from cryptography.x509.oid import NameOID
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        assert cn.value == "rsa-test"

    def test_basic_constraints_extension(self, sample_ec_private_key):
        from cryptography import x509
        der = generate_self_signed_cert(sample_ec_private_key)
        cert = load_certificate(der)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True


class TestLoadCertificate:
    def test_load_der(self, sample_ec_private_key):
        der = generate_self_signed_cert(sample_ec_private_key)
        cert = load_certificate(der)
        assert cert is not None

    def test_load_pem(self, sample_ec_private_key):
        from pico2hsm.crypto import cert_to_pem
        der = generate_self_signed_cert(sample_ec_private_key)
        cert_obj = load_certificate(der)
        pem = cert_to_pem(cert_obj)
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        reloaded = load_certificate(pem)
        assert reloaded.serial_number == cert_obj.serial_number


# ---------------------------------------------------------------------------
# EC / RSA keypair generation (host-side)
# ---------------------------------------------------------------------------

class TestGenerateECKeypair:
    @pytest.mark.parametrize("curve", ["P-256", "P-384", "P-521", "secp256k1"])
    def test_generates_pem_pair(self, curve):
        priv, pub = generate_ec_keypair(curve)
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    def test_unsupported_curve_raises(self):
        with pytest.raises(ValueError, match="Unsupported curve"):
            generate_ec_keypair("brainpool256")

    def test_different_calls_give_different_keys(self):
        priv1, _ = generate_ec_keypair("P-256")
        priv2, _ = generate_ec_keypair("P-256")
        assert priv1 != priv2


class TestGenerateRSAKeypair:
    def test_generates_pem_pair(self):
        priv, pub = generate_rsa_keypair(1024)  # small for speed
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    def test_key_size_respected(self):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv_pem, _ = generate_rsa_keypair(1024)
        key = load_pem_private_key(priv_pem, password=None)
        assert key.key_size == 1024


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

class TestAesGcm:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, pico2hsm!"
        blob = encrypt_aes_gcm(key, plaintext)
        recovered = decrypt_aes_gcm(key, blob)
        assert recovered == plaintext

    def test_encrypt_with_aad(self):
        key = os.urandom(32)
        plaintext = b"sensitive data"
        aad = b"context header"
        blob = encrypt_aes_gcm(key, plaintext, aad=aad)
        recovered = decrypt_aes_gcm(key, blob, aad=aad)
        assert recovered == plaintext

    def test_wrong_aad_raises(self):
        from cryptography.exceptions import InvalidTag
        key = os.urandom(32)
        blob = encrypt_aes_gcm(key, b"data", aad=b"correct")
        with pytest.raises(Exception):  # InvalidTag or similar
            decrypt_aes_gcm(key, blob, aad=b"wrong")

    def test_wrong_key_raises(self):
        key = os.urandom(32)
        blob = encrypt_aes_gcm(key, b"data")
        with pytest.raises(Exception):
            decrypt_aes_gcm(os.urandom(32), blob)

    def test_nonce_is_random(self):
        key = os.urandom(32)
        blob1 = encrypt_aes_gcm(key, b"x")
        blob2 = encrypt_aes_gcm(key, b"x")
        # nonces (first 12 bytes) should differ
        assert blob1[:12] != blob2[:12]

    def test_blob_length(self):
        key = os.urandom(32)
        plaintext = bytes(100)
        blob = encrypt_aes_gcm(key, plaintext)
        # nonce (12) + ciphertext (100) + tag (16)
        assert len(blob) == 12 + 100 + 16


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class TestPKCS7:
    def test_pad_to_block_boundary(self):
        data = bytes(10)
        padded = _pkcs7_pad(data, 16)
        assert len(padded) == 16
        assert padded[-1] == 6  # 16-10 = 6

    def test_pad_full_block_adds_extra_block(self):
        data = bytes(16)
        padded = _pkcs7_pad(data, 16)
        assert len(padded) == 32
        assert padded[-1] == 16

    def test_unpad_basic(self):
        data = bytes(10) + bytes([6] * 6)
        unpadded = _pkcs7_unpad(data)
        assert len(unpadded) == 10

    def test_roundtrip(self):
        for size in range(1, 33):
            original = os.urandom(size)
            padded = _pkcs7_pad(original, 16)
            assert len(padded) % 16 == 0
            recovered = _pkcs7_unpad(padded)
            assert recovered == original

    def test_unpad_empty_raises(self):
        with pytest.raises(ValueError):
            _pkcs7_unpad(b"")


class TestKDF:
    def test_returns_correct_length(self):
        key = os.urandom(32)
        result = _kdf(key, b"test-label", 32)
        assert len(result) == 32

    def test_different_labels_give_different_output(self):
        key = os.urandom(32)
        out1 = _kdf(key, b"label-1", 32)
        out2 = _kdf(key, b"label-2", 32)
        assert out1 != out2

    def test_same_inputs_give_same_output(self):
        key = bytes(range(32))
        out1 = _kdf(key, b"label", 16)
        out2 = _kdf(key, b"label", 16)
        assert out1 == out2

    def test_truncation(self):
        key = os.urandom(32)
        full = _kdf(key, b"x", 32)
        short = _kdf(key, b"x", 16)
        assert short == full[:16]
