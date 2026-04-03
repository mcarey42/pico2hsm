"""Cryptographic verification helpers for hardware integration tests."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
    Prehashed,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    ECDH,
)
from cryptography.hazmat.backends import default_backend


def p1363_to_der(sig_bytes: bytes) -> bytes:
    """Convert a raw ECDSA P1363 signature (r||s) to DER/ASN.1 format.

    P1363 format: r and s are fixed-width integers concatenated.
    The split point is exactly half of the byte length.
    """
    if len(sig_bytes) % 2 != 0:
        raise ValueError(
            f"P1363 signature has odd length {len(sig_bytes)}; cannot split r||s"
        )
    half = len(sig_bytes) // 2
    r = int.from_bytes(sig_bytes[:half], "big")
    s = int.from_bytes(sig_bytes[half:], "big")
    return encode_dss_signature(r, s)


def verify_ecdsa_signature(
    pubkey_pem: str,
    message: bytes,
    sig_p1363: bytes,
    hash_algo: str,
) -> bool:
    """Verify an ECDSA signature over *message* using a PEM public key.

    Args:
        pubkey_pem: PEM-encoded EC public key (-----BEGIN PUBLIC KEY-----).
        message:    The raw message bytes that were signed.
        sig_p1363:  Signature in P1363 format (r||s concatenated, fixed width).
        hash_algo:  One of "sha256", "sha384", "sha512".

    Returns:
        True if the signature is valid.

    Raises:
        ValueError on bad inputs.
        cryptography.exceptions.InvalidSignature if the signature is wrong.
    """
    _hash_map: dict[str, type[hashes.HashAlgorithm]] = {
        "sha1":   hashes.SHA1,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    if hash_algo not in _hash_map:
        raise ValueError(f"Unsupported hash_algo '{hash_algo}'. Choose from {list(_hash_map)}")

    pub_key: EllipticCurvePublicKey = serialization.load_pem_public_key(
        pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem,
        backend=default_backend(),
    )  # type: ignore[assignment]

    sig_der = p1363_to_der(sig_p1363)
    hash_instance = _hash_map[hash_algo]()

    pub_key.verify(sig_der, message, ec.ECDSA(hash_instance))
    # verify() raises InvalidSignature on failure; if we reach here it's valid
    return True


def verify_ecdsa_prehash_signature(
    pubkey_pem: str,
    hash_bytes: bytes,
    sig_p1363: bytes,
    algorithm: hashes.HashAlgorithm | None = None,
) -> bool:
    """Verify an ECDSA signature where the caller has already computed the digest.

    Use this for hash algorithms not natively supported by the *cryptography*
    library for ECDSA (MD5, RIPEMD-160, GOSTR3411, …).  The caller pre-hashes
    the message and passes the raw digest bytes here.

    Args:
        pubkey_pem:  PEM-encoded EC public key.
        hash_bytes:  Pre-computed message digest (any length accepted by the curve).
        sig_p1363:   Signature in P1363 format (r||s concatenated, fixed width).
        algorithm:   Hash algorithm used to produce hash_bytes. Required by
                     cryptography >= 42 (Prehashed now takes an algorithm arg).
                     If None, a size-matched algorithm is chosen automatically.

    Returns:
        True if the signature is valid.

    Raises:
        cryptography.exceptions.InvalidSignature if the signature is wrong.
    """
    if algorithm is None:
        # Auto-select a hash whose output size matches the digest length.
        # This satisfies the EVP digest-size check inside OpenSSL while still
        # passing the raw bytes through unchanged (Prehashed skips re-hashing).
        _size_map: dict[int, type[hashes.HashAlgorithm]] = {
            16: hashes.MD5,
            20: hashes.SHA1,
            28: hashes.SHA224,
            32: hashes.SHA256,
            48: hashes.SHA384,
            64: hashes.SHA512,
        }
        algo_cls = _size_map.get(len(hash_bytes), hashes.SHA256)
        algorithm = algo_cls()

    pub_key: EllipticCurvePublicKey = serialization.load_pem_public_key(
        pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem,
        backend=default_backend(),
    )  # type: ignore[assignment]

    sig_der = p1363_to_der(sig_p1363)
    pub_key.verify(sig_der, hash_bytes, ec.ECDSA(Prehashed(algorithm)))
    return True


def generate_ec_peer_key(curve_name: str) -> tuple[bytes, bytes]:
    """Generate an ephemeral EC key pair.

    Args:
        curve_name: OpenSSL curve name: "prime256v1", "secp384r1", or "secp521r1".

    Returns:
        (private_key_pem_bytes, raw_ec_point_bytes)

        raw_ec_point_bytes is the uncompressed point 04||X||Y as expected by
        pkcs11-tool --derive --input-file.
    """
    curve_map: dict[str, ec.EllipticCurve] = {
        "prime256v1": ec.SECP256R1(),
        "secp384r1":  ec.SECP384R1(),
        "secp521r1":  ec.SECP521R1(),
    }
    if curve_name not in curve_map:
        raise ValueError(
            f"Unsupported curve '{curve_name}'. "
            f"ECDH peers must use one of: {list(curve_map)}"
        )

    private_key = ec.generate_private_key(curve_map[curve_name], backend=default_backend())

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_key = private_key.public_key()
    # pkcs11-tool ≥ 0.25 requires DER-encoded SubjectPublicKeyInfo for --input-file.
    # Older versions expected raw 04||X||Y; use DER to work with current OpenSC.
    pub_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return priv_pem, pub_der


def ecdh_host_side(peer_priv_pem: bytes, device_pub_pem: str) -> bytes:
    """Compute the ECDH shared secret on the host.

    Args:
        peer_priv_pem:  PEM bytes of the ephemeral private key.
        device_pub_pem: PEM string of the device's EC public key.

    Returns:
        Raw X-coordinate bytes of the shared point (32, 48, or 66 bytes
        depending on curve). This matches what the SC-HSM device returns
        for ECDH1-COFACTOR-DERIVE.
    """
    peer_priv = serialization.load_pem_private_key(
        peer_priv_pem if isinstance(peer_priv_pem, bytes) else peer_priv_pem.encode(),
        password=None,
        backend=default_backend(),
    )

    device_pub: EllipticCurvePublicKey = serialization.load_pem_public_key(
        device_pub_pem.encode() if isinstance(device_pub_pem, str) else device_pub_pem,
        backend=default_backend(),
    )  # type: ignore[assignment]

    shared_key = peer_priv.exchange(ECDH(), device_pub)  # type: ignore[arg-type]
    # shared_key is the raw X coordinate (big-endian), which is what ECDH1-COFACTOR-DERIVE returns
    return shared_key
