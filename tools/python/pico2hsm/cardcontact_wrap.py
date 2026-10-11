"""SmartCard-HSM (CardContact) key-backup blob: an independent reference.

This module implements the wrapped-key format that `WRAP KEY` (80 72) returns
and `UNWRAP KEY` (80 74) accepts on a SmartCard-HSM, as written by
`sc-hsm-tool --wrap-key` into the `.wky` file (inside a SEQUENCE / OCTET
STRING) and read back by `sc-hsm-tool --unwrap-key`.

It was written from the format description, not from the pico2hsm firmware,
so that the firmware's known-answer tests (`firmware/tests/vectors/`) compare
two implementations.  Sources (see docs/SC_HSM_APDU_REFERENCE.md, "Key backup
blob"):

* CardContact Smart Card Shell `scsh/sc-hsm/DKEK.js` (`dumpKeyBLOB` output
  field list, as quoted on the Nitrokey support forum);
* the C reference firmware pico-hsm `src/hsm/kek.c`
  (`dkek_kcv`, `dkek_kenc`, `dkek_kmac`, `dkek_encode_key`, `dkek_decode_key`);
* OpenSC `src/tools/sc-hsm-tool.c` / `src/libopensc/card-sc-hsm.c`
  (APDUs, `.wky` container, KEY DOMAIN status layout).

Layout::

    KCV(8) | type(1) | LV(default algorithm OID) | LV(allowed algorithms)
           | LV(access conditions) | LV(key OID)
           | AES-256-CBC(K_enc, IV=0, rand(8) | key size(2) | key | 80 00..)
           | AES-CMAC(K_mac, everything before)(16)

    LV(x) = len(x) as 2-byte big endian | x
    KCV   = SHA-256(DKEK)[0:8]
    K_enc = SHA-256(DKEK | 00 00 00 01)
    K_mac = SHA-256(DKEK | 00 00 00 02)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_TYPE_RSA = 5
KEY_TYPE_RSA_CRT = 6
KEY_TYPE_EC = 12
KEY_TYPE_AES = 15

# Default algorithm OIDs (DER content octets, no tag/length).
OID_RSA_V15_SHA256 = bytes.fromhex("04007f00070202020102")  # 0.4.0.127.0.7.2.2.2.1.2
OID_ECDSA_SHA256 = bytes.fromhex("04007f00070202020203")  # 0.4.0.127.0.7.2.2.2.2.3
OID_AES = bytes.fromhex("6086480165030401")  # 2.16.840.1.101.3.4.1

ALGO_WRAP = 0x92


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def combine_shares(*shares: bytes) -> bytes:
    """DKEK = XOR of all shares (SmartCard-HSM key domain share import)."""
    out = bytes(32)
    for s in shares:
        if len(s) != 32:
            raise ValueError("a DKEK share is 32 bytes")
        out = bytes(a ^ b for a, b in zip(out, s))
    return out


def kcv(dkek: bytes) -> bytes:
    return hashlib.sha256(dkek).digest()[:8]


def k_enc(dkek: bytes) -> bytes:
    return hashlib.sha256(dkek + b"\x00\x00\x00\x01").digest()


def k_mac(dkek: bytes) -> bytes:
    return hashlib.sha256(dkek + b"\x00\x00\x00\x02").digest()


# ---------------------------------------------------------------------------
# Curves (SEC 2 / FIPS 186-4 domain parameters)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Curve:
    name: str
    crypto_curve: type
    p: int
    a: int
    b: int
    n: int

    @property
    def field_len(self) -> int:
        return (self.p.bit_length() + 7) // 8

    @property
    def order_len(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def point(self, d: int) -> bytes:
        """Uncompressed d*G, computed by the `cryptography` package."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        key = ec.derive_private_key(d, self.crypto_curve())
        return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    @property
    def g(self) -> bytes:
        return self.point(1)


_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P384_P = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "FFFFFFFF0000000000000000FFFFFFFF", 16)
_P521_P = (1 << 521) - 1
_K256_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

CURVES = {
    "P-256": Curve(
        "P-256", ec.SECP256R1, _P256_P, _P256_P - 3,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551),
    "P-384": Curve(
        "P-384", ec.SECP384R1, _P384_P, _P384_P - 3,
        int("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF", 16),
        int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
            "581A0DB248B0A77AECEC196ACCC52973", 16)),
    "P-521": Curve(
        "P-521", ec.SECP521R1, _P521_P, _P521_P - 3,
        int("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
            "3F00", 16),
        int("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
            "6409", 16)),
    "secp256k1": Curve(
        "secp256k1", ec.SECP256K1, _K256_P, 0, 7,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
}


def check_curves() -> None:
    """Self-test the hand-typed domain parameters against `cryptography`."""
    for c in CURVES.values():
        g = c.g
        x = int.from_bytes(g[1:1 + c.field_len], "big")
        y = int.from_bytes(g[1 + c.field_len:], "big")
        assert (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0, c.name
        # (n-1)*G = -G: same x, y' = p - y.
        m = c.point(c.n - 1)
        assert m[1:1 + c.field_len] == g[1:1 + c.field_len], c.name
        assert int.from_bytes(m[1 + c.field_len:], "big") == c.p - y, c.name


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def lv(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def unsigned(v: int) -> bytes:
    """Minimal big-endian unsigned encoding (zero is empty)."""
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def fixed(v: int, n: int) -> bytes:
    return v.to_bytes(n, "big")


@dataclass
class Policy:
    algorithms: bytes = b""
    access_conditions: bytes = b""
    key_oid: bytes = b""


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

def ec_material(curve: Curve, d: int) -> tuple[int, bytes]:
    """(key size in bits, EC key material) — fields A B P N G d Q."""
    fl, ol = curve.field_len, curve.order_len
    body = (lv(fixed(curve.a, fl)) + lv(fixed(curve.b, fl)) + lv(fixed(curve.p, fl))
            + lv(fixed(curve.n, ol)) + lv(curve.g) + lv(fixed(d, ol)) + lv(curve.point(d)))
    return curve.p.bit_length(), body


def rsa_crt_material(key: rsa.RSAPrivateKey) -> tuple[int, bytes]:
    """(modulus bits, RSA-CRT material) — dP dQ p qInv q n e."""
    pn = key.private_numbers()
    pub = pn.public_numbers
    body = (lv(unsigned(pn.dmp1)) + lv(unsigned(pn.dmq1)) + lv(unsigned(pn.p))
            + lv(unsigned(pn.iqmp)) + lv(unsigned(pn.q)) + lv(unsigned(pub.n))
            + lv(unsigned(pub.e)))
    return pub.n.bit_length(), body


def rsa_plain_material(key: rsa.RSAPrivateKey) -> tuple[int, bytes]:
    """(modulus bits, RSA material without CRT) — d n e."""
    pn = key.private_numbers()
    pub = pn.public_numbers
    body = lv(unsigned(pn.d)) + lv(unsigned(pub.n)) + lv(unsigned(pub.e))
    return pub.n.bit_length(), body


def aes_material(key: bytes) -> tuple[int, bytes]:
    """(key size in BYTES, key) — AES carries its size in bytes."""
    return len(key), key


# ---------------------------------------------------------------------------
# Wrap / unwrap
# ---------------------------------------------------------------------------

def wrap(dkek: bytes, key_type: int, oid: bytes, key_size: int, material: bytes,
         randomize: bytes, policy: Optional[Policy] = None) -> bytes:
    """Build a key blob.  `randomize` is the 8-byte random prefix."""
    if len(randomize) != 8:
        raise ValueError("randomize is 8 bytes")
    policy = policy or Policy()
    header = (kcv(dkek) + bytes([key_type]) + lv(oid) + lv(policy.algorithms)
              + lv(policy.access_conditions) + lv(policy.key_oid))
    plain = randomize + key_size.to_bytes(2, "big") + material
    # ISO/IEC 9797-1 padding method 2: always 0x80, then zeros to a block.
    plain += b"\x80" + bytes((-(len(plain) + 1)) % 16)
    enc = Cipher(algorithms.AES(k_enc(dkek)), modes.CBC(bytes(16))).encryptor()
    body = header + enc.update(plain) + enc.finalize()
    mac = cmac.CMAC(algorithms.AES(k_mac(dkek)))
    mac.update(body)
    return body + mac.finalize()


@dataclass
class Unwrapped:
    key_type: int
    oid: bytes
    policy: Policy
    randomize: bytes
    key_size: int
    fields: list = field(default_factory=list)  # LV fields (RSA / EC) or [key] (AES)


def unwrap(dkek: bytes, blob: bytes) -> Unwrapped:
    if len(blob) < 8 + 1 + 8 + 16 + 16 or blob[:8] != kcv(dkek):
        raise ValueError("blob does not match this DKEK")
    mac = cmac.CMAC(algorithms.AES(k_mac(dkek)))
    mac.update(blob[:-16])
    mac.verify(blob[-16:])
    key_type = blob[8]
    off = 9
    fields = []
    for _ in range(4):
        n = int.from_bytes(blob[off:off + 2], "big")
        fields.append(blob[off + 2:off + 2 + n])
        off += 2 + n
    enc = blob[off:-16]
    if len(enc) % 16:
        raise ValueError("encrypted part is not block aligned")
    dec = Cipher(algorithms.AES(k_enc(dkek)), modes.CBC(bytes(16))).decryptor()
    plain = dec.update(enc) + dec.finalize()
    out = Unwrapped(key_type, fields[0], Policy(fields[1], fields[2], fields[3]),
                    plain[:8], int.from_bytes(plain[8:10], "big"))
    off = 10
    if key_type == KEY_TYPE_AES:
        out.fields = [plain[off:off + out.key_size]]
        return out
    count = {KEY_TYPE_RSA: 3, KEY_TYPE_RSA_CRT: 7, KEY_TYPE_EC: 7}[key_type]
    for _ in range(count):
        n = int.from_bytes(plain[off:off + 2], "big")
        out.fields.append(plain[off + 2:off + 2 + n])
        off += 2 + n
    return out
