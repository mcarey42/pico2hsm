"""pico2hsm domains (cluster plan V3, phase P1): an independent reference.

Written from `docs/CLUSTER_PLAN_V3.md` §4 and `docs/SC_HSM_APDU_REFERENCE.md`
(DOMAIN_STATUS, GET_MEMBERS), not from the firmware, so that the firmware's
known-answer tests (`firmware/tests/vectors/domain_v1.txt`, written by
`firmware/tests/vectors/gen_domain.py`) compare two implementations.  The
host tool (`pico2hsm-tool`, crate `pico2hsm-proto`) reads the same vectors.

Domain key::

    okm       = HKDF-SHA256(ikm = DKEK, salt = "pico2hsm-domain-v1",
                            info = "sign", L = 48)
    d_domain  = int(okm) mod n            (P-256 order; 0 is refused)
    Q_domain  = d_domain * G              (65-byte uncompressed point)
    domain_id = SHA-256(Q_domain)[0:16]

Member certificate (187 bytes)::

    version(1) = 1 | domain_id(16) | member_id(16) = SHA-256(member_pub)[0:16]
    | member_pub(65) | sponsor_id(16) | issued_lamport(8, BE) | flags(1)
    | sig(64) = ECDSA-P256(d_domain, SHA-256("pico2hsm-member-cert-v1" | body)), r | s

Only the `cryptography` package is needed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

DOMAIN_SALT = b"pico2hsm-domain-v1"
DOMAIN_INFO_SIGN = b"sign"
OKM_LEN = 48

CERT_VERSION = 1
CERT_BODY_LEN = 123
CERT_LEN = CERT_BODY_LEN + 64
CERT_CONTEXT = b"pico2hsm-member-cert-v1"
FLAG_MAY_SPONSOR = 0x01

ENTRY_VERSION = 1
ENTRY_LEN = 10 + CERT_LEN
STATUS_ACTIVE = 0
STATUS_REVOKED = 1

DOMAIN_STATUS_LEN = 117
DS_DKEK = 0x01
DS_PRODUCTION = 0x02
DS_SELF_MEMBER = 0x04
DS_PINNED_PEER = 0x08


# ---------------------------------------------------------------------------
# Domain key
# ---------------------------------------------------------------------------

def combine_shares(*shares: bytes) -> bytes:
    """DKEK = XOR of the raw 32-byte shares (as SmartCard-HSM combines them)."""
    out = bytearray(32)
    for s in shares:
        if len(s) != 32:
            raise ValueError("a DKEK share is 32 bytes")
        for i, b in enumerate(s):
            out[i] ^= b
    return bytes(out)


def kcv(dkek: bytes) -> bytes:
    """CardContact key check value: SHA-256(DKEK)[0:8]."""
    return hashlib.sha256(dkek).digest()[:8]


def domain_okm(dkek: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=OKM_LEN, salt=DOMAIN_SALT, info=DOMAIN_INFO_SIGN
    ).derive(dkek)


def domain_scalar(dkek: bytes) -> int:
    d = int.from_bytes(domain_okm(dkek), "big") % P256_N
    if d == 0:
        raise ValueError("domain scalar is zero")
    return d


def domain_private_key(dkek: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(domain_scalar(dkek), ec.SECP256R1())


def point_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def domain_q(dkek: bytes) -> bytes:
    return point_bytes(domain_private_key(dkek).public_key())


def domain_id(q: bytes) -> bytes:
    return hashlib.sha256(q).digest()[:16]


def member_id(member_pub: bytes) -> bytes:
    return hashlib.sha256(member_pub).digest()[:16]


# ---------------------------------------------------------------------------
# Member certificates
# ---------------------------------------------------------------------------

@dataclass
class MemberCert:
    domain_id: bytes
    member_id: bytes
    member_pub: bytes
    sponsor_id: bytes
    issued_lamport: int
    flags: int
    sig: bytes

    def body(self) -> bytes:
        return (bytes([CERT_VERSION]) + self.domain_id + self.member_id + self.member_pub
                + self.sponsor_id + struct.pack(">Q", self.issued_lamport)
                + bytes([self.flags]))

    def encode(self) -> bytes:
        return self.body() + self.sig

    def verify(self, q_domain: bytes) -> bool:
        if self.domain_id != domain_id(q_domain):
            return False
        if self.member_id != member_id(self.member_pub):
            return False
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), q_domain)
        r = int.from_bytes(self.sig[:32], "big")
        s = int.from_bytes(self.sig[32:], "big")
        try:
            pub.verify(utils.encode_dss_signature(r, s), CERT_CONTEXT + self.body(),
                       ec.ECDSA(hashes.SHA256()))
        except Exception:
            return False
        return True


def parse_cert(b: bytes) -> MemberCert:
    if len(b) != CERT_LEN or b[0] != CERT_VERSION:
        raise ValueError("not a version-1 member certificate")
    return MemberCert(
        domain_id=b[1:17], member_id=b[17:33], member_pub=b[33:98], sponsor_id=b[98:114],
        issued_lamport=struct.unpack(">Q", b[114:122])[0], flags=b[122], sig=b[123:187],
    )


def issue_cert(dkek: bytes, member_pub: bytes, sponsor_id: bytes, lamport: int,
               flags: int, deterministic: bool = True) -> MemberCert:
    """Sign a certificate with the domain key (RFC 6979 when deterministic)."""
    q = domain_q(dkek)
    cert = MemberCert(domain_id(q), member_id(member_pub), member_pub, sponsor_id,
                      lamport, flags, b"")
    algo = (ec.ECDSA(hashes.SHA256(), deterministic_signing=True) if deterministic
            else ec.ECDSA(hashes.SHA256()))
    der = domain_private_key(dkek).sign(CERT_CONTEXT + cert.body(), algo)
    r, s = utils.decode_dss_signature(der)
    cert.sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return cert


# ---------------------------------------------------------------------------
# APDU responses
# ---------------------------------------------------------------------------

@dataclass
class DomainStatus:
    version: int
    flags: int
    domain_id: bytes
    kcv: bytes
    q_domain: bytes
    member_id: bytes
    lamport: int
    members: int
    capacity: int

    @property
    def has_dkek(self) -> bool:
        return bool(self.flags & DS_DKEK)

    @property
    def production(self) -> bool:
        return bool(self.flags & DS_PRODUCTION)

    @property
    def self_member(self) -> bool:
        return bool(self.flags & DS_SELF_MEMBER)


def parse_domain_status(b: bytes) -> DomainStatus:
    """Response of DOMAIN_STATUS (80 54 40 00)."""
    if len(b) != DOMAIN_STATUS_LEN or b[0] != 1:
        raise ValueError(f"unexpected DOMAIN_STATUS ({len(b)} bytes)")
    return DomainStatus(
        version=b[0], flags=b[1], domain_id=b[2:18], kcv=b[18:26], q_domain=b[26:91],
        member_id=b[91:107], lamport=struct.unpack(">Q", b[107:115])[0],
        members=b[115], capacity=b[116],
    )


@dataclass
class MemberEntry:
    status: int
    revoked_lamport: int
    cert: MemberCert


def parse_member_entry(b: bytes) -> MemberEntry:
    if len(b) != ENTRY_LEN or b[0] != ENTRY_VERSION:
        raise ValueError("not a version-1 member-list entry")
    return MemberEntry(b[1], struct.unpack(">Q", b[2:10])[0], parse_cert(b[10:]))


def parse_members_page(b: bytes) -> tuple[int, int, list[MemberEntry]]:
    """Response of GET_MEMBERS (80 54 47 <first>): (total, first, entries)."""
    total, first, n = b[0], b[1], b[2]
    body = b[3:]
    if len(body) != n * ENTRY_LEN:
        raise ValueError("GET_MEMBERS length mismatch")
    return total, first, [parse_member_entry(body[i * ENTRY_LEN:(i + 1) * ENTRY_LEN])
                          for i in range(n)]
