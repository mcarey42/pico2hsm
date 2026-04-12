"""SC-HSM APDU command builders and response parsers for pico2hsm.

All ``build_*`` functions return raw APDU bytes ready to pass to
``Pico2HSM.transmit()``.  All ``parse_*`` functions accept the response
data bytes (without the status word) returned by ``transmit()``.
"""

from __future__ import annotations

import struct
from typing import Optional

from .errors import ProtocolError

# ---------------------------------------------------------------------------
# INS codes (must match firmware sc_hsm.h)
# ---------------------------------------------------------------------------
INS_SELECT = 0xA4
INS_READ_BINARY = 0xB0
INS_READ_BINARY_ODD = 0xB1
INS_UPDATE_BINARY = 0xD6
INS_WRITE_DATA = 0xD7
INS_VERIFY = 0x20
INS_CHANGE_PIN = 0x24
INS_RESET_RETRY = 0x2C
INS_INITIALIZE = 0x50
INS_GENERATE_KEYPAIR = 0x46
INS_GENERATE_KEY = 0x48
INS_IMPORT_KEY = 0x74
INS_EXPORT_KEY = 0x72
INS_SIGN = 0x68
INS_DECRYPT = 0x62
INS_CIPHER_SYM = 0x78
INS_DELETE_FILE = 0xE4
INS_GET_CHALLENGE = 0x84
INS_EXTERNAL_AUTH = 0x82
INS_GENERAL_AUTH = 0x86
INS_MSE = 0x22
INS_PSO = 0x2A
INS_KEY_DOMAIN = 0x52
INS_BIP_DERIVE = 0x60
INS_EXTRAS = 0x54

# ---------------------------------------------------------------------------
# Algorithm identifiers (must match firmware sc_hsm.h)
# ---------------------------------------------------------------------------
ALGO_RSA_RAW = 0x20
ALGO_RSA_PKCS1 = 0x30
ALGO_RSA_PKCS1_SHA256 = 0x33
ALGO_RSA_PSS = 0x40
ALGO_RSA_PSS_SHA256 = 0x43
ALGO_EC_RAW = 0x70
ALGO_EC_SHA256 = 0x73
ALGO_EC_DH = 0x80
ALGO_AES_CBC_ENCRYPT = 0x10
ALGO_AES_CBC_DECRYPT = 0x11
ALGO_AES_CMAC = 0x18
ALGO_WRAP = 0x92
ALGO_UNWRAP = 0x93

# ---------------------------------------------------------------------------
# Key type constants
# ---------------------------------------------------------------------------
KEY_TYPE_RSA = 0x06
KEY_TYPE_EC = 0x13
KEY_TYPE_AES = 0x15

# Standard EC curve OIDs (DER encoded)
OID_SECP256R1 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
OID_SECP384R1 = bytes([0x2B, 0x81, 0x04, 0x00, 0x22])
OID_SECP521R1 = bytes([0x2B, 0x81, 0x04, 0x00, 0x23])
OID_SECP256K1 = bytes([0x2B, 0x81, 0x04, 0x00, 0x0A])

# EF file IDs used by SC-HSM
FID_DIR = 0x2F00
FID_KEYDIR = 0xC000  # base; key N lives at 0xC0 + N*2

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a BER-TLV element with definite-length encoding."""
    length = len(value)
    if tag > 0xFF:
        tag_bytes = struct.pack(">H", tag)
    else:
        tag_bytes = bytes([tag])

    if length < 0x80:
        len_bytes = bytes([length])
    elif length <= 0xFF:
        len_bytes = bytes([0x81, length])
    elif length <= 0xFFFF:
        len_bytes = bytes([0x82]) + struct.pack(">H", length)
    else:
        raise ValueError(f"TLV value too large: {length} bytes")

    return tag_bytes + len_bytes + value


def _encode_apdu(
    cla: int,
    ins: int,
    p1: int,
    p2: int,
    data: bytes = b"",
    le: Optional[int] = None,
) -> bytes:
    """Build a case-1/2/3/4 ISO 7816-4 APDU.

    Uses extended length encoding automatically when data > 255 bytes or
    Le > 256.
    """
    use_extended = len(data) > 255 or (le is not None and le > 256)

    header = bytes([cla, ins, p1, p2])

    if not data and le is None:
        # Case 1
        return header

    if not data and le is not None:
        # Case 2
        if use_extended:
            return header + bytes([0x00]) + struct.pack(">H", le)
        return header + bytes([le & 0xFF])

    if data and le is None:
        # Case 3
        if use_extended:
            return header + bytes([0x00]) + struct.pack(">H", len(data)) + data
        return header + bytes([len(data)]) + data

    # Case 4 (data + Le)
    if use_extended:
        return (
            header
            + bytes([0x00])
            + struct.pack(">H", len(data))
            + data
            + struct.pack(">H", le)
        )
    return header + bytes([len(data)]) + data + bytes([le & 0xFF])


def _pin_bytes(pin: str) -> bytes:
    """Encode a PIN string as UTF-8 bytes."""
    return pin.encode("utf-8")


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def build_initialize(
    so_pin: str,
    pin: str,
    label: str = "pico2hsm",
    options: int = 0,
    dkek_shares: int = 1,
) -> bytes:
    """Build the INITIALIZE APDU (INS=0x50).

    The data field contains a sequence of TLV objects:
      80 - Options byte
      81 - SO-PIN (8 bytes, zero-padded)
      82 - PIN (6-8 bytes)
      83 - Label (UTF-8, up to 20 bytes)
      84 - DKEK shares count (1 byte)
    """
    so_pin_b = _pin_bytes(so_pin)
    pin_b = _pin_bytes(pin)
    label_b = label.encode("utf-8")[:20]

    data = (
        _encode_tlv(0x80, bytes([options]))
        + _encode_tlv(0x81, so_pin_b)
        + _encode_tlv(0x82, pin_b)
        + _encode_tlv(0x83, label_b)
        + _encode_tlv(0x84, bytes([dkek_shares]))
    )
    return _encode_apdu(0x80, INS_INITIALIZE, 0x00, 0x00, data)


def build_verify_pin(pin: str) -> bytes:
    """Build VERIFY PIN APDU (INS=0x20, P2=0x81 for user PIN)."""
    return _encode_apdu(0x00, INS_VERIFY, 0x00, 0x81, _pin_bytes(pin))


def build_change_pin(old_pin: str, new_pin: str) -> bytes:
    """Build CHANGE REFERENCE DATA APDU (INS=0x24, P2=0x81)."""
    data = _pin_bytes(old_pin) + _pin_bytes(new_pin)
    return _encode_apdu(0x00, INS_CHANGE_PIN, 0x00, 0x81, data)


def build_reset_retry_counter(so_pin: str, new_pin: str) -> bytes:
    """Build RESET RETRY COUNTER APDU (INS=0x2C)."""
    data = _pin_bytes(so_pin) + _pin_bytes(new_pin)
    return _encode_apdu(0x00, INS_RESET_RETRY, 0x03, 0x81, data)


def build_generate_keypair(key_id: int, algo: int, curve_oid: bytes = b"") -> bytes:
    """Build GENERATE ASYMMETRIC KEY PAIR APDU (INS=0x46).

    Args:
        key_id: Key reference (0x01-0xFF).
        algo: Algorithm identifier (KEY_TYPE_RSA or KEY_TYPE_EC).
        curve_oid: For EC keys, the raw OID bytes (without tag/length).
    """
    inner: bytes
    if algo == KEY_TYPE_EC and curve_oid:
        # 0x80 = key type, 0x81 = curve OID
        inner = _encode_tlv(0x80, bytes([KEY_TYPE_EC])) + _encode_tlv(0x81, curve_oid)
    else:
        inner = _encode_tlv(0x80, bytes([algo]))

    data = _encode_tlv(0x7F49, inner)
    return _encode_apdu(0x00, INS_GENERATE_KEYPAIR, 0x00, key_id, data, le=0)


def build_generate_aes_key(key_id: int, key_size: int) -> bytes:
    """Build GENERATE SYMMETRIC KEY APDU (INS=0x48).

    Args:
        key_id: Key reference (0x01-0xFF).
        key_size: Key size in bits (128, 192, or 256).
    """
    size_byte = key_size // 8
    data = _encode_tlv(0x80, bytes([KEY_TYPE_AES])) + _encode_tlv(0x81, bytes([size_byte]))
    return _encode_apdu(0x00, INS_GENERATE_KEY, 0x00, key_id, data)


def build_sign(key_id: int, algo: int, data: bytes) -> bytes:
    """Build PERFORM SECURITY OPERATION - Sign APDU (INS=0x68).

    Args:
        key_id: Key reference.
        algo: Algorithm identifier (e.g. ALGO_EC_SHA256).
        data: Data/hash to sign.
    """
    return _encode_apdu(0x80, INS_SIGN, algo, key_id, data, le=0)


def build_decrypt(key_id: int, algo: int, data: bytes) -> bytes:
    """Build DECRYPT APDU (INS=0x62).

    Args:
        key_id: Key reference.
        algo: Algorithm identifier (e.g. ALGO_RSA_PKCS1).
        data: Ciphertext to decrypt.
    """
    return _encode_apdu(0x80, INS_DECRYPT, algo, key_id, data, le=0)


def build_cipher_sym(key_id: int, algo: int, data: bytes) -> bytes:
    """Build SYMMETRIC CIPHER APDU (INS=0x78)."""
    return _encode_apdu(0x80, INS_CIPHER_SYM, algo, key_id, data, le=0)


def build_read_binary(fid: int, offset: int = 0, length: int = 0) -> bytes:
    """Build READ BINARY APDU (INS=0xB0).

    Args:
        fid: File identifier (2 bytes).
        offset: Byte offset into the file.
        length: Number of bytes to read (0 = read all / use Le=00).
    """
    # First select the EF via short file ID or absolute FID
    # For simplicity, encode offset in P1/P2
    p1 = (offset >> 8) & 0x7F
    p2 = offset & 0xFF
    le = length if length else 0
    return _encode_apdu(0x00, INS_READ_BINARY, p1, p2, le=le)


def build_select_ef(fid: int) -> bytes:
    """Build SELECT FILE APDU to select an EF by FID."""
    data = struct.pack(">H", fid)
    return _encode_apdu(0x00, INS_SELECT, 0x02, 0x0C, data)


def build_read_binary_odd(offset: int = 0, le: int = 0) -> bytes:
    """Build READ BINARY ODD APDU (INS=0xB1, SC-HSM proprietary).

    Reads from the currently selected EF (set by build_select_ef).
    Uses TLV-encoded offset: 54 02 <off_hi> <off_lo>.
    """
    data = bytes([0x54, 0x02, (offset >> 8) & 0xFF, offset & 0xFF])
    return _encode_apdu(0x00, INS_READ_BINARY_ODD, 0x00, 0x00, data, le=le)


def build_write_data(fid: int, offset: int, payload: bytes) -> bytes:
    """Build WRITE DATA APDU (INS=0xD7, SC-HSM proprietary).

    Writes payload to the EF at fid starting at offset.
    TLV format: 54 02 <off_hi> <off_lo> 53 <BER-len> <payload>
    """
    tlv = bytes([0x54, 0x02, (offset >> 8) & 0xFF, offset & 0xFF, 0x53])
    # BER-TLV length encoding
    plen = len(payload)
    if plen < 128:
        tlv += bytes([plen])
    elif plen < 256:
        tlv += bytes([0x81, plen])
    else:
        tlv += bytes([0x82, (plen >> 8) & 0xFF, plen & 0xFF])
    tlv += payload
    return _encode_apdu(0x80, INS_WRITE_DATA, (fid >> 8) & 0xFF, fid & 0xFF, tlv)


def build_list_keys() -> bytes:
    """Build LIST PUBLIC KEY OBJECTS APDU.

    Uses READ BINARY on the key directory EF (FID 0x2F02).
    Returns the APDU to select and read the key directory.
    """
    # Select the key directory file 2F02
    data = bytes([0x2F, 0x02])
    return _encode_apdu(0x00, INS_SELECT, 0x02, 0x04, data, le=0)


def build_get_challenge(length: int = 8) -> bytes:
    """Build GET CHALLENGE APDU (INS=0x84)."""
    return _encode_apdu(0x00, INS_GET_CHALLENGE, 0x00, 0x00, le=length)


def build_external_auth(auth_data: bytes) -> bytes:
    """Build EXTERNAL AUTHENTICATE APDU (INS=0x82)."""
    return _encode_apdu(0x00, INS_EXTERNAL_AUTH, 0x00, 0x00, auth_data)


def build_import_key(key_id: int, key_data: bytes) -> bytes:
    """Build IMPORT KEY APDU (INS=0x74, P1=key_ref, P2=0x93).

    key_data should be a DKEK-wrapped key blob.
    sc-hsm-tool sends: 80 74 <key_ref> 93 <len> <wrapped_blob>
    """
    return _encode_apdu(0x80, INS_IMPORT_KEY, key_id, 0x93, key_data)


def build_export_key(key_id: int) -> bytes:
    """Build EXPORT KEY APDU (INS=0x72, P1=key_ref, P2=0x92).

    Returns the DKEK-wrapped key blob.
    sc-hsm-tool sends: 80 72 <key_ref> 92 00
    """
    return _encode_apdu(0x80, INS_EXPORT_KEY, key_id, 0x92, le=0)


def build_delete_file(fid: int) -> bytes:
    """Build DELETE FILE APDU (INS=0xE4)."""
    data = struct.pack(">H", fid)
    return _encode_apdu(0x80, INS_DELETE_FILE, 0x02, 0x00, data)


def build_mse_set_algo(key_id: int, algo: int, operation: int = 0xB8) -> bytes:
    """Build MANAGE SECURITY ENVIRONMENT (MSE SET) APDU (INS=0x22).

    Args:
        key_id: Key reference.
        algo: Algorithm reference.
        operation: 0xB8 for digital signature, 0xB4 for auth.
    """
    data = bytes([0x80, 0x01, algo, 0x84, 0x01, key_id])
    return _encode_apdu(0x00, INS_MSE, 0x41, operation, data)


def build_pso_sign(hash_data: bytes) -> bytes:
    """Build PSO COMPUTE DIGITAL SIGNATURE APDU (INS=0x2A)."""
    return _encode_apdu(0x00, INS_PSO, 0x9E, 0x9A, hash_data, le=0)


def build_key_domain(domain_id: int, operation: int = 0x00) -> bytes:
    """Build KEY DOMAIN APDU (INS=0x52)."""
    return _encode_apdu(0x80, INS_KEY_DOMAIN, operation, domain_id)


def build_bip_derive(key_id: int, index: int, hardened: bool = False) -> bytes:
    """Build BIP32 DERIVE APDU (INS=0x60).

    Args:
        key_id: Parent key reference.
        index: Child index.
        hardened: If True, set the hardened bit (index |= 0x80000000).
    """
    if hardened:
        index |= 0x80000000
    data = struct.pack(">I", index)
    return _encode_apdu(0x80, INS_BIP_DERIVE, 0x00, key_id, data, le=0)


def build_extras(sub_cmd: int, data: bytes = b"") -> bytes:
    """Build EXTRAS command APDU (INS=0x54) for firmware-specific extensions."""
    return _encode_apdu(0x80, INS_EXTRAS, sub_cmd, 0x00, data, le=0)


# ---------------------------------------------------------------------------
# DKEK exchange sub-commands for INS_EXTRAS (P1 values)
# ---------------------------------------------------------------------------
EXTRAS_GET_DEVICE_PUBKEY  = 0x30  # Returns 65-byte uncompressed P-256 public key
EXTRAS_NOISE_INITIATE     = 0x31  # In: peer_ephem_pub (65B) or empty; Out: our_ephem_pub (65B)
EXTRAS_NOISE_FINALIZE_SEND = 0x32  # In: peer_ephem_pub (65B); Out: encrypted_dkek (60B)
EXTRAS_NOISE_FINALIZE_RECV = 0x33  # In: initiator_ephem_pub(65) + encrypted_dkek(60) + device_id(16)
EXTRAS_GET_GENERATION      = 0x34  # Returns 4-byte big-endian generation counter


def build_get_device_pubkey() -> bytes:
    """Build EXTRAS P1=0x30 APDU."""
    return build_extras(EXTRAS_GET_DEVICE_PUBKEY)


def build_noise_initiate(peer_ephem_pub: bytes = b"") -> bytes:
    """Build EXTRAS P1=0x31 APDU. peer_ephem_pub is 65 bytes or empty."""
    return build_extras(EXTRAS_NOISE_INITIATE, peer_ephem_pub)


def build_noise_finalize_send(peer_ephem_pub: bytes) -> bytes:
    """Build EXTRAS P1=0x32 APDU. peer_ephem_pub is 65 bytes."""
    return build_extras(EXTRAS_NOISE_FINALIZE_SEND, peer_ephem_pub)


def build_noise_finalize_recv(
    initiator_ephem_pub: bytes,
    encrypted_dkek: bytes,
    initiator_device_id: bytes,
) -> bytes:
    """Build EXTRAS P1=0x33 APDU. Data is ephem_pub(65) + encrypted_dkek(60) + device_id(16)."""
    data = initiator_ephem_pub + encrypted_dkek + initiator_device_id
    return build_extras(EXTRAS_NOISE_FINALIZE_RECV, data)


def build_get_generation() -> bytes:
    """Build EXTRAS P1=0x34 APDU."""
    return build_extras(EXTRAS_GET_GENERATION)


def build_delete_key(key_ref: int) -> bytes:
    """Build DELETE KEY APDU.

    Uses DELETE FILE (INS=0xE4) with FID encoding 0xCC:key_ref,
    which the firmware interprets as a key object deletion.
    """
    data = struct.pack(">H", 0xCC00 | (key_ref & 0xFF))
    return _encode_apdu(0x80, INS_DELETE_FILE, 0x02, 0x00, data)


# ---------------------------------------------------------------------------
# Cluster sub-commands for INS_EXTRAS (V2 protocol, P1 values 0x35-0x3C)
# ---------------------------------------------------------------------------
EXTRAS_NOISE_TARGET_INIT      = 0x35
EXTRAS_NOISE_SOURCE_RESPOND   = 0x36
EXTRAS_NOISE_FINALIZE_SEND_V2 = 0x37
EXTRAS_NOISE_FINALIZE_RECV_V2 = 0x38
EXTRAS_GET_KEY_MANIFEST       = 0x39
EXTRAS_GET_STATE_HASH         = 0x3A
EXTRAS_SIGN_ENROLLMENT        = 0x3B
EXTRAS_GET_GENERATION_V2      = 0x3C
EXTRAS_ENROLL_PEER_PUBKEY     = 0x3D


def build_noise_target_init(source_static_pub: bytes) -> bytes:
    """INS=0x54, P1=0x35: target generates challenge + signs ephem key."""
    assert len(source_static_pub) == 65
    return build_extras(EXTRAS_NOISE_TARGET_INIT, source_static_pub)


def build_noise_source_respond(ephem_T_pub: bytes, challenge: bytes, sig_T: bytes) -> bytes:
    """INS=0x54, P1=0x36: source verifies target's signed ephem + signs its own."""
    data = ephem_T_pub + challenge + sig_T
    assert len(data) == 161
    return build_extras(EXTRAS_NOISE_SOURCE_RESPOND, data)


def build_noise_finalize_send_v2(
    target_ephem_pub: bytes, target_static_pub: bytes, challenge: bytes,
) -> bytes:
    """INS=0x54, P1=0x37."""
    data = target_ephem_pub + target_static_pub + challenge
    assert len(data) == 162
    return build_extras(EXTRAS_NOISE_FINALIZE_SEND_V2, data)


def build_noise_finalize_recv_v2(
    source_ephem_pub: bytes, sig_S: bytes, encrypted_dkek: bytes,
) -> bytes:
    """INS=0x54, P1=0x38."""
    data = source_ephem_pub + sig_S + encrypted_dkek
    assert len(data) == 189
    return build_extras(EXTRAS_NOISE_FINALIZE_RECV_V2, data)


def build_get_key_manifest() -> bytes:
    """INS=0x54, P1=0x39."""
    return build_extras(EXTRAS_GET_KEY_MANIFEST)


def build_get_state_hash() -> bytes:
    """INS=0x54, P1=0x3A."""
    return build_extras(EXTRAS_GET_STATE_HASH)


def build_sign_enrollment(tls_fingerprint: bytes, cluster_id: bytes) -> bytes:
    """INS=0x54, P1=0x3B."""
    data = tls_fingerprint + cluster_id
    assert len(data) == 48
    return build_extras(EXTRAS_SIGN_ENROLLMENT, data)


def build_get_generation_v2() -> bytes:
    """INS=0x54, P1=0x3C."""
    return build_extras(EXTRAS_GET_GENERATION_V2)


def build_enroll_peer_pubkey(peer_pubkey: bytes) -> bytes:
    """INS=0x54, P1=0x3D: enroll a peer P-256 public key for V2 Noise auth.

    peer_pubkey must be 65 bytes (uncompressed P-256: 04 || x || y).
    Requires SO-PIN VERIFY before calling.
    """
    assert len(peer_pubkey) == 65
    return build_extras(EXTRAS_ENROLL_PEER_PUBKEY, peer_pubkey)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def parse_list_keys(response: bytes) -> list[dict]:
    """Parse the key directory response into a list of key info dicts.

    The key directory is an array of fixed-size records, each describing
    one key object stored on the HSM.

    Returns list of dicts with keys:
        - key_id (int)
        - key_type (str)  -- 'RSA', 'EC', 'AES', 'UNKNOWN'
        - key_size (int)  -- bits
        - label (str)
        - fid (int)       -- file identifier
    """
    if not response:
        return []

    keys = []
    offset = 0
    while offset < len(response):
        # Each record: 2-byte FID + 1-byte type + 1-byte size_class
        if offset + 4 > len(response):
            break
        fid = struct.unpack(">H", response[offset : offset + 2])[0]
        key_type_raw = response[offset + 2]
        size_class = response[offset + 3]
        offset += 4

        # FID encoding: 0xCC XX where XX is the key reference
        key_id = fid & 0xFF
        key_type, key_size = _decode_key_type(key_type_raw, size_class)

        # Try to read label if present (variable-length after fixed header)
        label = ""
        if offset < len(response) and response[offset] != 0xCC:
            # Read up to null terminator or next record
            end = response.find(0x00, offset)
            if end == -1:
                end = len(response)
            label = response[offset:end].decode("utf-8", errors="replace")
            offset = end + 1

        keys.append(
            {
                "key_id": key_id,
                "key_type": key_type,
                "key_size": key_size,
                "label": label,
                "fid": fid,
            }
        )

    return keys


def parse_key_info(response: bytes) -> dict:
    """Parse a single key info response (e.g. from READ BINARY on a key EF).

    Returns a dict with:
        - key_type (str)
        - key_size (int)
        - algorithm (int)
        - access_conditions (list[int])
        - public_key_bytes (bytes) -- DER-encoded public key if available
    """
    if not response:
        raise ProtocolError("Empty key info response")

    result: dict = {
        "key_type": "UNKNOWN",
        "key_size": 0,
        "algorithm": 0,
        "access_conditions": [],
        "public_key_bytes": b"",
    }

    offset = 0
    while offset < len(response):
        if offset + 2 > len(response):
            break
        tag = response[offset]
        offset += 1
        length = response[offset]
        offset += 1

        if length == 0x81:
            if offset >= len(response):
                break
            length = response[offset]
            offset += 1
        elif length == 0x82:
            if offset + 1 >= len(response):
                break
            length = struct.unpack(">H", response[offset : offset + 2])[0]
            offset += 2

        value = response[offset : offset + length]
        offset += length

        if tag == 0x80:  # Key type
            if value:
                raw_type = value[0]
                result["key_type"], _ = _decode_key_type(raw_type, 0)
        elif tag == 0x81:  # Key size
            if len(value) >= 2:
                result["key_size"] = struct.unpack(">H", value[:2])[0]
            elif len(value) == 1:
                result["key_size"] = value[0] * 8
        elif tag == 0x82:  # Algorithm
            if value:
                result["algorithm"] = value[0]
        elif tag == 0x86:  # Access conditions
            result["access_conditions"] = list(value)
        elif tag in (0x7F49, 0x86):  # Public key
            result["public_key_bytes"] = value

    return result


def parse_challenge(response: bytes) -> bytes:
    """Return the raw challenge bytes from GET CHALLENGE response."""
    return response


def parse_public_key(response: bytes) -> bytes:
    """Extract public key DER bytes from GENERATE KEYPAIR response."""
    # Response is typically a TLV 7F49 containing the public key data
    if not response:
        raise ProtocolError("Empty public key response")
    offset = 0
    while offset < len(response):
        if offset + 2 > len(response):
            break
        tag = response[offset]
        offset += 1
        # Handle 2-byte tags
        if tag == 0x7F:
            if offset >= len(response):
                break
            tag = (tag << 8) | response[offset]
            offset += 1
        length = response[offset]
        offset += 1
        if length == 0x81:
            length = response[offset]
            offset += 1
        elif length == 0x82:
            length = struct.unpack(">H", response[offset : offset + 2])[0]
            offset += 2
        value = response[offset : offset + length]
        offset += length
        if tag == 0x7F49:
            return value
    # Fallback: return raw response
    return response


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_key_type(type_byte: int, size_class: int) -> tuple[str, int]:
    """Return (key_type_str, key_size_bits) from raw type and size bytes."""
    if type_byte == KEY_TYPE_RSA:
        size_map = {0x00: 1024, 0x01: 2048, 0x02: 3072, 0x03: 4096}
        return "RSA", size_map.get(size_class, size_class * 256)
    elif type_byte == KEY_TYPE_EC:
        size_map = {0x20: 256, 0x30: 384, 0x40: 521}
        return "EC", size_map.get(size_class, size_class * 8)
    elif type_byte == KEY_TYPE_AES:
        size_map = {0x10: 128, 0x18: 192, 0x20: 256}
        return "AES", size_map.get(size_class, size_class * 8)
    return "UNKNOWN", 0
