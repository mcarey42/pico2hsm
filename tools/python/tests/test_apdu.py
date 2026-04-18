"""Unit tests for APDU builder and parser functions in pico2hsm.protocol.

No hardware required — these tests verify byte-level correctness of the
APDU construction logic.
"""

from __future__ import annotations

import struct

import pytest

from pico2hsm import protocol as proto
from pico2hsm.protocol import (
    INS_CHANGE_PIN,
    INS_DECRYPT,
    INS_GENERATE_KEY,
    INS_GENERATE_KEYPAIR,
    INS_IMPORT_KEY,
    INS_INITIALIZE,
    INS_SIGN,
    INS_VERIFY,
    KEY_TYPE_AES,
    KEY_TYPE_EC,
    KEY_TYPE_RSA,
    OID_SECP256R1,
    _encode_tlv,
    build_change_pin,
    build_generate_aes_key,
    build_generate_keypair,
    build_initialize,
    build_sign,
    build_verify_pin,
    parse_key_info,
    parse_list_keys,
)


# ---------------------------------------------------------------------------
# TLV encoding helpers
# ---------------------------------------------------------------------------

class TestEncodeTLV:
    def test_short_length(self):
        encoded = _encode_tlv(0x80, bytes([0x01]))
        assert encoded == bytes([0x80, 0x01, 0x01])

    def test_one_byte_length_boundary(self):
        # 127 bytes -> length field should be 0x7F (< 0x80, short form)
        data = bytes(127)
        encoded = _encode_tlv(0x81, data)
        assert encoded[0] == 0x81
        assert encoded[1] == 0x7F
        assert len(encoded) == 1 + 1 + 127

    def test_long_length_1_byte(self):
        # 128 bytes -> 0x81 0x80
        data = bytes(128)
        encoded = _encode_tlv(0x82, data)
        assert encoded[0] == 0x82
        assert encoded[1] == 0x81
        assert encoded[2] == 0x80
        assert len(encoded) == 1 + 2 + 128

    def test_long_length_2_bytes(self):
        data = bytes(256)
        encoded = _encode_tlv(0x83, data)
        assert encoded[0] == 0x83
        assert encoded[1] == 0x82
        assert struct.unpack(">H", encoded[2:4])[0] == 256

    def test_two_byte_tag(self):
        encoded = _encode_tlv(0x7F49, bytes([0xAB, 0xCD]))
        assert encoded[:2] == bytes([0x7F, 0x49])
        assert encoded[2] == 0x02
        assert encoded[3:5] == bytes([0xAB, 0xCD])


# ---------------------------------------------------------------------------
# build_initialize
# ---------------------------------------------------------------------------

class TestBuildInitialize:
    def test_returns_bytes(self):
        apdu = build_initialize("12345678", "123456")
        assert isinstance(apdu, bytes)

    def test_header_bytes(self):
        apdu = build_initialize("12345678", "123456")
        # CLA=0x80 INS=INS_INITIALIZE P1=0 P2=0
        assert apdu[0] == 0x80
        assert apdu[1] == INS_INITIALIZE
        assert apdu[2] == 0x00
        assert apdu[3] == 0x00

    def test_contains_so_pin(self):
        apdu = build_initialize("SOPIN123", "userpin")
        # SO-PIN tag is 0x81
        assert b"SOPIN123" in apdu

    def test_contains_user_pin(self):
        apdu = build_initialize("sopin", "mypin99")
        assert b"mypin99" in apdu

    def test_contains_label(self):
        apdu = build_initialize("so", "pin", label="mydevice")
        assert b"mydevice" in apdu

    def test_default_label(self):
        apdu = build_initialize("so", "pin")
        assert b"pico2hsm" in apdu

    def test_dkek_shares_encoded(self):
        # dkek_shares=3 should appear as a byte in the TLV
        apdu = build_initialize("so", "pin", dkek_shares=3)
        # Tag 0x84 followed by length 0x01 followed by 0x03
        idx = apdu.find(bytes([0x84, 0x01, 0x03]))
        assert idx != -1, "DKEK shares TLV not found in APDU"

    def test_options_byte(self):
        apdu = build_initialize("so", "pin", options=0x05)
        # Tag 0x80, length 0x01, value 0x05
        idx = apdu.find(bytes([0x80, 0x01, 0x05]))
        assert idx != -1, "Options TLV not found in APDU"

    def test_label_truncated_to_20_chars(self):
        long_label = "A" * 30
        apdu = build_initialize("so", "pin", label=long_label)
        # The label in the APDU should not exceed 20 bytes
        label_tag_idx = apdu.find(bytes([0x83]))
        assert label_tag_idx != -1
        label_len = apdu[label_tag_idx + 1]
        assert label_len <= 20

    def test_minimum_apdu_length(self):
        apdu = build_initialize("so", "pi")
        # Must have at least header (4) + Lc (1) + some data
        assert len(apdu) > 5


# ---------------------------------------------------------------------------
# build_verify_pin
# ---------------------------------------------------------------------------

class TestBuildVerifyPin:
    def test_returns_bytes(self):
        assert isinstance(build_verify_pin("123456"), bytes)

    def test_header(self):
        apdu = build_verify_pin("123456")
        assert apdu[0] == 0x00   # CLA
        assert apdu[1] == INS_VERIFY
        assert apdu[2] == 0x00   # P1
        assert apdu[3] == 0x81   # P2 = user PIN

    def test_pin_encoded_in_body(self):
        apdu = build_verify_pin("mysecret")
        assert b"mysecret" in apdu

    def test_pin_length_field(self):
        pin = "123456"
        apdu = build_verify_pin(pin)
        lc = apdu[4]
        assert lc == len(pin.encode())

    def test_unicode_pin(self):
        apdu = build_verify_pin("pässwörd")
        assert "pässwörd".encode("utf-8") in apdu

    def test_empty_pin_emits_case1_apdu(self):
        # Edge case: empty PIN. Per ISO 7816-4, an APDU with no body and no Le
        # encodes as Case 1 — a 4-byte header with no Lc. The firmware treats
        # this VERIFY Case 1 as "query remaining retry count".
        apdu = build_verify_pin("")
        assert len(apdu) == 4
        assert apdu[0] == 0x00
        assert apdu[1] == INS_VERIFY
        assert apdu[2] == 0x00
        assert apdu[3] == 0x81


# ---------------------------------------------------------------------------
# build_change_pin
# ---------------------------------------------------------------------------

class TestBuildChangePin:
    def test_returns_bytes(self):
        assert isinstance(build_change_pin("old", "new"), bytes)

    def test_instruction_code(self):
        apdu = build_change_pin("old123", "new456")
        assert apdu[1] == INS_CHANGE_PIN

    def test_both_pins_in_body(self):
        apdu = build_change_pin("oldpin", "newpin")
        assert b"oldpin" in apdu
        assert b"newpin" in apdu

    def test_pins_concatenated(self):
        apdu = build_change_pin("aaa", "bbb")
        body = apdu[5:]  # skip header + Lc
        assert b"aaabbb" in body


# ---------------------------------------------------------------------------
# build_generate_keypair
# ---------------------------------------------------------------------------

class TestBuildGenerateKeypair:
    def test_returns_bytes(self):
        assert isinstance(build_generate_keypair(1, KEY_TYPE_EC, OID_SECP256R1), bytes)

    def test_instruction_code(self):
        apdu = build_generate_keypair(1, KEY_TYPE_EC, OID_SECP256R1)
        assert apdu[1] == INS_GENERATE_KEYPAIR

    def test_key_id_in_p2(self):
        apdu = build_generate_keypair(5, KEY_TYPE_EC, OID_SECP256R1)
        assert apdu[3] == 0x05

    def test_ec_curve_oid_present(self):
        apdu = build_generate_keypair(1, KEY_TYPE_EC, OID_SECP256R1)
        assert OID_SECP256R1 in apdu

    def test_rsa_key_type_byte(self):
        apdu = build_generate_keypair(2, KEY_TYPE_RSA)
        assert KEY_TYPE_RSA in apdu

    def test_le_byte_present(self):
        apdu = build_generate_keypair(1, KEY_TYPE_EC, OID_SECP256R1)
        # Case 4 APDU ends with Le byte
        assert apdu[-1] == 0x00


# ---------------------------------------------------------------------------
# build_generate_aes_key
# ---------------------------------------------------------------------------

class TestBuildGenerateAesKey:
    def test_returns_bytes(self):
        assert isinstance(build_generate_aes_key(3, 256), bytes)

    def test_instruction_code(self):
        apdu = build_generate_aes_key(3, 256)
        assert apdu[1] == INS_GENERATE_KEY

    def test_key_id_in_p2(self):
        apdu = build_generate_aes_key(7, 256)
        assert apdu[3] == 0x07

    def test_256bit_size_byte(self):
        apdu = build_generate_aes_key(1, 256)
        # 256 // 8 = 32 = 0x20
        assert bytes([0x20]) in apdu

    def test_128bit_size_byte(self):
        apdu = build_generate_aes_key(1, 128)
        # 128 // 8 = 16 = 0x10
        assert bytes([0x10]) in apdu

    def test_key_type_aes_present(self):
        apdu = build_generate_aes_key(1, 256)
        assert KEY_TYPE_AES in apdu


# ---------------------------------------------------------------------------
# build_sign
# ---------------------------------------------------------------------------

class TestBuildSign:
    def test_returns_bytes(self):
        assert isinstance(build_sign(1, proto.ALGO_EC_SHA256, b"\x00" * 32), bytes)

    def test_instruction_code(self):
        apdu = build_sign(1, proto.ALGO_EC_SHA256, b"data")
        assert apdu[1] == INS_SIGN

    def test_algo_in_p1(self):
        apdu = build_sign(2, proto.ALGO_EC_SHA256, b"x")
        assert apdu[2] == proto.ALGO_EC_SHA256

    def test_key_id_in_p2(self):
        apdu = build_sign(9, proto.ALGO_RSA_PKCS1, b"x")
        assert apdu[3] == 0x09

    def test_data_in_body(self):
        payload = b"\xDE\xAD\xBE\xEF" * 8
        apdu = build_sign(1, proto.ALGO_EC_SHA256, payload)
        assert payload in apdu

    def test_le_zero(self):
        apdu = build_sign(1, proto.ALGO_EC_SHA256, b"x")
        assert apdu[-1] == 0x00

    def test_extended_length_for_large_data(self):
        # RSA-4096 block is 512 bytes > 255 → must use extended APDU
        data = bytes(512)
        apdu = build_sign(1, proto.ALGO_RSA_PKCS1, data)
        # Extended APDU has Lc = 00 followed by 2-byte length
        assert apdu[4] == 0x00
        lc = struct.unpack(">H", apdu[5:7])[0]
        assert lc == 512


# ---------------------------------------------------------------------------
# parse_list_keys
# ---------------------------------------------------------------------------

class TestParseListKeys:
    def test_empty_response(self):
        assert parse_list_keys(b"") == []

    def test_single_rsa_key(self):
        # Synthesize a 4-byte record: FID=0xCC01, type=RSA(0x06), size=0x01 (2048-bit)
        record = bytes([0xCC, 0x01, KEY_TYPE_RSA, 0x01])
        result = parse_list_keys(record)
        assert len(result) == 1
        key = result[0]
        assert key["key_id"] == 0x01
        assert key["key_type"] == "RSA"
        assert key["key_size"] == 2048
        assert key["fid"] == 0xCC01

    def test_single_ec_key(self):
        record = bytes([0xCC, 0x02, KEY_TYPE_EC, 0x20])  # P-256
        result = parse_list_keys(record)
        assert len(result) == 1
        key = result[0]
        assert key["key_type"] == "EC"
        assert key["key_size"] == 256

    def test_single_aes_key(self):
        record = bytes([0xCC, 0x03, KEY_TYPE_AES, 0x20])  # AES-256
        result = parse_list_keys(record)
        assert len(result) == 1
        key = result[0]
        assert key["key_type"] == "AES"
        assert key["key_size"] == 256

    def test_multiple_keys(self):
        records = (
            bytes([0xCC, 0x01, KEY_TYPE_RSA, 0x01])  # RSA-2048
            + bytes([0xCC, 0x02, KEY_TYPE_EC, 0x20])  # EC-P256
        )
        result = parse_list_keys(records)
        assert len(result) == 2
        assert result[0]["key_type"] == "RSA"
        assert result[1]["key_type"] == "EC"

    def test_unknown_key_type(self):
        record = bytes([0xCC, 0x05, 0xFF, 0x00])
        result = parse_list_keys(record)
        assert len(result) == 1
        assert result[0]["key_type"] == "UNKNOWN"

    def test_rsa_4096(self):
        record = bytes([0xCC, 0x01, KEY_TYPE_RSA, 0x03])  # size_class=3 → 4096-bit
        result = parse_list_keys(record)
        assert result[0]["key_size"] == 4096


# ---------------------------------------------------------------------------
# parse_key_info
# ---------------------------------------------------------------------------

class TestParseKeyInfo:
    def _make_tlv(self, tag: int, value: bytes) -> bytes:
        return _encode_tlv(tag, value)

    def test_parses_key_type(self):
        data = self._make_tlv(0x80, bytes([KEY_TYPE_EC]))
        result = parse_key_info(data)
        assert result["key_type"] == "EC"

    def test_parses_key_size_two_bytes(self):
        data = self._make_tlv(0x81, struct.pack(">H", 2048))
        result = parse_key_info(data)
        assert result["key_size"] == 2048

    def test_parses_algorithm(self):
        data = self._make_tlv(0x82, bytes([proto.ALGO_EC_SHA256]))
        result = parse_key_info(data)
        assert result["algorithm"] == proto.ALGO_EC_SHA256

    def test_parses_combined(self):
        data = (
            self._make_tlv(0x80, bytes([KEY_TYPE_RSA]))
            + self._make_tlv(0x81, struct.pack(">H", 4096))
            + self._make_tlv(0x82, bytes([proto.ALGO_RSA_PKCS1_SHA256]))
        )
        result = parse_key_info(data)
        assert result["key_type"] == "RSA"
        assert result["key_size"] == 4096
        assert result["algorithm"] == proto.ALGO_RSA_PKCS1_SHA256

    def test_empty_response_raises(self):
        from pico2hsm.errors import ProtocolError
        with pytest.raises(ProtocolError):
            parse_key_info(b"")


# ---------------------------------------------------------------------------
# Algorithm constant sanity checks
# ---------------------------------------------------------------------------

class TestAlgoConstants:
    def test_algo_values(self):
        assert proto.ALGO_EC_SHA256 == 0x73
        assert proto.ALGO_RSA_PKCS1 == 0x30
        assert proto.ALGO_AES_CBC_ENCRYPT == 0x10
        assert proto.ALGO_WRAP == 0x92
        assert proto.ALGO_UNWRAP == 0x93

    def test_ins_values(self):
        assert proto.INS_INITIALIZE == 0x50
        assert proto.INS_GENERATE_KEYPAIR == 0x46
        assert proto.INS_SIGN == 0x68
        assert proto.INS_DECRYPT == 0x62
        assert proto.INS_VERIFY == 0x20


# ---------------------------------------------------------------------------
# APDU edge cases
# ---------------------------------------------------------------------------

class TestAPDUEdgeCases:
    def test_case1_apdu_length(self):
        """Case 1: no data, no Le → 4 bytes."""
        from pico2hsm.protocol import _encode_apdu
        apdu = _encode_apdu(0x00, 0xA4, 0x04, 0x00)
        assert len(apdu) == 4

    def test_case2_short_apdu(self):
        """Case 2: no data, Le=8 → 5 bytes."""
        from pico2hsm.protocol import _encode_apdu
        apdu = _encode_apdu(0x00, 0x84, 0x00, 0x00, le=8)
        assert len(apdu) == 5
        assert apdu[4] == 0x08

    def test_case3_apdu(self):
        """Case 3: data, no Le."""
        from pico2hsm.protocol import _encode_apdu
        data = bytes(10)
        apdu = _encode_apdu(0x00, 0x20, 0x00, 0x81, data)
        assert apdu[4] == 10
        assert len(apdu) == 4 + 1 + 10

    def test_case4_extended_apdu(self):
        """Case 4 with data > 255 uses extended Lc."""
        from pico2hsm.protocol import _encode_apdu
        data = bytes(300)
        apdu = _encode_apdu(0x80, 0x68, 0x73, 0x01, data, le=0)
        # Extended: header(4) + 00 + 2-byte Lc + data + 2-byte Le
        assert apdu[4] == 0x00
        lc = struct.unpack(">H", apdu[5:7])[0]
        assert lc == 300
