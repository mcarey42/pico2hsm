"""Tests for device-to-device key transfer functions.

Tests the export/import/delete/transfer_keys functions using MockPico2HSM
from conftest.py -- no hardware required.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from pico2hsm.errors import Pico2HSMError
from pico2hsm.key_transfer import (
    export_key_from_device,
    import_key_to_device,
    delete_key_from_device,
    transfer_keys,
)
from conftest import MockPico2HSM


# ---------------------------------------------------------------------------
# Stub SyncPlan / SyncResult for tests (cluster.py may not exist)
# ---------------------------------------------------------------------------

@dataclass
class SyncPlan:
    missing_on_secondary: list
    conflicts: list
    tombstone_on_secondary: list
    orphans: list


@dataclass
class SyncResult:
    success: bool
    keys_transferred: int
    keys_deleted: int
    conflicts_resolved: int
    error: Optional[str] = None


# A valid 40-byte wrapped blob: KCV(8) + IV(16) + one CBC block(16)
VALID_BLOB_40 = bytes(range(40))

# A valid 56-byte blob: KCV(8) + IV(16) + two CBC blocks(32)
VALID_BLOB_56 = bytes(range(56))


# ---------------------------------------------------------------------------
# export_key_from_device
# ---------------------------------------------------------------------------

class TestExportKeyFromDevice:

    def test_export_key_calls_correct_apdu(self):
        """MockPico2HSM queued with 40-byte response, verify export returns it."""
        hsm = MockPico2HSM()
        hsm.queue_response(VALID_BLOB_40, sw=0x9000)

        result = export_key_from_device(hsm, key_ref=1)

        assert result == VALID_BLOB_40
        assert len(hsm.transmitted) == 1
        apdu = hsm.transmitted[0]
        # INS_EXPORT_KEY = 0x34, P2 = key_ref
        assert apdu[1] == 0x34
        assert apdu[3] == 0x01

    def test_export_key_validates_key_ref_low(self):
        """key_ref=0 should raise ValueError."""
        hsm = MockPico2HSM()
        with pytest.raises(ValueError, match="key_ref must be 1-254"):
            export_key_from_device(hsm, key_ref=0)

    def test_export_key_validates_key_ref_high(self):
        """key_ref=255 should raise ValueError."""
        hsm = MockPico2HSM()
        with pytest.raises(ValueError, match="key_ref must be 1-254"):
            export_key_from_device(hsm, key_ref=255)

    def test_export_key_apdu_error(self):
        """Non-9000 SW should raise Pico2HSMError."""
        hsm = MockPico2HSM()
        hsm.queue_response(b"", sw=0x6A82)

        with pytest.raises(Pico2HSMError, match="EXPORT KEY"):
            export_key_from_device(hsm, key_ref=1)

    def test_export_key_short_response(self):
        """Response shorter than 40 bytes should raise Pico2HSMError."""
        hsm = MockPico2HSM()
        hsm.queue_response(bytes(10), sw=0x9000)

        with pytest.raises(Pico2HSMError, match="too few bytes"):
            export_key_from_device(hsm, key_ref=1)


# ---------------------------------------------------------------------------
# import_key_to_device
# ---------------------------------------------------------------------------

class TestImportKeyToDevice:

    def test_import_key_validates_blob_too_short(self):
        """10-byte blob should raise ValueError."""
        hsm = MockPico2HSM()
        with pytest.raises(ValueError, match="too short"):
            import_key_to_device(hsm, key_ref=1, wrapped_blob=bytes(10))

    def test_import_key_validates_cbc_alignment(self):
        """41-byte blob (payload=17, not 16-aligned) should raise ValueError."""
        hsm = MockPico2HSM()
        # KCV(8) + IV(16) + 17 bytes = 41 total; 17 % 16 != 0
        blob = bytes(41)
        with pytest.raises(ValueError, match="not a multiple of 16"):
            import_key_to_device(hsm, key_ref=1, wrapped_blob=blob)

    def test_import_key_validates_blob_too_large(self):
        """Blob > 4096 bytes should raise ValueError."""
        hsm = MockPico2HSM()
        # KCV(8) + IV(16) + 4080 bytes = 4104 > 4096
        blob = bytes(4104)
        with pytest.raises(ValueError, match="too large"):
            import_key_to_device(hsm, key_ref=1, wrapped_blob=blob)

    def test_import_key_calls_correct_apdu(self):
        """Valid blob should trigger transmit with IMPORT KEY APDU."""
        hsm = MockPico2HSM()
        hsm.queue_response(b"", sw=0x9000)

        import_key_to_device(hsm, key_ref=5, wrapped_blob=VALID_BLOB_40)

        assert len(hsm.transmitted) == 1
        apdu = hsm.transmitted[0]
        # INS_IMPORT_KEY = 0x58, P2 = key_ref
        assert apdu[1] == 0x58
        assert apdu[3] == 0x05

    def test_import_key_apdu_error(self):
        """Non-9000 SW should raise Pico2HSMError."""
        hsm = MockPico2HSM()
        hsm.queue_response(b"", sw=0x6985)

        with pytest.raises(Pico2HSMError, match="IMPORT KEY"):
            import_key_to_device(hsm, key_ref=1, wrapped_blob=VALID_BLOB_40)


# ---------------------------------------------------------------------------
# delete_key_from_device
# ---------------------------------------------------------------------------

class TestDeleteKeyFromDevice:

    def test_delete_key_calls_apdu(self):
        """Delete should send DELETE FILE APDU."""
        hsm = MockPico2HSM()
        hsm.queue_response(b"", sw=0x9000)

        delete_key_from_device(hsm, key_ref=3)

        assert len(hsm.transmitted) == 1
        apdu = hsm.transmitted[0]
        # INS_DELETE_FILE = 0xE4
        assert apdu[1] == 0xE4

    def test_delete_key_validates_key_ref(self):
        """key_ref=0 should raise ValueError."""
        hsm = MockPico2HSM()
        with pytest.raises(ValueError):
            delete_key_from_device(hsm, key_ref=0)


# ---------------------------------------------------------------------------
# transfer_keys
# ---------------------------------------------------------------------------

class TestTransferKeys:

    def test_transfer_keys_missing(self):
        """Plan with missing=[1]: verify export+import called."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[1], conflicts=[], tombstone_on_secondary=[], orphans=[])

        # Primary: export returns valid blob
        primary.queue_response(VALID_BLOB_40, sw=0x9000)
        # Secondary: import succeeds
        secondary.queue_response(b"", sw=0x9000)

        result = transfer_keys(primary, secondary, plan)

        assert result.success
        assert result.keys_transferred == 1
        assert len(primary.transmitted) == 1   # export
        assert len(secondary.transmitted) == 1  # import

    def test_transfer_keys_conflict_overwrites(self):
        """Plan with conflicts=[2]: verify export+import called for secondary."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[], conflicts=[2], tombstone_on_secondary=[], orphans=[])

        # Primary: export blob
        primary.queue_response(VALID_BLOB_40, sw=0x9000)
        # Secondary: import succeeds
        secondary.queue_response(b"", sw=0x9000)

        result = transfer_keys(primary, secondary, plan)

        assert result.success
        assert result.conflicts_resolved == 1
        assert len(primary.transmitted) == 1
        assert len(secondary.transmitted) == 1

    def test_transfer_keys_tombstone_deletes(self):
        """Plan with tombstone_on_secondary=[3]: verify delete called on secondary."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[], conflicts=[], tombstone_on_secondary=[3], orphans=[])

        # Secondary: delete succeeds
        secondary.queue_response(b"", sw=0x9000)

        result = transfer_keys(primary, secondary, plan)

        assert result.success
        assert result.keys_deleted == 1
        assert len(primary.transmitted) == 0
        assert len(secondary.transmitted) == 1
        # Verify it was a DELETE FILE APDU
        assert secondary.transmitted[0][1] == 0xE4

    def test_transfer_keys_orphans_logged_not_deleted(self):
        """Plan with orphans=[4]: verify delete NOT called."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[], conflicts=[], tombstone_on_secondary=[], orphans=[4])

        result = transfer_keys(primary, secondary, plan)

        assert result.success
        assert result.keys_transferred == 0
        assert result.keys_deleted == 0
        assert len(primary.transmitted) == 0
        assert len(secondary.transmitted) == 0

    def test_transfer_keys_partial_failure(self):
        """If one key fails, continue with the rest and return success=False."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[1, 2], conflicts=[], tombstone_on_secondary=[], orphans=[])

        # Key 1: export succeeds, import fails
        primary.queue_response(VALID_BLOB_40, sw=0x9000)
        secondary.queue_response(b"", sw=0x6985)  # import fails
        # Key 2: export succeeds, import succeeds
        primary.queue_response(VALID_BLOB_40, sw=0x9000)
        secondary.queue_response(b"", sw=0x9000)

        result = transfer_keys(primary, secondary, plan)

        assert not result.success
        assert result.keys_transferred == 1
        assert result.error is not None

    def test_transfer_keys_conflict_with_backup(self, tmp_path):
        """Conflict with backup_dir: secondary's version should be saved."""
        primary = MockPico2HSM()
        secondary = MockPico2HSM()
        plan = SyncPlan(missing_on_secondary=[], conflicts=[7], tombstone_on_secondary=[], orphans=[])

        backup_dir = str(tmp_path)

        # Secondary: export for backup
        secondary.queue_response(VALID_BLOB_56, sw=0x9000)
        # Primary: export blob
        primary.queue_response(VALID_BLOB_40, sw=0x9000)
        # Secondary: import succeeds
        secondary.queue_response(b"", sw=0x9000)

        result = transfer_keys(primary, secondary, plan, conflict_backup_dir=backup_dir)

        assert result.success
        assert result.conflicts_resolved == 1
        # Verify backup file exists
        backup_file = os.path.join(backup_dir, "conflict_backup_key_7.bin")
        assert os.path.exists(backup_file)
        with open(backup_file, "rb") as f:
            assert f.read() == VALID_BLOB_56
