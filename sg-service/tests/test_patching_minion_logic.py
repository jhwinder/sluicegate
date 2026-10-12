from __future__ import annotations

import hashlib
import sys
from pathlib import Path
import pytest

# Add minion-registry/minions/patching to path for test imports
MINION_PATHING_DIR = Path(__file__).resolve().parents[2] / "minion-registry" / "minions" / "patching"
sys.path.insert(0, str(MINION_PATHING_DIR))

from patching_minion import (
    load_patch_catalog,
    load_nessus_mapping,
    resolve_target_patches,
    verify_file_sha256,
    reconcile_patches,
)


def test_load_patch_catalog_valid_and_approved_only(tmp_path: Path) -> None:
    catalog_file = tmp_path / "catalog.csv"
    catalog_content = (
        "patch_status,plugin_id,iavm_id,vendor,title,patch_id,patch_title,patch_type,requires_reboot,patch_path,patch_sha256,source_url,install_command,notes\n"
        "APPROVED,101,IAVM-01,Adobe,Acrobat,AA-01,Title 1,SECURITY,false,/path/to/p1.msp,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,https://example.com,msiexec /p \"%PATCHPATH%\",note 1\n"
        "DRAFT,102,IAVM-02,Adobe,Acrobat,AA-02,Title 2,SECURITY,false,/path/to/p2.msp,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,https://example.com,msiexec /p \"%PATCHPATH%\",note 2\n"
        "RETIRED,103,IAVM-03,Adobe,Acrobat,AA-03,Title 3,SECURITY,false,/path/to/p3.msp,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,https://example.com,msiexec /p \"%PATCHPATH%\",note 3\n"
    )
    catalog_file.write_text(catalog_content, encoding="utf-8")

    approved = load_patch_catalog(catalog_file)
    assert len(approved) == 1
    assert approved[0]["plugin_id"] == "101"
    assert approved[0]["patch_id"] == "AA-01"


def test_load_patch_catalog_rejects_duplicate_approved(tmp_path: Path) -> None:
    catalog_file = tmp_path / "catalog_dup.csv"
    catalog_content = (
        "patch_status,plugin_id,iavm_id,vendor,title,patch_id,patch_title,patch_type,requires_reboot,patch_path,patch_sha256,source_url,install_command,notes\n"
        "APPROVED,101,IAVM-01,Adobe,Acrobat,AA-01,Title 1,SECURITY,false,/path/1,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,https://example.com,cmd,n1\n"
        "APPROVED,101,IAVM-02,Adobe,Acrobat,AA-02,Title 2,SECURITY,false,/path/2,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,https://example.com,cmd,n2\n"
    )
    catalog_file.write_text(catalog_content, encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate approved catalog row"):
        load_patch_catalog(catalog_file)


def test_load_nessus_mapping_and_resolve_targets(tmp_path: Path) -> None:
    mapping_file = tmp_path / "mapping.csv"
    mapping_file.write_text(
        "PLUGIN_ID,DNS_NAME\n"
        "101,server01.example.gov\n"
        "102,server01.example.gov\n"
        "101,server02.example.gov\n"
        "999,unauthorized.example.gov\n",
        encoding="utf-8",
    )

    mappings = load_nessus_mapping(mapping_file)
    assert len(mappings) == 4

    approved_catalog = [
        {"plugin_id": "101", "patch_id": "P1", "patch_type": "SECURITY", "requires_reboot": "false"},
        {"plugin_id": "102", "patch_id": "P2", "patch_type": "FEATURE", "requires_reboot": "false"},
        {"plugin_id": "103", "patch_id": "P3", "patch_type": "SECURITY", "requires_reboot": "true"},
    ]

    # Target only server01, allowed SECURITY only, no reboot
    resolved = resolve_target_patches(
        mapping_rows=mappings,
        approved_catalog=approved_catalog,
        target_servers=["server01.example.gov"],
        allowed_patch_types=["SECURITY"],
        allow_reboot=False,
    )

    assert "server01.example.gov" in resolved
    assert len(resolved["server01.example.gov"]) == 1
    assert resolved["server01.example.gov"][0]["plugin_id"] == "101"
    assert "server02.example.gov" not in resolved


def test_reconcile_patches_full_flow(tmp_path: Path) -> None:
    # Create fake patch file
    patch_file = tmp_path / "patch.msp"
    patch_bytes = b"sample-patch-content-v1"
    patch_file.write_bytes(patch_bytes)
    sha256 = hashlib.sha256(patch_bytes).hexdigest()

    assert verify_file_sha256(patch_file, sha256) is True
    assert verify_file_sha256(patch_file, "wrong-hash" * 4) is False

    catalog_file = tmp_path / "catalog.csv"
    catalog_file.write_text(
        "patch_status,plugin_id,iavm_id,vendor,title,patch_id,patch_title,patch_type,requires_reboot,patch_path,patch_sha256,source_url,install_command,notes\n"
        f"APPROVED,201,IAVM-201,Vendor,Product,P-201,Title,SECURITY,false,{patch_file},{sha256},https://example.com,msiexec /p \"%PATCHPATH%\",ok\n",
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.csv"
    mapping_file.write_text(
        "PLUGIN_ID,DNS_NAME\n"
        "201,srv-app-01.domain.local\n",
        encoding="utf-8",
    )

    envelope = {
        "target": {"servers": ["srv-app-01.domain.local"]},
        "parameters": {
            "patch_sources": ["wsus", "nessus_catalog"],
            "patch_constraints": {
                "allowed_patch_types": ["SECURITY"],
                "allow_reboot": False,
            },
        },
    }

    outcome = reconcile_patches(
        envelope=envelope,
        catalog_path=catalog_file,
        mapping_path=mapping_file,
        dry_run=True,
    )

    assert outcome["status"] == "MISSION_COMPLETE_SUCCEEDED"
    result = outcome["result"]
    assert result["targets_count"] == 1
    target_res = result["target_results"][0]
    assert target_res["server"] == "srv-app-01.domain.local"
    assert len(target_res["catalog_patches"]) == 1
    assert target_res["catalog_patches"][0]["status"] == "SUCCESS"
    assert target_res["wsus_result"]["status"] == "SUCCESS"
