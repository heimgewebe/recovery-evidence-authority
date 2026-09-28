import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "validator.py")
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)

AUTH_REV = "1" * 40
HEIM_REV = "2" * 40
NOW = datetime(2026, 9, 28, 4, 0, 0, tzinfo=timezone.utc)


def contract():
    required = []
    for evidence_id, (scope, restore) in validator.EXPECTED_REQUIREMENTS.items():
        required.append(
            {
                "id": evidence_id,
                "scope": scope,
                "requires_restore_test": restore,
                "producer": validator.producer_for(evidence_id),
                "evidence_schema": validator.evidence_schema_for(evidence_id, False),
                "restore_test_schema": (
                    validator.evidence_schema_for(evidence_id, True) if restore else None
                ),
            }
        )
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_recovery_readiness_contract",
        "required_evidence": required,
        "evidence_freshness": {"maximum_age_seconds": 604800, "future_skew_seconds": 5},
        "evidence_attestation": {
            "status": "provisioned",
            "trust_model": "github-artifact-attestation",
            "repository": validator.AUTHORITY_REPOSITORY,
            "signer_workflow": validator.AUTHORITY_WORKFLOW,
            "signer_digest": AUTH_REV,
            "source_digest": AUTH_REV,
            "source_ref": "refs/heads/main",
            "predicate_type": validator.PREDICATE_TYPE,
            "deny_self_hosted_runners": True,
            "attestation_predicate_source_revision_bound": True,
            "producer_receipt_digest_bound": True,
            "provisioning_authority": "later-cutover-process",
        },
    }


def facts_for(evidence_id, restore):
    sha = "a" * 64
    if evidence_id == "off-host-home-restore":
        if restore:
            return {
                "off_host": True,
                "restore_test_passed": True,
                "restore_target_disposable": True,
                "source_inventory_sha256": sha,
                "restored_inventory_sha256": sha,
                "inventories_match": True,
                "network_required": False,
            }
        return {
            "off_host": True,
            "backup_snapshot_sha256": sha,
            "critical_scope_sha256": "b" * 64,
            "backup_complete": True,
            "target_independent": True,
        }
    if evidence_id == "offline-secret-recovery":
        if restore:
            return {
                "offline": True,
                "recovery_test_passed": True,
                "secret_bytes_exposed": False,
                "network_required": False,
                "production_system_disk_required": False,
            }
        return {
            "offline": True,
            "secret_bytes_exposed": False,
            "recovery_material_sha256": sha,
            "recovery_material_size": 65,
            "production_system_disk_required": False,
        }
    if evidence_id == "luks-header-metadata-backup":
        if restore:
            return {
                "header_restore_test_passed": True,
                "restore_target_disposable": True,
                "network_required": False,
                "secret_bytes_exposed": False,
            }
        return {
            "header_backup_sha256": sha,
            "header_backup_present": True,
            "source_class": "recovery-medium",
            "production_target_required": False,
            "secret_bytes_exposed": False,
        }
    if evidence_id == "bootable-recovery-media":
        if restore:
            return {
                "repeat_boot_passed": True,
                "network_required": False,
                "production_system_disk_required": False,
                "boot_stage": "luks-prompt",
            }
        return {
            "booted": True,
            "network_required": False,
            "production_system_disk_required": False,
            "boot_stage": "luks-prompt",
            "medium_identity_sha256": sha,
        }
    if evidence_id == "offline-host-control-closure":
        if restore:
            return {
                "offline_validation_passed": True,
                "network_required": False,
                "replacement_target_disposable": True,
                "host_closure_sha256": sha,
                "control_closure_sha256": "b" * 64,
            }
        return {
            "offline": True,
            "network_required": False,
            "host_closure_sha256": sha,
            "control_closure_sha256": "b" * 64,
            "material_complete": True,
        }
    if evidence_id == "network-off-reconstruction-boot":
        key = "repeat_reconstruction_passed" if restore else "booted"
        return {
            key: True,
            "network_required": False,
            "replacement_or_isolated_target": True,
            "system_closure": "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc",
            "closure_manifest_sha256": sha,
        }
    if evidence_id == "rpo-rto-record":
        return {
            "reviewed": True,
            "rpo_seconds": 86400,
            "rto_seconds": 14400,
            "basis_sha256": sha,
        }
    raise AssertionError(evidence_id)


def build_pair(evidence_id, restore=False):
    c = contract()
    contract_bytes = (json.dumps(c, sort_keys=True) + "\n").encode()
    contract_sha = hashlib.sha256(contract_bytes).hexdigest()
    scope, restore_required = validator.EXPECTED_REQUIREMENTS[evidence_id]
    if restore and not restore_required:
        raise AssertionError("invalid fixture")
    schema = validator.evidence_schema_for(evidence_id, restore)
    producer = validator.producer_for(evidence_id)
    facts = facts_for(evidence_id, restore)
    observed = "2026-09-28T03:55:00Z"
    receipt = {
        "schema_version": 1,
        "kind": validator.RECEIPT_KIND,
        "producer": producer,
        "evidence_id": evidence_id,
        "evidence_scope": scope,
        "evidence_schema": schema,
        "source_revision": HEIM_REV,
        "recovery_contract_sha256": contract_sha,
        "observed_at": observed,
        "result": "passed",
        "facts": facts,
        "production_effects_authorized": False,
    }
    receipt_bytes = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    provenance = {
        "schema_version": 1,
        "kind": (
            "heim_pc.nixos_recovery_restore_test_provenance"
            if restore
            else "heim_pc.nixos_recovery_evidence_provenance"
        ),
        "evidence_id": evidence_id,
        "evidence_scope": scope,
        "source_revision": HEIM_REV,
        "recovery_contract_sha256": contract_sha,
        "status": "passed",
        "observed_at": observed,
        "producer": producer,
        "evidence_schema": schema,
        "evidence": {
            "schema_version": 1,
            "kind": schema,
            "result": "passed",
            "producer_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "facts": facts,
        },
        "production_effects_authorized": False,
    }
    provenance_bytes = (json.dumps(provenance, sort_keys=True) + "\n").encode()
    return c, contract_bytes, receipt, receipt_bytes, provenance, provenance_bytes


@pytest.mark.parametrize("evidence_id", list(validator.EXPECTED_REQUIREMENTS))
def test_valid_evidence_provenance(evidence_id):
    c, cb, r, rb, p, pb = build_pair(evidence_id)
    predicate = validator.validate_subject(
        p, pb, r, rb, c, cb,
        authority_revision=AUTH_REV,
        expected_heim_pc_revision=HEIM_REV,
        now=NOW,
    )
    assert predicate["evidence_id"] == evidence_id
    assert predicate["producer_receipt_sha256"] == hashlib.sha256(rb).hexdigest()


@pytest.mark.parametrize(
    "evidence_id",
    [k for k, (_, restore) in validator.EXPECTED_REQUIREMENTS.items() if restore],
)
def test_valid_restore_provenance(evidence_id):
    c, cb, r, rb, p, pb = build_pair(evidence_id, restore=True)
    predicate = validator.validate_subject(
        p, pb, r, rb, c, cb,
        authority_revision=AUTH_REV,
        expected_heim_pc_revision=HEIM_REV,
        now=NOW,
    )
    assert predicate["provenance_kind"].endswith("restore_test_provenance")


def test_tampered_receipt_digest_rejected():
    c, cb, r, rb, p, pb = build_pair("offline-secret-recovery")
    r["facts"]["recovery_material_size"] = 66
    tampered = (json.dumps(r, sort_keys=True) + "\n").encode()
    with pytest.raises(validator.ValidationError, match="producer receipt digest mismatch"):
        validator.validate_subject(
            p, pb, r, tampered, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_unprovisioned_contract_rejected():
    c, cb, r, rb, p, pb = build_pair("bootable-recovery-media")
    c["evidence_attestation"]["status"] = "unprovisioned"
    with pytest.raises(validator.ValidationError, match="trust root mismatch"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_wrong_heim_pc_main_rejected():
    c, cb, r, rb, p, pb = build_pair("rpo-rto-record")
    with pytest.raises(validator.ValidationError, match="current Heim-PC main"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision="3" * 40,
            now=NOW,
        )
