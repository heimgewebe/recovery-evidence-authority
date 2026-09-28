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


def _binding(identity):
    return validator.sha256_json(identity)


def base_facts(evidence_id):
    a = "a" * 64
    b = "b" * 64
    if evidence_id == "off-host-home-restore":
        identity = {"backup_snapshot_sha256": a, "critical_scope_sha256": b}
        return {
            "off_host": True,
            **identity,
            "backup_complete": True,
            "target_independent": True,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "offline-secret-recovery":
        identity = {"recovery_material_sha256": a, "recovery_material_size": 65}
        return {
            "offline": True,
            "secret_bytes_exposed": False,
            **identity,
            "production_system_disk_required": False,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "luks-header-metadata-backup":
        identity = {"header_backup_sha256": a, "source_class": "recovery-medium"}
        return {
            **identity,
            "header_backup_present": True,
            "production_target_required": False,
            "secret_bytes_exposed": False,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "bootable-recovery-media":
        identity = {"medium_identity_sha256": a}
        return {
            "booted": True,
            "network_required": False,
            "production_system_disk_required": False,
            "boot_stage": "luks-prompt",
            **identity,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "offline-host-control-closure":
        identity = {"host_closure_sha256": a, "control_closure_sha256": b}
        return {
            "offline": True,
            "network_required": False,
            **identity,
            "material_complete": True,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "network-off-reconstruction-boot":
        identity = {
            "system_closure": "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc",
            "closure_manifest_sha256": a,
        }
        return {
            "booted": True,
            "network_required": False,
            "replacement_or_isolated_target": True,
            **identity,
            "material_binding_sha256": _binding(identity),
        }
    if evidence_id == "rpo-rto-record":
        return {
            "reviewed": True,
            "rpo_seconds": 86400,
            "rto_seconds": 14400,
            "basis_sha256": a,
        }
    raise AssertionError(evidence_id)


def restore_facts(evidence_id, base_receipt_bytes, base):
    base_sha = hashlib.sha256(base_receipt_bytes).hexdigest()
    binding = base["material_binding_sha256"]
    if evidence_id == "off-host-home-restore":
        return {
            "off_host": True,
            "restore_test_passed": True,
            "restore_target_disposable": True,
            "source_inventory_sha256": "c" * 64,
            "restored_inventory_sha256": "c" * 64,
            "inventories_match": True,
            "network_required": False,
            "backup_snapshot_sha256": base["backup_snapshot_sha256"],
            "critical_scope_sha256": base["critical_scope_sha256"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    if evidence_id == "offline-secret-recovery":
        return {
            "offline": True,
            "recovery_test_passed": True,
            "secret_bytes_exposed": False,
            "network_required": False,
            "production_system_disk_required": False,
            "recovery_material_sha256": base["recovery_material_sha256"],
            "recovery_material_size": base["recovery_material_size"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    if evidence_id == "luks-header-metadata-backup":
        return {
            "header_restore_test_passed": True,
            "restore_target_disposable": True,
            "network_required": False,
            "secret_bytes_exposed": False,
            "header_backup_sha256": base["header_backup_sha256"],
            "source_class": base["source_class"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    if evidence_id == "bootable-recovery-media":
        return {
            "repeat_boot_passed": True,
            "network_required": False,
            "production_system_disk_required": False,
            "boot_stage": "luks-prompt",
            "medium_identity_sha256": base["medium_identity_sha256"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    if evidence_id == "offline-host-control-closure":
        return {
            "offline_validation_passed": True,
            "network_required": False,
            "replacement_target_disposable": True,
            "host_closure_sha256": base["host_closure_sha256"],
            "control_closure_sha256": base["control_closure_sha256"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    if evidence_id == "network-off-reconstruction-boot":
        return {
            "repeat_reconstruction_passed": True,
            "network_required": False,
            "replacement_or_isolated_target": True,
            "system_closure": base["system_closure"],
            "closure_manifest_sha256": base["closure_manifest_sha256"],
            "material_binding_sha256": binding,
            "base_producer_receipt_sha256": base_sha,
        }
    raise AssertionError(evidence_id)


def make_receipt(evidence_id, schema, facts, contract_sha, observed_at):
    scope = validator.EXPECTED_REQUIREMENTS[evidence_id][0]
    return {
        "schema_version": 1,
        "kind": validator.RECEIPT_KIND,
        "producer": validator.producer_for(evidence_id),
        "evidence_id": evidence_id,
        "evidence_scope": scope,
        "evidence_schema": schema,
        "source_revision": HEIM_REV,
        "recovery_contract_sha256": contract_sha,
        "observed_at": observed_at,
        "result": "passed",
        "facts": facts,
        "production_effects_authorized": False,
    }


def make_provenance(evidence_id, restore, facts, receipt_bytes, contract_sha, observed_at):
    scope = validator.EXPECTED_REQUIREMENTS[evidence_id][0]
    schema = validator.evidence_schema_for(evidence_id, restore)
    return {
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
        "observed_at": observed_at,
        "producer": validator.producer_for(evidence_id),
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


def build_pair(evidence_id, restore=False):
    c = contract()
    cb = (json.dumps(c, sort_keys=True) + "\n").encode()
    csha = hashlib.sha256(cb).hexdigest()
    base = base_facts(evidence_id)
    base_schema = validator.evidence_schema_for(evidence_id, False)
    base_receipt = make_receipt(evidence_id, base_schema, base, csha, "2026-09-28T03:50:00Z")
    base_rb = (json.dumps(base_receipt, sort_keys=True) + "\n").encode()
    if not restore:
        p = make_provenance(evidence_id, False, base, base_rb, csha, "2026-09-28T03:50:00Z")
        pb = (json.dumps(p, sort_keys=True) + "\n").encode()
        return c, cb, base_receipt, base_rb, p, pb, None, None

    if not validator.EXPECTED_REQUIREMENTS[evidence_id][1]:
        raise AssertionError("invalid restore fixture")
    rf = restore_facts(evidence_id, base_rb, base)
    schema = validator.evidence_schema_for(evidence_id, True)
    receipt = make_receipt(evidence_id, schema, rf, csha, "2026-09-28T03:55:00Z")
    rb = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    p = make_provenance(evidence_id, True, rf, rb, csha, "2026-09-28T03:55:00Z")
    pb = (json.dumps(p, sort_keys=True) + "\n").encode()
    return c, cb, receipt, rb, p, pb, base_receipt, base_rb


@pytest.mark.parametrize("evidence_id", list(validator.EXPECTED_REQUIREMENTS))
def test_valid_evidence_provenance(evidence_id):
    c, cb, r, rb, p, pb, _br, _brb = build_pair(evidence_id)
    predicate = validator.validate_subject(
        p, pb, r, rb, c, cb,
        authority_revision=AUTH_REV,
        expected_heim_pc_revision=HEIM_REV,
        now=NOW,
    )
    assert predicate["evidence_id"] == evidence_id


@pytest.mark.parametrize(
    "evidence_id",
    [k for k, (_, restore) in validator.EXPECTED_REQUIREMENTS.items() if restore],
)
def test_valid_restore_provenance_is_bound_to_base_material(evidence_id):
    c, cb, r, rb, p, pb, br, brb = build_pair(evidence_id, restore=True)
    predicate = validator.validate_subject(
        p, pb, r, rb, c, cb,
        authority_revision=AUTH_REV,
        expected_heim_pc_revision=HEIM_REV,
        base_receipt=br,
        base_receipt_bytes=brb,
        now=NOW,
    )
    assert predicate["provenance_kind"].endswith("restore_test_provenance")


def test_restore_requires_base_receipt():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("offline-secret-recovery", restore=True)
    with pytest.raises(validator.ValidationError, match="signed base producer receipt"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_restore_rejects_different_recovery_material_even_with_rebound_base_digest():
    c, cb, r, rb, p, pb, br, brb = build_pair("offline-secret-recovery", restore=True)
    br["facts"]["recovery_material_sha256"] = "d" * 64
    identity = {
        "recovery_material_sha256": br["facts"]["recovery_material_sha256"],
        "recovery_material_size": br["facts"]["recovery_material_size"],
    }
    br["facts"]["material_binding_sha256"] = _binding(identity)
    changed_brb = (json.dumps(br, sort_keys=True) + "\n").encode()
    r["facts"]["base_producer_receipt_sha256"] = hashlib.sha256(changed_brb).hexdigest()
    rb = (json.dumps(r, sort_keys=True) + "\n").encode()
    p["evidence"]["producer_receipt_sha256"] = hashlib.sha256(rb).hexdigest()
    p["evidence"]["facts"] = r["facts"]
    pb = (json.dumps(p, sort_keys=True) + "\n").encode()
    with pytest.raises(validator.ValidationError, match="material binding differs"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            base_receipt=br,
            base_receipt_bytes=changed_brb,
            now=NOW,
        )


def test_provenance_bool_does_not_equal_integer_one():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("offline-secret-recovery")
    p["evidence"]["facts"] = dict(p["evidence"]["facts"])
    p["evidence"]["facts"]["offline"] = 1
    pb = (json.dumps(p, sort_keys=True) + "\n").encode()
    with pytest.raises(validator.ValidationError, match="offline must be True"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_provenance_integer_does_not_equal_float():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("offline-secret-recovery")
    p["evidence"]["facts"] = dict(p["evidence"]["facts"])
    p["evidence"]["facts"]["recovery_material_size"] = 65.0
    pb = (json.dumps(p, sort_keys=True) + "\n").encode()
    with pytest.raises(validator.ValidationError, match="must be an integer"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_tampered_receipt_digest_rejected():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("offline-secret-recovery")
    r["facts"]["recovery_material_size"] = 66
    tampered = (json.dumps(r, sort_keys=True) + "\n").encode()
    with pytest.raises(validator.ValidationError):
        validator.validate_subject(
            p, pb, r, tampered, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_unprovisioned_contract_rejected():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("bootable-recovery-media")
    c["evidence_attestation"]["status"] = "unprovisioned"
    with pytest.raises(validator.ValidationError, match="trust root mismatch"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )


def test_wrong_heim_pc_main_rejected():
    c, cb, r, rb, p, pb, _br, _brb = build_pair("rpo-rto-record")
    with pytest.raises(validator.ValidationError, match="current Heim-PC main"):
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision="3" * 40,
            now=NOW,
        )


def test_producer_signature_verifier_uses_exact_receipt_bytes(monkeypatch, tmp_path):
    receipt_bytes = b'{"receipt":"exact"}\n'
    signature = tmp_path / "receipt.sig"
    signature.write_text("-----BEGIN SSH SIGNATURE-----\nfixture\n-----END SSH SIGNATURE-----\n")
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(
        "heimberry-recovery-producer ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIHW1P0IHun3CCzTA+ihKV2aExfpuoSt5s2Qo6v2yflpd\n"
    )
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["input"] = kwargs["input"]
        observed["env"] = kwargs["env"]
        return validator.subprocess.CompletedProcess(argv, 0, b"Good signature\n", b"")

    monkeypatch.setattr(validator.subprocess, "run", fake_run)
    result = validator.verify_producer_signature(receipt_bytes, signature, allowed)
    assert observed["input"] == receipt_bytes
    assert observed["argv"] == [
        "/usr/bin/ssh-keygen", "-Y", "verify",
        "-f", str(allowed),
        "-I", "heimberry-recovery-producer",
        "-n", "heim-pc-recovery-evidence",
        "-s", str(signature),
    ]
    assert observed["env"]["PATH"] == "/usr/bin:/bin"
    assert result["producer_signature_sha256"] == hashlib.sha256(signature.read_bytes()).hexdigest()


def test_producer_signature_verifier_fails_closed(monkeypatch, tmp_path):
    signature = tmp_path / "receipt.sig"
    signature.write_text("invalid-signature\n")
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(
        "heimberry-recovery-producer ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIHW1P0IHun3CCzTA+ihKV2aExfpuoSt5s2Qo6v2yflpd\n"
    )

    def fake_run(argv, **kwargs):
        return validator.subprocess.CompletedProcess(argv, 255, b"", b"Signature verification failed")

    monkeypatch.setattr(validator.subprocess, "run", fake_run)
    with pytest.raises(validator.ValidationError, match="signature verification failed"):
        validator.verify_producer_signature(b"receipt\n", signature, allowed)
