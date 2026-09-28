#!/usr/bin/env python3
"""Fail-closed validator for Heim-PC recovery provenance attestations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

AUTHORITY_REPOSITORY = "heimgewebe/recovery-evidence-authority"
AUTHORITY_WORKFLOW = (
    "heimgewebe/recovery-evidence-authority/.github/workflows/recovery-evidence.yml"
)
HEIM_PC_REPOSITORY = "heimgewebe/heim-pc"
PREDICATE_TYPE = "https://heimgewebe.local/attestations/nixos-recovery-evidence/v1"
PROVENANCE_KINDS = {
    "heim_pc.nixos_recovery_evidence_provenance",
    "heim_pc.nixos_recovery_restore_test_provenance",
}
RECEIPT_KIND = "heim_pc.external_recovery_producer_receipt.v1"
ATTESTATION_KIND = "heim_pc.nixos_recovery_provenance_attestation"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
PRODUCER_SIGNER_IDENTITY = "heimberry-recovery-producer"
PRODUCER_SIGNATURE_NAMESPACE = "heim-pc-recovery-evidence"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
STORE_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+$")

EXPECTED_REQUIREMENTS = {
    "off-host-home-restore": ("critical-user-data", True),
    "offline-secret-recovery": ("recovery-identity", True),
    "luks-header-metadata-backup": ("storage-recovery-material", True),
    "bootable-recovery-media": ("host-independent-boot", True),
    "offline-host-control-closure": ("known-good-host-and-control-closure", True),
    "network-off-reconstruction-boot": ("replacement-or-isolated-target", True),
    "rpo-rto-record": ("representative-recovery", False),
}


class ValidationError(ValueError):
    pass


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def load_json_bytes(path: Path, label: str, max_bytes: int = 256 * 1024) -> tuple[dict[str, Any], bytes]:
    payload = path.read_bytes()
    if not payload or len(payload) > max_bytes:
        raise ValidationError(f"{label} size is outside the bounded contract")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return value, payload


def verify_producer_signature(
    receipt_bytes: bytes,
    signature_path: Path,
    allowed_signers_path: Path,
) -> dict[str, str]:
    """Verify the exact producer-receipt bytes against the pinned external signer."""
    signature_bytes = signature_path.read_bytes()
    if not signature_bytes or len(signature_bytes) > 64 * 1024:
        raise ValidationError("producer signature size is outside the bounded contract")
    allowed_signers_bytes = allowed_signers_path.read_bytes()
    if not allowed_signers_bytes or len(allowed_signers_bytes) > 64 * 1024:
        raise ValidationError("allowed signers file is outside the bounded contract")
    argv = [
        SSH_KEYGEN,
        "-Y",
        "verify",
        "-f",
        str(allowed_signers_path),
        "-I",
        PRODUCER_SIGNER_IDENTITY,
        "-n",
        PRODUCER_SIGNATURE_NAMESPACE,
        "-s",
        str(signature_path),
    ]
    try:
        result = subprocess.run(
            argv,
            input=receipt_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except OSError as exc:
        raise ValidationError("producer signature verifier could not execute") from exc
    if result.returncode != 0:
        raise ValidationError("producer receipt signature verification failed")
    return {
        "producer_signature_sha256": sha256_bytes(signature_bytes),
        "allowed_signers_sha256": sha256_bytes(allowed_signers_bytes),
        "verifier_argv_sha256": sha256_json(argv),
    }


def require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise ValidationError(f"{label} keys mismatch")


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be lowercase sha256")
    return value


def require_revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or REVISION_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be exact 40-hex revision")
    return value


def require_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValidationError(f"{label} is invalid") from exc


def require_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        raise ValidationError(f"{label} must be {expected}")


def require_positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{label} must be an integer")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValidationError(f"{label} is outside range")
    return value


def producer_for(evidence_id: str) -> str:
    return f"heim_pc.external_recovery_producer.{evidence_id.replace('-', '_')}.v1"


def evidence_schema_for(evidence_id: str, restore: bool) -> str:
    base = f"heim_pc.recovery.{evidence_id.replace('-', '_')}.v1"
    return base + ".restore_test" if restore else base


def validate_off_host_home_restore(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        require_exact_keys(
            facts,
            {
                "off_host",
                "restore_test_passed",
                "restore_target_disposable",
                "source_inventory_sha256",
                "restored_inventory_sha256",
                "inventories_match",
                "network_required",
            },
            "off-host-home-restore restore facts",
        )
        require_bool(facts["off_host"], True, "off_host")
        require_bool(facts["restore_test_passed"], True, "restore_test_passed")
        require_bool(facts["restore_target_disposable"], True, "restore_target_disposable")
        require_sha(facts["source_inventory_sha256"], "source_inventory_sha256")
        require_sha(facts["restored_inventory_sha256"], "restored_inventory_sha256")
        if facts["source_inventory_sha256"] != facts["restored_inventory_sha256"]:
            raise ValidationError("off-host restore inventory digests differ")
        require_bool(facts["inventories_match"], True, "inventories_match")
        require_bool(facts["network_required"], False, "network_required")
    else:
        require_exact_keys(
            facts,
            {
                "off_host",
                "backup_snapshot_sha256",
                "critical_scope_sha256",
                "backup_complete",
                "target_independent",
            },
            "off-host-home-restore facts",
        )
        require_bool(facts["off_host"], True, "off_host")
        require_sha(facts["backup_snapshot_sha256"], "backup_snapshot_sha256")
        require_sha(facts["critical_scope_sha256"], "critical_scope_sha256")
        require_bool(facts["backup_complete"], True, "backup_complete")
        require_bool(facts["target_independent"], True, "target_independent")


def validate_offline_secret_recovery(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        require_exact_keys(
            facts,
            {
                "offline",
                "recovery_test_passed",
                "secret_bytes_exposed",
                "network_required",
                "production_system_disk_required",
            },
            "offline-secret-recovery restore facts",
        )
        require_bool(facts["offline"], True, "offline")
        require_bool(facts["recovery_test_passed"], True, "recovery_test_passed")
        require_bool(facts["secret_bytes_exposed"], False, "secret_bytes_exposed")
        require_bool(facts["network_required"], False, "network_required")
        require_bool(
            facts["production_system_disk_required"],
            False,
            "production_system_disk_required",
        )
    else:
        require_exact_keys(
            facts,
            {
                "offline",
                "secret_bytes_exposed",
                "recovery_material_sha256",
                "recovery_material_size",
                "production_system_disk_required",
            },
            "offline-secret-recovery facts",
        )
        require_bool(facts["offline"], True, "offline")
        require_bool(facts["secret_bytes_exposed"], False, "secret_bytes_exposed")
        require_sha(facts["recovery_material_sha256"], "recovery_material_sha256")
        require_positive_int(facts["recovery_material_size"], "recovery_material_size")
        require_bool(
            facts["production_system_disk_required"],
            False,
            "production_system_disk_required",
        )


def validate_luks_header(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        require_exact_keys(
            facts,
            {
                "header_restore_test_passed",
                "restore_target_disposable",
                "network_required",
                "secret_bytes_exposed",
            },
            "luks-header restore facts",
        )
        require_bool(facts["header_restore_test_passed"], True, "header_restore_test_passed")
        require_bool(facts["restore_target_disposable"], True, "restore_target_disposable")
        require_bool(facts["network_required"], False, "network_required")
        require_bool(facts["secret_bytes_exposed"], False, "secret_bytes_exposed")
    else:
        require_exact_keys(
            facts,
            {
                "header_backup_sha256",
                "header_backup_present",
                "source_class",
                "production_target_required",
                "secret_bytes_exposed",
            },
            "luks-header facts",
        )
        require_sha(facts["header_backup_sha256"], "header_backup_sha256")
        require_bool(facts["header_backup_present"], True, "header_backup_present")
        if facts["source_class"] not in {"rehearsal", "recovery-medium", "disposable-target"}:
            raise ValidationError("luks header source_class is invalid")
        require_bool(facts["production_target_required"], False, "production_target_required")
        require_bool(facts["secret_bytes_exposed"], False, "secret_bytes_exposed")


def validate_bootable_media(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        require_exact_keys(
            facts,
            {
                "repeat_boot_passed",
                "network_required",
                "production_system_disk_required",
                "boot_stage",
            },
            "bootable recovery restore facts",
        )
        require_bool(facts["repeat_boot_passed"], True, "repeat_boot_passed")
    else:
        require_exact_keys(
            facts,
            {
                "booted",
                "network_required",
                "production_system_disk_required",
                "boot_stage",
                "medium_identity_sha256",
            },
            "bootable recovery facts",
        )
        require_bool(facts["booted"], True, "booted")
        require_sha(facts["medium_identity_sha256"], "medium_identity_sha256")
    require_bool(facts["network_required"], False, "network_required")
    require_bool(
        facts["production_system_disk_required"],
        False,
        "production_system_disk_required",
    )
    if facts["boot_stage"] not in {"luks-prompt", "recovery-shell", "system"}:
        raise ValidationError("boot_stage is invalid")


def validate_offline_host_control(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        require_exact_keys(
            facts,
            {
                "offline_validation_passed",
                "network_required",
                "replacement_target_disposable",
                "host_closure_sha256",
                "control_closure_sha256",
            },
            "offline host/control restore facts",
        )
        require_bool(facts["offline_validation_passed"], True, "offline_validation_passed")
        require_bool(facts["network_required"], False, "network_required")
        require_bool(facts["replacement_target_disposable"], True, "replacement_target_disposable")
    else:
        require_exact_keys(
            facts,
            {
                "offline",
                "network_required",
                "host_closure_sha256",
                "control_closure_sha256",
                "material_complete",
            },
            "offline host/control facts",
        )
        require_bool(facts["offline"], True, "offline")
        require_bool(facts["network_required"], False, "network_required")
        require_bool(facts["material_complete"], True, "material_complete")
    require_sha(facts["host_closure_sha256"], "host_closure_sha256")
    require_sha(facts["control_closure_sha256"], "control_closure_sha256")


def validate_network_off_boot(facts: dict[str, Any], restore: bool) -> None:
    keys = {
        "network_required",
        "replacement_or_isolated_target",
        "system_closure",
        "closure_manifest_sha256",
        "repeat_reconstruction_passed" if restore else "booted",
    }
    require_exact_keys(facts, keys, "network-off reconstruction facts")
    require_bool(
        facts["repeat_reconstruction_passed" if restore else "booted"],
        True,
        "reconstruction result",
    )
    require_bool(facts["network_required"], False, "network_required")
    require_bool(
        facts["replacement_or_isolated_target"],
        True,
        "replacement_or_isolated_target",
    )
    if not isinstance(facts["system_closure"], str) or STORE_RE.fullmatch(facts["system_closure"]) is None:
        raise ValidationError("system_closure is not a canonical Nix store path")
    require_sha(facts["closure_manifest_sha256"], "closure_manifest_sha256")


def validate_rpo_rto(facts: dict[str, Any], restore: bool) -> None:
    if restore:
        raise ValidationError("rpo-rto-record cannot carry restore-test provenance")
    require_exact_keys(
        facts,
        {"reviewed", "rpo_seconds", "rto_seconds", "basis_sha256"},
        "rpo-rto facts",
    )
    require_bool(facts["reviewed"], True, "reviewed")
    require_positive_int(facts["rpo_seconds"], "rpo_seconds", allow_zero=True)
    require_positive_int(facts["rto_seconds"], "rto_seconds")
    require_sha(facts["basis_sha256"], "basis_sha256")


FACT_VALIDATORS: dict[str, Callable[[dict[str, Any], bool], None]] = {
    "off-host-home-restore": validate_off_host_home_restore,
    "offline-secret-recovery": validate_offline_secret_recovery,
    "luks-header-metadata-backup": validate_luks_header,
    "bootable-recovery-media": validate_bootable_media,
    "offline-host-control-closure": validate_offline_host_control,
    "network-off-reconstruction-boot": validate_network_off_boot,
    "rpo-rto-record": validate_rpo_rto,
}


def validate_contract(
    contract: dict[str, Any],
    raw_contract: bytes,
    *,
    authority_revision: str,
) -> dict[str, tuple[str, bool, str, str]]:
    require_revision(authority_revision, "authority revision")
    if contract.get("schema_version") != 1 or contract.get("kind") != "heim_pc.nixos_recovery_readiness_contract":
        raise ValidationError("recovery contract identity mismatch")
    required = contract.get("required_evidence")
    if not isinstance(required, list) or len(required) != len(EXPECTED_REQUIREMENTS):
        raise ValidationError("recovery evidence requirement set mismatch")
    result: dict[str, tuple[str, bool, str, str]] = {}
    for item in required:
        if not isinstance(item, dict):
            raise ValidationError("recovery evidence requirement is malformed")
        require_exact_keys(
            item,
            {
                "id",
                "scope",
                "requires_restore_test",
                "producer",
                "evidence_schema",
                "restore_test_schema",
            },
            "recovery evidence requirement",
        )
        evidence_id = item["id"]
        if evidence_id not in EXPECTED_REQUIREMENTS or evidence_id in result:
            raise ValidationError("foreign or duplicate recovery evidence id")
        scope, restore_required = EXPECTED_REQUIREMENTS[evidence_id]
        if item["scope"] != scope or item["requires_restore_test"] is not restore_required:
            raise ValidationError("recovery evidence scope/restore policy mismatch")
        producer = producer_for(evidence_id)
        evidence_schema = evidence_schema_for(evidence_id, False)
        restore_schema = evidence_schema_for(evidence_id, True) if restore_required else None
        if (
            item["producer"] != producer
            or item["evidence_schema"] != evidence_schema
            or item["restore_test_schema"] != restore_schema
        ):
            raise ValidationError("recovery producer/schema contract mismatch")
        result[evidence_id] = (scope, restore_required, producer, evidence_schema)

    freshness = contract.get("evidence_freshness")
    if not isinstance(freshness, dict):
        raise ValidationError("recovery freshness policy missing")
    max_age = require_positive_int(freshness.get("maximum_age_seconds"), "maximum_age_seconds")
    skew = require_positive_int(
        freshness.get("future_skew_seconds"),
        "future_skew_seconds",
        allow_zero=True,
    )
    if skew > 300:
        raise ValidationError("future skew is excessive")

    policy = contract.get("evidence_attestation")
    if not isinstance(policy, dict):
        raise ValidationError("recovery attestation policy missing")
    require_exact_keys(
        policy,
        {
            "status",
            "trust_model",
            "repository",
            "signer_workflow",
            "signer_digest",
            "source_digest",
            "source_ref",
            "predicate_type",
            "deny_self_hosted_runners",
            "attestation_predicate_source_revision_bound",
            "producer_receipt_digest_bound",
            "provisioning_authority",
        },
        "recovery attestation policy",
    )
    if (
        policy["status"] != "provisioned"
        or policy["trust_model"] != "github-artifact-attestation"
        or policy["repository"] != AUTHORITY_REPOSITORY
        or policy["signer_workflow"] != AUTHORITY_WORKFLOW
        or policy["signer_digest"] != authority_revision
        or policy["source_digest"] != authority_revision
        or policy["source_ref"] != "refs/heads/main"
        or policy["predicate_type"] != PREDICATE_TYPE
        or policy["deny_self_hosted_runners"] is not True
        or policy["attestation_predicate_source_revision_bound"] is not True
        or policy["producer_receipt_digest_bound"] is not True
        or policy["provisioning_authority"] != "later-cutover-process"
    ):
        raise ValidationError("recovery attestation trust root mismatch")
    return result


def validate_subject(
    provenance: dict[str, Any],
    provenance_bytes: bytes,
    receipt: dict[str, Any],
    receipt_bytes: bytes,
    contract: dict[str, Any],
    contract_bytes: bytes,
    *,
    authority_revision: str,
    expected_heim_pc_revision: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    requirements = validate_contract(contract, contract_bytes, authority_revision=authority_revision)
    require_revision(expected_heim_pc_revision, "expected Heim-PC revision")
    require_exact_keys(
        provenance,
        {
            "schema_version",
            "kind",
            "evidence_id",
            "evidence_scope",
            "source_revision",
            "recovery_contract_sha256",
            "status",
            "observed_at",
            "producer",
            "evidence_schema",
            "evidence",
            "production_effects_authorized",
        },
        "provenance",
    )
    if provenance["schema_version"] != 1 or provenance["kind"] not in PROVENANCE_KINDS:
        raise ValidationError("provenance identity mismatch")
    evidence_id = provenance["evidence_id"]
    if evidence_id not in requirements:
        raise ValidationError("provenance evidence id is foreign")
    scope, restore_required, producer, base_schema = requirements[evidence_id]
    restore = provenance["kind"] == "heim_pc.nixos_recovery_restore_test_provenance"
    if restore and not restore_required:
        raise ValidationError("restore-test provenance is not required for this evidence")
    schema = evidence_schema_for(evidence_id, restore)
    if (
        provenance["evidence_scope"] != scope
        or provenance["producer"] != producer
        or provenance["evidence_schema"] != schema
    ):
        raise ValidationError("provenance producer/schema binding mismatch")
    if provenance["source_revision"] != expected_heim_pc_revision:
        raise ValidationError("provenance is not bound to current Heim-PC main")
    contract_sha = sha256_bytes(contract_bytes)
    if provenance["recovery_contract_sha256"] != contract_sha:
        raise ValidationError("provenance recovery contract digest mismatch")
    if provenance["status"] != "passed":
        raise ValidationError("provenance did not pass")
    require_bool(
        provenance["production_effects_authorized"],
        False,
        "production_effects_authorized",
    )

    observed = require_utc(provenance["observed_at"], "provenance observed_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    freshness = contract["evidence_freshness"]
    age = (current - observed).total_seconds()
    if age < -freshness["future_skew_seconds"] or age > freshness["maximum_age_seconds"]:
        raise ValidationError("provenance is outside freshness policy")

    require_exact_keys(
        receipt,
        {
            "schema_version",
            "kind",
            "producer",
            "evidence_id",
            "evidence_scope",
            "evidence_schema",
            "source_revision",
            "recovery_contract_sha256",
            "observed_at",
            "result",
            "facts",
            "production_effects_authorized",
        },
        "producer receipt",
    )
    if receipt["schema_version"] != 1 or receipt["kind"] != RECEIPT_KIND:
        raise ValidationError("producer receipt identity mismatch")
    for field in (
        "producer",
        "evidence_id",
        "evidence_scope",
        "evidence_schema",
        "source_revision",
        "recovery_contract_sha256",
        "observed_at",
    ):
        if receipt[field] != provenance[field]:
            raise ValidationError(f"producer receipt {field} mismatch")
    if receipt["result"] != "passed":
        raise ValidationError("producer receipt did not pass")
    require_bool(
        receipt["production_effects_authorized"],
        False,
        "producer receipt production_effects_authorized",
    )
    facts = receipt["facts"]
    if not isinstance(facts, dict) or not facts:
        raise ValidationError("producer receipt facts are missing")
    FACT_VALIDATORS[evidence_id](facts, restore)

    evidence = provenance["evidence"]
    if not isinstance(evidence, dict):
        raise ValidationError("provenance evidence payload missing")
    require_exact_keys(
        evidence,
        {"schema_version", "kind", "result", "producer_receipt_sha256", "facts"},
        "provenance evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != schema or evidence["result"] != "passed":
        raise ValidationError("provenance evidence schema/result mismatch")
    if evidence["facts"] != facts:
        raise ValidationError("provenance evidence facts differ from producer receipt")
    receipt_sha = sha256_bytes(receipt_bytes)
    if evidence["producer_receipt_sha256"] != receipt_sha:
        raise ValidationError("producer receipt digest mismatch")

    return {
        "schema_version": 1,
        "kind": ATTESTATION_KIND,
        "provenance_kind": provenance["kind"],
        "provenance_sha256": sha256_bytes(provenance_bytes),
        "producer": producer,
        "evidence_id": evidence_id,
        "evidence_scope": scope,
        "evidence_schema": schema,
        "evidence_sha256": sha256_json(evidence),
        "producer_receipt_sha256": receipt_sha,
        "source_revision": provenance["source_revision"],
        "recovery_contract_sha256": contract_sha,
        "observed_at": provenance["observed_at"],
        "production_effects_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--producer-receipt", type=Path, required=True)
    parser.add_argument("--producer-signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--recovery-contract", type=Path, required=True)
    parser.add_argument("--authority-revision", required=True)
    parser.add_argument("--expected-heim-pc-revision", required=True)
    parser.add_argument("--write-predicate", type=Path, required=True)
    args = parser.parse_args()

    provenance, provenance_bytes = load_json_bytes(args.provenance, "provenance")
    receipt, receipt_bytes = load_json_bytes(args.producer_receipt, "producer receipt")
    verify_producer_signature(
        receipt_bytes,
        args.producer_signature,
        args.allowed_signers,
    )
    contract, contract_bytes = load_json_bytes(args.recovery_contract, "recovery contract")
    predicate = validate_subject(
        provenance,
        provenance_bytes,
        receipt,
        receipt_bytes,
        contract,
        contract_bytes,
        authority_revision=args.authority_revision,
        expected_heim_pc_revision=args.expected_heim_pc_revision,
    )
    args.write_predicate.write_text(
        json.dumps(predicate, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "evidence_id": predicate["evidence_id"],
                "provenance_kind": predicate["provenance_kind"],
                "source_revision": predicate["source_revision"],
                "provenance_sha256": predicate["provenance_sha256"],
                "producer_receipt_sha256": predicate["producer_receipt_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())