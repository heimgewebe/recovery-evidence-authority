#!/usr/bin/env python3
"""Dependency-free security self-test for the recovery evidence authority."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import validator

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


def make_receipt(evidence_id, schema, facts, contract_sha, observed_at):
    return {
        "schema_version": 1,
        "kind": validator.RECEIPT_KIND,
        "producer": validator.producer_for(evidence_id),
        "evidence_id": evidence_id,
        "evidence_scope": validator.EXPECTED_REQUIREMENTS[evidence_id][0],
        "evidence_schema": schema,
        "source_revision": HEIM_REV,
        "recovery_contract_sha256": contract_sha,
        "observed_at": observed_at,
        "result": "passed",
        "facts": facts,
        "production_effects_authorized": False,
    }


def provenance(evidence_id, restore, facts, receipt_bytes, contract_sha, observed_at):
    schema = validator.evidence_schema_for(evidence_id, restore)
    return {
        "schema_version": 1,
        "kind": (
            "heim_pc.nixos_recovery_restore_test_provenance"
            if restore
            else "heim_pc.nixos_recovery_evidence_provenance"
        ),
        "evidence_id": evidence_id,
        "evidence_scope": validator.EXPECTED_REQUIREMENTS[evidence_id][0],
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


def secret_pair(restore=False):
    c = contract()
    cb = (json.dumps(c, sort_keys=True) + "\n").encode()
    csha = hashlib.sha256(cb).hexdigest()
    identity = {"recovery_material_sha256": "a" * 64, "recovery_material_size": 65}
    base_facts = {
        "offline": True,
        "secret_bytes_exposed": False,
        **identity,
        "production_system_disk_required": False,
        "material_binding_sha256": validator.sha256_json(identity),
    }
    base = make_receipt(
        "offline-secret-recovery",
        validator.evidence_schema_for("offline-secret-recovery", False),
        base_facts,
        csha,
        "2026-09-28T03:50:00Z",
    )
    base_bytes = (json.dumps(base, sort_keys=True) + "\n").encode()
    if not restore:
        p = provenance(
            "offline-secret-recovery",
            False,
            base_facts,
            base_bytes,
            csha,
            "2026-09-28T03:50:00Z",
        )
        return c, cb, base, base_bytes, p, (json.dumps(p, sort_keys=True) + "\n").encode(), None, None

    restore_facts = {
        "offline": True,
        "recovery_test_passed": True,
        "secret_bytes_exposed": False,
        "network_required": False,
        "production_system_disk_required": False,
        **identity,
        "material_binding_sha256": base_facts["material_binding_sha256"],
        "base_producer_receipt_sha256": hashlib.sha256(base_bytes).hexdigest(),
    }
    receipt = make_receipt(
        "offline-secret-recovery",
        validator.evidence_schema_for("offline-secret-recovery", True),
        restore_facts,
        csha,
        "2026-09-28T03:55:00Z",
    )
    rb = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    p = provenance(
        "offline-secret-recovery",
        True,
        restore_facts,
        rb,
        csha,
        "2026-09-28T03:55:00Z",
    )
    return c, cb, receipt, rb, p, (json.dumps(p, sort_keys=True) + "\n").encode(), base, base_bytes


class SecuritySelfTest(unittest.TestCase):
    def test_base_evidence_valid(self):
        c, cb, r, rb, p, pb, _, _ = secret_pair(False)
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            now=NOW,
        )

    def test_restore_is_bound_to_same_signed_material(self):
        c, cb, r, rb, p, pb, br, brb = secret_pair(True)
        validator.validate_subject(
            p, pb, r, rb, c, cb,
            authority_revision=AUTH_REV,
            expected_heim_pc_revision=HEIM_REV,
            base_receipt=br,
            base_receipt_bytes=brb,
            now=NOW,
        )

    def test_restore_rejects_rebound_different_material(self):
        c, cb, r, rb, p, pb, br, _ = secret_pair(True)
        br["facts"]["recovery_material_sha256"] = "d" * 64
        identity = {
            "recovery_material_sha256": br["facts"]["recovery_material_sha256"],
            "recovery_material_size": br["facts"]["recovery_material_size"],
        }
        br["facts"]["material_binding_sha256"] = validator.sha256_json(identity)
        brb = (json.dumps(br, sort_keys=True) + "\n").encode()
        r["facts"]["base_producer_receipt_sha256"] = hashlib.sha256(brb).hexdigest()
        rb = (json.dumps(r, sort_keys=True) + "\n").encode()
        p["evidence"]["producer_receipt_sha256"] = hashlib.sha256(rb).hexdigest()
        p["evidence"]["facts"] = r["facts"]
        pb = (json.dumps(p, sort_keys=True) + "\n").encode()
        with self.assertRaisesRegex(validator.ValidationError, "material binding differs"):
            validator.validate_subject(
                p, pb, r, rb, c, cb,
                authority_revision=AUTH_REV,
                expected_heim_pc_revision=HEIM_REV,
                base_receipt=br,
                base_receipt_bytes=brb,
                now=NOW,
            )

    def test_bool_integer_coercion_is_rejected(self):
        c, cb, r, rb, p, _, _, _ = secret_pair(False)
        p["evidence"]["facts"]["offline"] = 1
        pb = (json.dumps(p, sort_keys=True) + "\n").encode()
        with self.assertRaises(validator.ValidationError):
            validator.validate_subject(
                p, pb, r, rb, c, cb,
                authority_revision=AUTH_REV,
                expected_heim_pc_revision=HEIM_REV,
                now=NOW,
            )

    def test_signature_verifier_binds_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sig = root / "receipt.sig"
            allowed = root / "allowed_signers"
            sig.write_text("fixture-signature\n")
            allowed.write_text(
                "heimberry-recovery-producer ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIHW1P0IHun3CCzTA+ihKV2aExfpuoSt5s2Qo6v2yflpd\n"
            )
            observed = {}

            def fake_run(argv, **kwargs):
                observed["input"] = kwargs["input"]
                return validator.subprocess.CompletedProcess(argv, 0, b"Good signature\n", b"")

            with patch.object(validator.subprocess, "run", side_effect=fake_run):
                validator.verify_producer_signature(b"exact-receipt\n", sig, allowed)
            self.assertEqual(b"exact-receipt\n", observed["input"])


    def test_signed_json_parser_rejects_duplicate_members_and_nonstandard_values(self):
        cases = (
            b'{"evidence":{"status":"passed","status":"denied"}}',
            b'{"facts":{"offline":true,"offl\\u0069ne":false}}',
            b'{"facts":{"time":NaN}}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "signed-receipt.json"
            for payload in cases:
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    with self.assertRaisesRegex(
                        validator.ValidationError, "duplicate|non-standard"
                    ):
                        validator.load_json_bytes(path, "producer receipt")


    def test_real_sshsig_rejects_tampering_and_unpinned_signer(self):
        """Real OpenSSH primitive; ephemeral fixture key is NOT the heimberry key."""
        import subprocess

        receipt = b'{"kind":"synthetic-unsigned-recovery-fixture","result":"passed"}\n'
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        with tempfile.TemporaryDirectory(prefix="recovery-sshsig-ci-") as scratch:
            root = Path(scratch)
            private_key = root / "ephemeral-test-only"
            signature = root / "receipt.sig"
            test_signers = root / "test-allowed-signers"
            fake_signers = root / "incorrect-principal"
            subprocess.run(
                [
                    validator.SSH_KEYGEN, "-q", "-t", "ed25519",
                    "-N", "", "-f", str(private_key),
                ],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, env=env,
            )
            public_key = private_key.with_suffix(".pub").read_text(
                encoding="ascii"
            ).strip()
            test_signers.write_text(
                validator.PRODUCER_SIGNER_IDENTITY + " " + public_key + "\n",
                encoding="ascii",
            )
            fake_signers.write_text(
                "unapproved-recovery-producer " + public_key + "\n",
                encoding="ascii",
            )

            def sign(namespace):
                completed = subprocess.run(
                    [
                        validator.SSH_KEYGEN, "-Y", "sign", "-f",
                        str(private_key), "-n", namespace,
                    ],
                    input=receipt, check=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=15, env=env,
                )
                signature.write_bytes(completed.stdout)
                self.assertTrue(
                    completed.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----")
                )

            sign(validator.PRODUCER_SIGNATURE_NAMESPACE)
            observed = validator.verify_producer_signature(
                receipt, signature, test_signers
            )
            self.assertEqual(
                hashlib.sha256(signature.read_bytes()).hexdigest(),
                observed["producer_signature_sha256"],
            )
            with self.assertRaisesRegex(
                validator.ValidationError, "signature verification failed"
            ):
                validator.verify_producer_signature(
                    receipt.replace(b'"passed"', b'"denied"'),
                    signature, test_signers,
                )
            with self.assertRaises(validator.ValidationError):
                validator.verify_producer_signature(
                    receipt + b" ", signature, test_signers
                )
            with self.assertRaises(validator.ValidationError):
                validator.verify_producer_signature(
                    receipt, signature, fake_signers
                )

            pinned = Path(__file__).resolve().parent / "keys" / "allowed_signers"
            # Independent, reviewed production PUBLIC-key anchor. A missing,
            # truncated or rotated key must fail the CI gate *before* we
            # interpret the ephemeral-signature mismatch as successful denial.
            # Key rotation requires an explicit reviewed update of this hash.
            self.assertEqual(
                hashlib.sha256(pinned.read_bytes()).hexdigest(),
                "41ba9ae93d08b0d0a6ab037aa51ea4257cdcea6eedac310becee0c06832cc493",
                "production allowed-signers public key identity drifted",
            )
            with self.assertRaisesRegex(
                validator.ValidationError, "signature verification failed"
            ):
                validator.verify_producer_signature(receipt, signature, pinned)

            sign("unauthorized-recovery-domain")
            with self.assertRaises(validator.ValidationError):
                validator.verify_producer_signature(
                    receipt, signature, test_signers
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
