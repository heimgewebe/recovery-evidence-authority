# recovery-evidence-authority

Independent, fail-closed GitHub-hosted attestation authority for the Heim-PC NixOS pre-cutover recovery contract.

This repository contains **no recovery secrets, raw backups, LUKS keys, private device identities, or production authorization**. It validates redacted, source-bound recovery provenance plus a digest-bound producer receipt against producer-specific schemas, requires that the exact producer-receipt bytes carry a valid OpenSSH sshsig from the pinned heimberry recovery-producer key, verifies that the exact Heim-PC source revision is current `main`, verifies that the supplied recovery contract is provisioned to this exact authority commit, and only then emits a GitHub Artifact Attestation for the exact provenance bytes.

The consumer is `heimgewebe/heim-pc/scripts/nixos_pre_cutover_readiness.py`.

## Trust boundary

The workflow rejects:

- self-hosted execution (the consumer verifies `--deny-self-hosted-runners`);
- same-repository signing by `heimgewebe/heim-pc`;
- unprovisioned or drifted recovery contracts;
- provenance not bound to current `heim-pc/main`;
- producer/evidence-schema mismatches;
- producer receipts whose bytes do not match the digest embedded in the provenance;\n- producer receipts without a valid `heim-pc-recovery-evidence` sshsig from the pinned heimberry key;
- producer-specific facts that fail the fail-closed schema;
- restore-test evidence whose signed base producer receipt, base receipt digest, or material-binding digest does not identify the same recovery material;
- stale/future evidence outside the recovery contract freshness window;
- any object claiming `production_effects_authorized=true`.

Attestation never grants cutover authority by itself. The Heim-PC pre-cutover readiness validator still requires the complete seven-evidence receipt set and revalidates it immediately before the first storage mutation.
The pinned public key is non-secret. Its private counterpart remains on heimberry and is never accepted as workflow input, repository content, or attestation material.