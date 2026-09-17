# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A review-first pipeline for migrating Kafka authorization rules to RBAC RoleBindings, with pluggable sources (Confluent Cloud ACLs, Apache Ranger Kafka-service policies) and pluggable targets (Confluent Cloud IAM v2, Confluent Platform via MDS). No build system, no test suite, no package manifest — just standalone Python scripts plus PyYAML as the sole dependency, with two small local packages (`common/`, `targets/`) holding the abstractions shared across sources/targets.

## Commands

```bash
python3 -m pip install -r requirements.txt   # only dependency: PyYAML

# 1a. Export ACLs from a cluster's Kafka REST endpoint
python3 export_cc_acls.py --cluster-id lkc-123456 \
  --rest-base-url 'https://pkc-xxxxx.eu-central-1.aws.confluent.cloud' \
  --output acls.yaml

# 1b. Or: flatten a local Apache Ranger Kafka-service policy export instead
python3 export_ranger_policies.py --input-file ranger-kafka-policies.json \
  --cluster-id lkc-123456 --output acls.yaml

# 2. Convert to reviewable RoleBinding YAML for a target (never mutates anything remote)
#    --target cc (default) = Confluent Cloud IAM v2; --target cp-mds = Confluent Platform via MDS
python3 acl_to_rolebindings.py acls.yaml \
  --organization-id <org-id> --environment-id <env-id> --output rolebindings.yaml

# 3a. Dry-run (default) then apply against IAM v2 (--target cc bindings)
python3 apply_rolebindings.py rolebindings.yaml
python3 apply_rolebindings.py rolebindings.yaml --apply --continue-on-error

# 3b. Or: dry-run then apply against MDS (--target cp-mds bindings)
python3 apply_to_mds.py rolebindings.yaml
python3 apply_to_mds.py rolebindings.yaml --apply --continue-on-error
```

Credentials are read from environment variables, never CLI args:
- CC target: `CC_API_KEY` / `CC_API_SECRET` (or the per-script overrides `CC_KAFKA_API_KEY`/`CC_KAFKA_API_SECRET` for export, `CC_IAM_API_KEY`/`CC_IAM_API_SECRET` for apply), or `CC_ACCESS_TOKEN` as a bearer token, which takes precedence when set.
- CP/MDS target: `MDS_ACCESS_TOKEN` as a bearer token, or `MDS_USERNAME`/`MDS_PASSWORD` (used to log in against MDS's `/security/1.0/authenticate`), which takes precedence when the token is unset.

Cluster/org identifiers also fall back to environment variables when the matching flag is omitted (the flag still wins if both are given): `--cluster-id`/`CC_CLUSTER_ID` and `--rest-base-url`/`CC_REST_BASE_URL` for `export_cc_acls.py`; `--cluster-id`/`RANGER_KAFKA_CLUSTER_ID` for `export_ranger_policies.py`; `--organization-id`/`CC_ORGANIZATION_ID`, `--environment-id`/`CC_ENVIRONMENT_ID`, and the optional `--kafka-cluster-id`/`CC_KAFKA_CLUSTER_ID` for `acl_to_rolebindings.py --target cc`; `--kafka-cluster-id`/`CP_KAFKA_CLUSTER_ID` for `acl_to_rolebindings.py --target cp-mds`; `--mds-url`/`MDS_URL` for `apply_to_mds.py`. Each script exits with a clear error if a required value has neither a flag nor an env var.

`.env.example` documents every one of these variables (credentials and cluster/org config). Copy it to `.env`, fill it in, and `set -a; source .env; set +a` before running the scripts — `.env` itself is gitignored and must never be committed.

There is no test suite, linter, or CI config in this repo — there is nothing to run beyond the scripts themselves. There's also no live-Ranger integration: `export_ranger_policies.py` only reads a local policy export JSON file.

## Architecture: pluggable sources and targets joined by a canonical YAML schema

The pipeline has three conceptual stages, but the middle one is now parameterized by target rather than being a single script tied to Confluent Cloud:

1. **Export (source-specific, standalone).** `export_cc_acls.py` GETs `/kafka/v3/clusters/{cluster_id}/acls` from the cluster's Kafka REST endpoint (not the IAM API host); `export_ranger_policies.py` reads a local Ranger Kafka-service policy export JSON and flattens `policyItems`/`denyPolicyItems` × `accesses` × resource values. **Both write the exact same canonical `{api_version, kind, metadata, data}` YAML**, where each `data` record has `{resource_type, resource_name, pattern_type, principal, host, operation, permission}` (plus passthrough `cluster_id`). There is still zero shared code *between* exporters — each is fully self-contained — because the canonical schema, not a Python API, is the interface. `export_cc_acls.py` additionally makes a *second* request filtered to `UserV2:*` and merges it with the unfiltered result by default, because the ACL API only returns RBAC-friendly `sa-xxx`-style principals when explicitly queried that way; numeric legacy principals are swapped for their normalized equivalents when the counts match for a given ACL key (see `acl_key_without_principal`). `--legacy-principals` skips this merge.

2. **Transform (target-parameterized, no network calls).** `acl_to_rolebindings.py` reads the canonical YAML, runs every record through `common/invariants.py` (the single, target-agnostic filter/grouping engine — DENY skip, ALLOW-only, wildcard-host-only, LITERAL/PREFIXED-only, wildcard-principal skip, CLUSTER-requires-explicit-role), then hands each surviving record to the module selected by `--target` (`targets/cc_rbac.py` for `cc`, the default; `targets/cp_mds.py` for `cp-mds`) for role-name and locator translation, and writes `{api_version, kind, metadata, data}` RoleBinding YAML. Role-name decisions (READ→DeveloperRead, etc. — see `README.md`) live in `common/role_table.py`, shared by both targets since CP and CC RBAC ship the same predefined role names; a target with different role names should get its own table instead. Every record that is skipped or only approximately translated is recorded as a string in `metadata.warnings` — this is the primary review surface before anything is applied. Bindings for the same `(principal, role_name, locator)` are grouped together with their contributing source records kept for audit (`source_acls`), but only `principal`/`role_name`/locator fields are ever sent to an apply script.

3. **Apply (target-specific, one script per target).** `apply_rolebindings.py` POSTs each `--target cc` binding's `{principal, role_name, crn_pattern}` to `https://api.confluent.cloud/iam/v2/role-bindings`; `apply_to_mds.py` POSTs each `--target cp-mds` binding to one of *two* MDS endpoints depending on whether it's cluster-scoped or resource-scoped: `POST {mds_url}/security/1.0/principals/{principal}/roles/{role}` with a bare `{"clusters": {...}}` body for a `CLUSTER` ACL, or `POST .../roles/{role}/bindings` with `{"scope", "resourcePatterns"}` for everything else — this has been run against a real, live CP broker with RBAC/MDS enabled (`docker-rbac/`), not just checked against docs. Both apply scripts share `common/apply_shell.py` for the generic dry-run/retry/backoff/`--continue-on-error`/results-log shell (dry-run is the default; `--apply` is required to actually POST; retries with backoff on 429/5xx honoring `Retry-After`); only the per-target payload shape, auth, and endpoint construction live in `targets/*.py`. `common/principals.py` holds the `UserV2:`→`User:` principal normalization every target needs (a real bug — an unnormalized `UserV2:` principal leaking through to the MDS target — was only caught by testing against `mock_server.py`, which is why that script exists: `export_cc_acls.py`'s output is the one place `UserV2:` principals can appear, and nothing downstream should ever see that prefix).

`mock_server.py` is a stdlib-only local mock of all three real APIs (Kafka v3 ACLs, IAM v2 role-bindings, MDS RBAC) for exercising the actual network/auth/retry code — not just dry-run — without a live cluster or MDS broker. Its docstring documents the canned dataset and the `TriggerRateLimit`/`TriggerServerError` role-name sentinels for forcing the retry path.

`docker-rbac/` is the step beyond that mock: a Docker Compose file that actually boots a minimal, real Confluent Platform broker with RBAC and MDS enabled (single-node KRaft, FILE-based MDS user store instead of LDAP, a locally-generated token-signing keypair, no TLS), and `docker-rbac/test_rbac.sh` runs *both* sources — `examples/cc-acls.yaml` directly, and `examples/ranger-kafka-policies.json` via `export_ranger_policies.py` first — through the real `acl_to_rolebindings.py --target cp-mds` → `apply_to_mds.py --apply` pipeline against it. This is what actually confirmed `targets/cp_mds.py`'s two-endpoint split works for both sources, not just that it matches the docs. Two non-obvious gotchas documented in `docker-rbac/README.md`: the FILE user store parser rejects `#` comment lines (so `login.properties` has none), and MDS 400s a cluster-scoped bind for a role like `ResourceOwner` that actually needs resources (`"Resources must be specified for role ResourceOwner"`) — that's the server validating correctly, not a bug in this repo.

Adding a new source is one new `export_*.py` emitting the canonical schema — nothing else changes. Adding a new target is one new `targets/*.py` implementing the interface used by `cc_rbac.py`/`cp_mds.py`, a registry entry in `targets/__init__.py`, and (if the wire format differs) a thin `apply_to_*.py` — the invariant engine and apply shell never need to change.

## Design invariants to preserve

These are deliberate safety properties of the current design, enforced once in `common/invariants.py` regardless of source or target — don't casually relax them:

- **Nothing here deletes anything.** No script removes ACLs, Ranger policies, RoleBindings, or other resources. Source rules and RBAC are meant to coexist during migration.
- **`DENY` records are never translated.** RBAC bindings are allow-only; a deny (a Kafka ACL `DENY`, or a Ranger `denyPolicyItems` entry) has no RBAC representation and is always skipped with a warning, never silently dropped.
- **Only `LITERAL` and `PREFIXED` resource patterns are translated**; anything else (e.g. `MATCH`) is skipped and warned about rather than guessed.
- **Only wildcard-host (`*`) records are translated** — RBAC bindings can't carry a host restriction, so a non-`*` host is skipped rather than silently widened. (Ranger has no host concept, so every Ranger-sourced record is host `*` by construction.)
- **`CLUSTER` records are skipped unless `--cluster-role` is explicitly passed** — cluster-level RBAC mapping is not guessed by default because it risks granting much broader access than the source rule.
- **Broad-approximation roles (`ALTER`/`ALTER_CONFIGS`/`ALL`/`ANY` → `ResourceOwner` by default) always emit a warning**, even though they're representable, because the role is intentionally broader than the source rule's actual permission.
- **`export_ranger_policies.py` skips an entire policy, not just the exception, when it has `allowExceptions`/`denyExceptions`** — silently ignoring an exception would widen access relative to what Ranger actually grants, which is the same class of mistake as dropping a `DENY`.
- Every skip or lossy/approximate mapping goes into `metadata.warnings` in the RoleBinding YAML (or, for `export_ranger_policies.py`'s own skips, its output YAML's `metadata.warnings`) — this is the thing a human is expected to read before running `apply_rolebindings.py --apply` or `apply_to_mds.py --apply`.

See `README.md` for the full ACL→role and Ranger-accessType→operation translation tables, the CP/MDS wire-format caveat, and the (intentionally manual/non-automated) reverse RoleBinding→ACL direction.
