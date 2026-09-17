# Confluent Cloud ACL → RBAC migration overview

This package is a conservative, review-first migration path:

1. Export Kafka ACLs (or Apache Ranger Kafka-service policies) to a canonical YAML record schema.
2. Convert representable `ALLOW` records to RoleBinding payloads for a chosen RBAC target.
3. Review warnings and submit the RoleBindings through that target's API.

It does not delete ACLs or Ranger policies. Keep the source rules in place until access has been tested and the generated bindings have been reviewed.

### Sources and targets

| | Confluent Cloud ACLs | Apache Ranger Kafka-service policies |
|---|---|---|
| Exporter | `export_cc_acls.py` | `export_ranger_policies.py` |

Both exporters write the same canonical ACL-record schema (`resource_type`, `resource_name`, `pattern_type`, `principal`, `host`, `operation`, `permission`), so `acl_to_rolebindings.py` has no source-specific code at all.

| | Confluent Cloud IAM v2 (`--target cc`, default) | Confluent Platform via MDS (`--target cp-mds`) |
|---|---|---|
| Transform | `acl_to_rolebindings.py --target cc` | `acl_to_rolebindings.py --target cp-mds` |
| Apply | `apply_rolebindings.py` | `apply_to_mds.py` |
| Locator | `crn_pattern` string | `scope` + `resource_patterns` |

**The CP/MDS target's wire format (`targets/cp_mds.py`) has been verified against a real, live Confluent Platform broker with RBAC/MDS enabled** — see `docker-rbac/` — not just against Confluent's docs and `mock_server.py`. MDS distinguishes a cluster-scoped bind (`POST .../roles/{role}`, plain `{"clusters": {...}}` body) from a resource-scoped bind (`POST .../roles/{role}/bindings`, `{"scope", "resourcePatterns"}` body), and `targets/cp_mds.py` picks the right one per binding; `docker-rbac/test_rbac.sh` runs both `examples/cc-acls.yaml` and `examples/ranger-kafka-policies.json` (via `export_ranger_policies.py`) through both paths against a real broker, so both sources are covered, not just the CC one -- and then reads every binding back via MDS's own lookup endpoints (`docker-rbac/verify_bindings.py`), rather than trusting `apply_to_mds.py`'s 204 status codes alone. That broker is single-node with a FILE user store and no TLS, though, so it confirms the wire format, not every property of your actual production-shaped MDS deployment (LDAP, mTLS, multiple brokers) — verify those against your own environment before `--apply`. The role-name assumption (CP RBAC's predefined roles matching Confluent Cloud's, via the shared `common/role_table.py`) is unaffected by this and still worth double-checking against your CP version.

## The important distinction

An ACL is a Kafka data-plane rule: principal + Kafka resource + operation + permission + host + pattern. Confluent Cloud RBAC is a binding of a principal to a predefined role on a Confluent Resource Name (CRN) pattern. RBAC roles are bundles of permissions, so the conversion is not lossless.

ACLs and RBAC can coexist. An applicable ACL `DENY` is evaluated first and overrides both ACL `ALLOW` rules and RBAC role bindings. An RBAC binding therefore cannot be used to “override” a deny ACL.

## ACL → RoleBinding translation policy

| ACL | Generated role binding | Notes |
|---|---|---|
| `ALLOW READ` on `TOPIC` | `DeveloperRead` on `.../topic=<name>` | Grants read-oriented access; it may include the describe permission required by the role. |
| `ALLOW WRITE` on `TOPIC` | `DeveloperWrite` on `.../topic=<name>` | Grants write-oriented access; it is broader than one raw Kafka API permission. |
| `ALLOW READ` or `DESCRIBE` on `GROUP` | `DeveloperRead` on `.../group=<name>` | Required for consuming with a consumer group. |
| `ALLOW READ`/`WRITE` on `TRANSACTIONAL_ID` | `DeveloperRead`/`DeveloperWrite` | Preserves the resource pattern, but the role’s bundled permissions still apply. |
| `ALLOW CREATE`, `DELETE`, or `DESCRIBE_CONFIGS` | `DeveloperManage` | This is an operational approximation, not a raw operation mapping. |
| `ALLOW ALTER` or `ALTER_CONFIGS` | `ResourceOwner` by default | Deliberately broad because the granular developer roles do not provide configuration alteration. Review and replace with a narrower design if available. |
| `ALLOW ALL` or `ANY` | `ResourceOwner` by default | Broad approximation; emitted with a warning. |
| `DENY` | Nothing | Skipped and reported. Keep the ACL if the deny is intentional. |
| Host other than `*` | Nothing | RBAC bindings do not carry the ACL host restriction. |
| `MATCH`, wildcard principal, malformed/unknown resource | Nothing | Skipped and reported for manual review. |

Resource patterns are represented as follows:

* `LITERAL` → the exact CRN resource name.
* `PREFIXED` → the CRN resource name with a trailing `*`.
* A literal resource name of `*` remains a wildcard CRN pattern.

The converter skips `CLUSTER` ACLs unless you explicitly provide `--cluster-role`; cluster-level mapping is intentionally not guessed because it can produce much broader access than the original Kafka ACL.

## Apache Ranger Kafka-service policy → canonical record

`export_ranger_policies.py` flattens Ranger's `policyItems`/`denyPolicyItems` × `accesses` × resource values into the same canonical record schema `export_cc_acls.py` produces. Ranger accessTypes (per [Apache Ranger's kafka service definition](https://github.com/apache/ranger/blob/master/agents-common/src/main/resources/service-defs/ranger-servicedef-kafka.json)) map onto Kafka ACL operations as follows:

| Ranger accessType | Canonical operation | Notes |
|---|---|---|
| `publish` | `WRITE` | |
| `consume` | `READ` | |
| `describe` | `DESCRIBE` | |
| `create` | `CREATE` | |
| `delete` | `DELETE` | |
| `describe_configs` | `DESCRIBE_CONFIGS` | |
| `alter_configs` | `ALTER_CONFIGS` | |
| `alter` | `ALTER` | |
| `configure` | `ALTER_CONFIGS` | Approximation: Ranger's `configure` (topic/cluster config management) has no exact Kafka ACL counterpart. |
| `kafka_admin` | `ALL` | Broad; only valid on the `cluster` resource in Ranger. |
| `cluster_action` | `ALL` | Broad; only valid on the `cluster` resource in Ranger. |
| `idempotent_write` | `WRITE` | Approximation: idempotent-producer capability, only valid on the `cluster` resource in Ranger. |

Ranger resource types map onto the same canonical `resource_type` values ACLs use: `topic`→`TOPIC`, `cluster`→`CLUSTER`, `consumergroup`→`GROUP`, `transactionalid`→`TRANSACTIONAL_ID`. `delegationtoken` and anything else pass through unmapped and get skipped with a warning by `acl_to_rolebindings.py`, the same as any other unrecognized `resource_type`.

A Ranger resource value that ends in `*` (e.g. `orders.*`) becomes `pattern_type: PREFIXED` with the `*` stripped; anything else becomes `LITERAL` (including a bare `*`, which stays a wildcard resource name — same convention as ACLs). `denyPolicyItems` become `permission: DENY` records, which `acl_to_rolebindings.py` then skips exactly like a Kafka ACL `DENY` — never silently dropped, always in `metadata.warnings`.

Two Ranger constructs are **not** translated at all, and skip the entire containing policy for safety rather than approximate it:

* A `policyItem` granting access via `roles` (a Ranger-role indirection over users/groups) instead of listing `users`/`groups` directly — resolving it would require an extra Ranger API call, so it's skipped with a warning.
* A policy with non-empty `allowExceptions`/`denyExceptions` — an exception narrows a grant in a way an RBAC binding cannot represent, and ignoring it would silently widen access, so the whole policy is skipped with a warning instead.

## CLI extension points

* `acl_to_rolebindings.py --target {cc,cp-mds}` selects the RBAC flavor (default `cc`); each target module in `targets/` owns its own role/locator mapping and CLI flags, but every source-agnostic design invariant above still applies identically regardless of target.
* Adding a third source means writing one new `export_*.py` that emits the canonical record schema — no changes anywhere else.
* Adding a third target means writing one new `targets/*.py` implementing the same interface as `targets/cc_rbac.py`/`targets/cp_mds.py`, registering it in `targets/__init__.py`, and (if it needs its own wire format) a thin `apply_to_*.py` — no changes to the sources or to `common/invariants.py`.

## RoleBinding → ACL: reverse direction

There is no exact reverse conversion. A RoleBinding must first be expanded using the current definition of the role, then each granted permission can be represented as an `ALLOW` ACL where Kafka ACLs support that resource and operation.

| RoleBinding | Possible ACL expansion | Caveat |
|---|---|---|
| `DeveloperRead` on a topic | `ALLOW READ` and usually `ALLOW DESCRIBE` on that topic | The role is a permission bundle and may also require a group binding for consumption. |
| `DeveloperWrite` on a topic | `ALLOW WRITE` and usually `ALLOW DESCRIBE` | Do not infer that it grants `READ`. |
| `DeveloperManage` on a topic/group/transactional ID | Lifecycle/describe-config permissions supported by the role | It is not a 1:1 list of ACL operations. |
| `ResourceOwner` | Read/write/manage/describe-style ACLs where applicable | It also grants access-management capabilities that Kafka ACLs cannot express. |
| Any role binding | No `DENY` ACL | RBAC grants are allow-only; an ACL deny must be modeled separately. |

The reverse direction should be treated as an audit/reporting exercise rather than an automated downgrade. Role definitions can evolve, and a role can grant permissions outside the one Kafka resource being inspected.

## Prerequisites and safety model

* Python 3.10+.
* One external dependency: `PyYAML`.
* For the `cc` target: a Confluent Cloud API key/secret with permission to list ACLs and create RoleBindings, or a supported bearer token. The ACL export uses the Kafka v3 ACL endpoint on the cluster REST endpoint; RoleBinding submission uses `POST https://api.confluent.cloud/iam/v2/role-bindings`.
* For the `cp-mds` target: a local Ranger policy export JSON (no live Ranger API call is made), and MDS credentials (bearer token or username/password) with permission to create role bindings. See the wire-format caveat above.
* `apply_rolebindings.py`/`apply_to_mds.py` are dry-run by default; `--apply` is required to make changes.
* The scripts do not delete ACLs, Ranger policies, RoleBindings, topics, or any other resources.

Granular Kafka RBAC is supported only on supported cluster types; validate the target cluster before applying generated bindings.

## Runbook

Try the transform and dry-run steps against the bundled example first — no credentials or live cluster needed:

```bash
python3 -m pip install -r requirements.txt
python3 acl_to_rolebindings.py examples/cc-acls.yaml \
  --organization-id org-1 --environment-id env-1 --cluster-role ClusterAdmin \
  --output /tmp/rolebindings.yaml
python3 apply_rolebindings.py /tmp/rolebindings.yaml   # dry-run, prints without any network call
```

To exercise the real network paths -- auth header construction, the MDS login flow, and 429/5xx retry/backoff -- without touching a live cluster, run `mock_server.py` (stdlib only, no dependencies) and point the scripts at it:

```bash
python3 mock_server.py --port 8089 &

CC_API_KEY=fake CC_API_SECRET=fake python3 export_cc_acls.py \
  --cluster-id lkc-mock1 --rest-base-url http://127.0.0.1:8089 --output /tmp/acls.yaml
python3 acl_to_rolebindings.py /tmp/acls.yaml --organization-id org-1 --environment-id env-1 --output /tmp/rb.yaml
CC_API_KEY=fake CC_API_SECRET=fake python3 apply_rolebindings.py /tmp/rb.yaml \
  --apply --endpoint http://127.0.0.1:8089/iam/v2/role-bindings

# and for the MDS path:
python3 acl_to_rolebindings.py /tmp/acls.yaml --target cp-mds --kafka-cluster-id lkc-mock1 --output /tmp/rb-cp.yaml
MDS_USERNAME=fake MDS_PASSWORD=fake python3 apply_to_mds.py /tmp/rb-cp.yaml --apply --mds-url http://127.0.0.1:8089
```

`mock_server.py`'s docstring documents its canned dataset and its failure-injection sentinels (`role_name: TriggerRateLimit` / `TriggerServerError`) for forcing the retry path.

Set credentials without putting them in command history, either directly:

```bash
export CC_API_KEY='...'
export CC_API_SECRET='...'
# Or use CC_ACCESS_TOKEN='...'
python3 -m pip install -r requirements.txt
```

or via an env file (copy `.env.example` to `.env`, fill it in, never commit `.env`):

```bash
cp .env.example .env
set -a; source .env; set +a
python3 -m pip install -r requirements.txt
```

Export ACLs. Use the Kafka REST base URL for the target cluster, not the IAM API host. `--cluster-id`/`--rest-base-url` fall back to `CC_CLUSTER_ID`/`CC_REST_BASE_URL` if set (e.g. in `.env`), so you can omit them once those are exported:

```bash
python3 export_cc_acls.py \
  --cluster-id lkc-123456 \
  --rest-base-url 'https://pkc-xxxxx.eu-central-1.aws.confluent.cloud' \
  --output acls.yaml
```

If the API returns legacy numeric service-account principals and the extra normalization request is not suitable for your environment, add `--legacy-principals`. You can also use `--principal` to export a filtered subset.

Convert and inspect warnings. `--organization-id`/`--environment-id` fall back to `CC_ORGANIZATION_ID`/`CC_ENVIRONMENT_ID`, and `--kafka-cluster-id` (only needed to override the cluster_id already recorded in the ACL file) falls back to `CC_KAFKA_CLUSTER_ID`:

```bash
python3 acl_to_rolebindings.py acls.yaml \
  --organization-id 00000000-0000-0000-0000-000000000000 \
  --environment-id env-123456 \
  --output rolebindings.yaml

python3 - <<'PY'
import yaml
with open('rolebindings.yaml') as f:
    doc = yaml.safe_load(f)
for warning in doc['metadata']['warnings']:
    print('WARNING:', warning)
print('bindings:', doc['metadata']['binding_count'])
PY
```

The generated YAML contains the API fields `principal`, `role_name`, and `crn_pattern`, plus source ACLs for review. The submitter ignores the review-only fields when constructing the POST body.

Dry-run, then apply:

```bash
python3 apply_rolebindings.py rolebindings.yaml
python3 apply_rolebindings.py rolebindings.yaml --apply --continue-on-error
```

After applying, verify effective access with representative produce/consume and management tests. Do not remove the source ACLs until the tests pass and the warnings have been resolved.

### Ranger source → Confluent Platform (MDS) target

```bash
python3 export_ranger_policies.py --input-file ranger-kafka-policies.json --cluster-id onprem-cluster-1 --output acls.yaml
python3 acl_to_rolebindings.py acls.yaml --target cp-mds --kafka-cluster-id onprem-cluster-1 --output rolebindings.yaml
python3 apply_to_mds.py rolebindings.yaml
python3 apply_to_mds.py rolebindings.yaml --apply --continue-on-error
```

Any source can feed any target: `export_ranger_policies.py` → `acl_to_rolebindings.py --target cc` → `apply_rolebindings.py` works just as well, and so does `export_cc_acls.py` → `acl_to_rolebindings.py --target cp-mds` → `apply_to_mds.py`.

## Files

* `export_cc_acls.py` — retrieves Confluent Cloud ACLs and writes the canonical source YAML.
* `export_ranger_policies.py` — flattens a local Apache Ranger Kafka-service policy export JSON into the same canonical source YAML.
* `acl_to_rolebindings.py` — converts canonical YAML to reviewable RoleBinding YAML for the selected `--target`.
* `apply_rolebindings.py` — dry-runs or submits `--target cc` RoleBindings through IAM v2.
* `apply_to_mds.py` — dry-runs or submits `--target cp-mds` RoleBindings through the MDS RBAC API.
* `common/invariants.py` — the source- and target-agnostic filter/grouping engine every translation goes through.
* `common/apply_shell.py` — the target-agnostic dry-run/retry/backoff/results-log shell every apply script uses.
* `common/role_table.py` — the Kafka-operation → RBAC role-name table shared by both RBAC targets.
* `targets/cc_rbac.py`, `targets/cp_mds.py` — per-target role/locator mapping, auth, and wire format.
* `examples/ranger-kafka-policies.json` — a sample Ranger Kafka policy export (adapted from Apache Ranger's own test fixtures) covering topics, prefixed topics, consumer groups, cluster-admin, deny, Ranger-role, and exception-carveout policies, for exercising `export_ranger_policies.py`.
* `examples/cc-acls.yaml` — a sample `export_cc_acls.py`-shaped ACL export covering every branch of the translation policy (every operation, `PREFIXED`/wildcard/`MATCH` patterns, `CLUSTER`, `DENY`, non-`*` host, wildcard principal, `UserV2:*` normalization, grouping of multiple ACLs into one binding), for exercising `acl_to_rolebindings.py`/`apply_rolebindings.py`/`apply_to_mds.py` without a live cluster.
* `mock_server.py` — a stdlib-only local mock of the Kafka v3 ACL, IAM v2 role-bindings, and MDS RBAC APIs, for exercising the real network/auth/retry code paths in `export_cc_acls.py`, `apply_rolebindings.py`, and `apply_to_mds.py` without a live cluster or MDS broker.
* `docker-rbac/` — a Docker Compose setup for a minimal, real, local Confluent Platform broker with RBAC/MDS enabled (KRaft, FILE user store, no LDAP/TLS), plus `test_rbac.sh` which runs both sources (`examples/cc-acls.yaml`, and `examples/ranger-kafka-policies.json` via `export_ranger_policies.py`) through the real `--target cp-mds` pipeline against it end to end, then reads every binding back from MDS (`verify_bindings.py`) to confirm it's actually there. This is what actually verified `targets/cp_mds.py`'s wire format, beyond what `mock_server.py` alone could prove.
* `common/principals.py` — the `UserV2:` → `User:` principal normalization shared by every RBAC target.

## Sources

* [ACL overview for Confluent Cloud](https://docs.confluent.io/cloud/current/security/access-control/acls/overview.html)
* [Use ACLs with RBAC](https://docs.confluent.io/cloud/current/security/access-control/rbac/use-acls-with-rbac.html)
* [Predefined RBAC roles](https://docs.confluent.io/cloud/current/security/access-control/rbac/predefined-rbac-roles.html)
* [Manage RBAC role bindings](https://docs.confluent.io/cloud/current/security/access-control/rbac/manage-role-bindings.html)
* [List ACLs API](https://docs.confluent.io/cloud/current/ccloud/get-kafka-acls/)
* [Create Role Binding API](https://docs.confluent.io/cloud/current/ccloud/create-iam-v-2-role-binding/)
* [Apache Ranger Kafka service definition](https://github.com/apache/ranger/blob/master/agents-common/src/main/resources/service-defs/ranger-servicedef-kafka.json)
* [Apache Ranger Kafka Plugin wiki](https://cwiki.apache.org/confluence/display/RANGER/Kafka+Plugin)
* [Apache Ranger policy import/export](https://cwiki.apache.org/confluence/display/RANGER/User+Guide+For+Import-Export)
* [Confluent Platform RBAC overview](https://docs.confluent.io/platform/current/security/rbac/overview.html)
* [Confluent Platform predefined RBAC roles](https://docs.confluent.io/platform/current/security/rbac/rbac-predefined-roles.html)
