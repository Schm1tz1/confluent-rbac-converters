#!/usr/bin/env python3
"""Export Apache Ranger Kafka-service policies to the canonical ACL-record YAML.

Reads a local Ranger policy export JSON file (either a bare list of policy
objects, or an object with a "policies" key holding that list -- both shapes
occur across Ranger's "Export JSON" admin action and its plugin-download
policy endpoint) and flattens each policy's resources x policyItems x
accesses into the same {resource_type, resource_name, pattern_type,
principal, host, operation, permission} record schema that export_cc_acls.py
produces. acl_to_rolebindings.py therefore needs zero Ranger-specific code:
every design invariant (DENY skip, LITERAL/PREFIXED-only, etc.) and every
target's role/locator mapping applies identically regardless of source.

Ranger's accessType vocabulary and per-resource-type restrictions are taken
from Apache Ranger's own kafka service definition (ranger-servicedef-kafka.json):
https://github.com/apache/ranger/blob/master/agents-common/src/main/resources/service-defs/ranger-servicedef-kafka.json

This only reads a local file -- it does not call the Ranger Admin REST API.

Requires: PyYAML (pip install -r requirements.txt)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

import yaml


RESOURCE_TYPE_MAP = {
    "topic": "TOPIC",
    "cluster": "CLUSTER",
    "consumergroup": "GROUP",
    "transactionalid": "TRANSACTIONAL_ID",
    # DELEGATION_TOKEN has no RBAC translation (not in any target's
    # RESOURCE_SEGMENTS), so acl_to_rolebindings.py always skips+warns on it;
    # it's listed explicitly here only so that warning names the same
    # resource_type value Confluent's own ACL API uses.
    "delegationtoken": "DELEGATION_TOKEN",
}

# publish/consume/describe/create/delete/describe_configs/alter_configs/alter
# map onto their Kafka-ACL-operation namesakes. configure/kafka_admin/
# cluster_action/idempotent_write have no exact Kafka ACL equivalent and are
# approximated (see README.md's Ranger accessType table for the rationale).
ACCESS_TYPE_TO_OPERATION = {
    "publish": "WRITE",
    "consume": "READ",
    "describe": "DESCRIBE",
    "create": "CREATE",
    "delete": "DELETE",
    "describe_configs": "DESCRIBE_CONFIGS",
    "alter_configs": "ALTER_CONFIGS",
    "alter": "ALTER",
    "configure": "ALTER_CONFIGS",
    "kafka_admin": "ALL",
    "cluster_action": "ALL",
    "idempotent_write": "WRITE",
}


def canonical_resource_type(ranger_type: str) -> str:
    return RESOURCE_TYPE_MAP.get(ranger_type, ranger_type.upper())


def resource_name_and_pattern(value: str) -> tuple[str, str]:
    if value != "*" and value.endswith("*"):
        return value[:-1], "PREFIXED"
    return value, "LITERAL"


def principals_for(item: dict, warnings: list[str], policy_name: str) -> list[str]:
    principals = [f"User:{name}" for name in item.get("users", [])]
    principals += [f"Group:{name}" for name in item.get("groups", [])]
    if item.get("roles"):
        warnings.append(
            f"policy {policy_name!r}: policyItem roles {item['roles']!r} are a Ranger-role indirection "
            "with no direct RBAC equivalent; skipped (expand to users/groups in Ranger first if needed)"
        )
    return principals


def records_for_policy(policy: dict, cluster_id: str, warnings: list[str]) -> list[dict]:
    name = policy.get("name", "<unnamed policy>")
    if not policy.get("isEnabled", True):
        return []
    if policy.get("allowExceptions") or policy.get("denyExceptions"):
        warnings.append(
            f"policy {name!r}: allowExceptions/denyExceptions are not modeled (they could narrow a grant "
            "in a way an RBAC binding cannot represent, which would widen access); the entire policy was "
            "skipped for safety"
        )
        return []

    records: list[dict] = []
    for ranger_type, spec in policy.get("resources", {}).items():
        resource_type = canonical_resource_type(ranger_type)
        values = spec.get("values", [])
        for permission, items in (("ALLOW", policy.get("policyItems", [])), ("DENY", policy.get("denyPolicyItems", []))):
            for item in items:
                principals = principals_for(item, warnings, name)
                for access in item.get("accesses", []):
                    if not access.get("isAllowed", True):
                        continue
                    access_type = access.get("type")
                    operation = ACCESS_TYPE_TO_OPERATION.get(access_type)
                    if operation is None:
                        warnings.append(
                            f"policy {name!r}: Ranger accessType {access_type!r} has no configured operation mapping; skipped"
                        )
                        continue
                    for value in values:
                        resource_name, pattern_type = resource_name_and_pattern(value)
                        for principal in principals:
                            records.append({
                                "cluster_id": cluster_id,
                                "resource_type": resource_type,
                                "resource_name": resource_name,
                                "pattern_type": pattern_type,
                                "principal": principal,
                                "host": "*",
                                "operation": operation,
                                "permission": permission,
                            })
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-file", required=True,
        help="Local Ranger policy export JSON (Ranger Admin's 'Export JSON' action, or "
             "GET /service/plugins/policies/exportJson saved to a file)",
    )
    parser.add_argument(
        "--cluster-id", default=os.getenv("RANGER_KAFKA_CLUSTER_ID"),
        help="Kafka cluster ID to record for downstream --kafka-cluster-id fallback (env: RANGER_KAFKA_CLUSTER_ID)",
    )
    parser.add_argument("-o", "--output", default="acls.yaml")
    args = parser.parse_args()
    if not args.cluster_id:
        raise SystemExit("Set --cluster-id or RANGER_KAFKA_CLUSTER_ID")

    with open(args.input_file, encoding="utf-8") as handle:
        payload = json.load(handle)
    policies = payload.get("policies", payload) if isinstance(payload, dict) else payload
    if not isinstance(policies, list):
        raise SystemExit("Unexpected Ranger export shape: expected a JSON list or an object with a 'policies' list")

    warnings: list[str] = []
    records: list[dict] = []
    for policy in policies:
        records.extend(records_for_policy(policy, args.cluster_id, warnings))

    document = {
        "api_version": "ranger/kafka-policies",
        "kind": "KafkaAclList",
        "metadata": {
            "cluster_id": args.cluster_id,
            "source_file": args.input_file,
            "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "count": len(records),
            "warning_count": len(warnings),
            "warnings": warnings,
        },
        "data": records,
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=True)

    for warning in warnings:
        print(f"WARNING: {warning}")
    print(json.dumps({"output": args.output, "record_count": len(records), "warning_count": len(warnings)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
