"""Kafka-operation -> RBAC role-name decision table.

Shared by every RBAC target. Confluent Cloud IAM v2 and Confluent Platform
RBAC (via MDS) both ship predefined roles under these same names
(DeveloperRead/DeveloperWrite/DeveloperManage, ResourceOwner, ...), so both
targets/cc_rbac.py and targets/cp_mds.py delegate here rather than each
keeping their own copy. If a future target's role names diverge from this
table, give it its own roles_for() instead of importing this one -- don't
bend this table to fit it.
"""
from __future__ import annotations


def roles_for(
    record: dict, resource_segments: dict[str, str], alter_role: str, all_role: str
) -> tuple[list[str], str | None]:
    resource_type = record.get("resource_type")
    operation = record.get("operation")
    if resource_type not in resource_segments:
        return [], f"resource_type {resource_type!r} has no granular Kafka RBAC translation"
    if operation == "READ":
        return ["DeveloperRead"], None
    if operation == "DESCRIBE":
        return ["DeveloperRead"], "DESCRIBE is approximated by DeveloperRead and therefore also grants read access"
    if operation == "WRITE":
        return ["DeveloperWrite"], None
    if operation in {"CREATE", "DELETE"}:
        return ["DeveloperManage"], None
    if operation == "DESCRIBE_CONFIGS":
        return ["DeveloperManage"], "DESCRIBE_CONFIGS is approximated by DeveloperManage and therefore also grants lifecycle permissions"
    if operation in {"ALTER", "ALTER_CONFIGS"}:
        return [alter_role], f"{operation} requires broader {alter_role} semantics; review least privilege"
    if operation in {"ALL", "ANY"}:
        return [all_role], f"{operation} expands to broad {all_role} access"
    return [], f"operation {operation!r} has no configured granular RBAC translation"
