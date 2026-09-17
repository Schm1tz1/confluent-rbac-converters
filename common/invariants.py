"""Design-invariant filtering shared by every source and every target.

These checks are what any RBAC system requires to hold, regardless of which
source produced the ACL-like record or which RBAC flavor it is being
translated to: DENY and non-ALLOW permissions have no RBAC representation,
RBAC bindings cannot carry a host restriction, wildcard principals are not
translatable, and only LITERAL/PREFIXED resource patterns are safely
representable. This file enforces those rules exactly once; target modules
never see a record that has already failed one of them.
"""
from __future__ import annotations

import json


def translate(records: list[dict], target, context) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    grouped: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []

    for index, record in enumerate(records):
        prefix = f"record {index}"
        permission = record.get("permission")
        if permission == "DENY":
            warnings.append(f"{prefix}: DENY cannot be represented by an RBAC role binding; skipped")
            continue
        if permission != "ALLOW":
            warnings.append(f"{prefix}: permission {permission!r} is not ALLOW; skipped")
            continue
        if record.get("host", "*") != "*":
            warnings.append(f"{prefix}: host restriction {record.get('host')!r} has no RBAC equivalent; skipped")
            continue
        principal = record.get("principal", "")
        if not principal or principal.endswith(":*"):
            warnings.append(f"{prefix}: wildcard principal {principal!r} has no RBAC equivalent; skipped")
            continue
        if record.get("pattern_type") not in {"LITERAL", "PREFIXED"}:
            warnings.append(f"{prefix}: pattern_type {record.get('pattern_type')!r} is not safely representable; skipped")
            continue

        if record.get("resource_type") == "CLUSTER":
            cluster = target.cluster_binding(context)
            if cluster is None:
                warnings.append(f"{prefix}: CLUSTER ACL requires an explicitly selected cluster role; skipped")
                continue
            role, locator, role_warning = cluster
            roles = [role]
        else:
            roles, role_warning = target.roles_for(record, context)
            if not roles:
                warnings.append(f"{prefix}: {role_warning}")
                continue
            try:
                locator = target.locator_for(record, context)
            except (KeyError, ValueError) as exc:
                warnings.append(f"{prefix}: {exc}; skipped")
                continue

        if role_warning:
            warnings.append(f"{prefix}: {role_warning}")

        principal_out = target.principal_for_target(principal)
        locator_key = json.dumps(locator, sort_keys=True)
        for role in roles:
            key = (principal_out, role, locator_key)
            if key not in grouped:
                grouped[key] = {"principal": principal_out, "role_name": role, **locator, "source_records": []}
                order.append(key)
            grouped[key]["source_records"].append(record)

    bindings = []
    for key in sorted(order):
        entry = grouped[key]
        source_records = entry.pop("source_records")
        entry["source_acl_count"] = len(source_records)
        entry["source_acls"] = source_records
        bindings.append(entry)
    return bindings, warnings
