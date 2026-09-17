"""Registry of pluggable RBAC targets.

Every target module implements the same duck-typed interface (see
common/invariants.py and common/apply_shell.py for the exact contract):
transform-side `add_transform_cli_args`, `resolve_context`, `metadata_for`,
`roles_for`, `locator_for`, `cluster_binding`, `principal_for_target`; and
apply-side `REQUIRED_APPLY_FIELDS`, `add_apply_cli_args`, `auth_headers`,
`endpoint_base`, `build_payload`, `submit_one`.

Adding a new target is one new module here plus one registry entry below —
nothing in the sources, common/invariants.py, or common/apply_shell.py needs
to change.
"""
from __future__ import annotations

from . import cc_rbac, cp_mds

TRANSFORM_TARGETS = {
    "cc": cc_rbac,
    "cp-mds": cp_mds,
}

APPLY_TARGETS = {
    "cc": cc_rbac,
    "cp-mds": cp_mds,
}
