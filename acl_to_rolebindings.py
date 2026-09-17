#!/usr/bin/env python3
"""Convert exported ACL/policy YAML into reviewable RBAC RoleBinding YAML.

Reads the canonical intermediate ACL-record schema (produced by
export_cc_acls.py or export_ranger_policies.py), applies the source-agnostic
design invariants in common/invariants.py (only ALLOW, wildcard-host,
LITERAL/PREFIXED ACLs are translated; DENY and everything else is skipped
and recorded in metadata.warnings), and hands each surviving record to the
--target module (targets/cc_rbac.py or targets/cp_mds.py) for role-name and
locator translation.

Requires: PyYAML (pip install PyYAML)
"""
from __future__ import annotations

import argparse
import sys

import yaml

from common.invariants import translate
from targets import TRANSFORM_TARGETS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="ACL/policy YAML from export_cc_acls.py or export_ranger_policies.py")
    parser.add_argument("-o", "--output", default="rolebindings.yaml")
    parser.add_argument(
        "--target", choices=sorted(TRANSFORM_TARGETS), default="cc",
        help="RBAC flavor to translate into: cc (Confluent Cloud IAM v2, default) or cp-mds (Confluent Platform via MDS)",
    )
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any ACL could not be translated")
    return parser


def main() -> int:
    # --target picks which extra CLI args exist (e.g. --organization-id for
    # cc vs. nothing comparable for cp-mds), so peek at it before building
    # the full parser.
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--target", choices=sorted(TRANSFORM_TARGETS), default="cc")
    pre_args, _ = pre_parser.parse_known_args()
    target = TRANSFORM_TARGETS[pre_args.target]

    parser = build_parser()
    target.add_transform_cli_args(parser)
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        source = yaml.safe_load(handle) or {}
    records = source.get("data", [])
    context = target.resolve_context(args, source.get("metadata", {}))

    bindings, warnings = translate(records, target, context)

    document = {
        "api_version": "iam/v2" if args.target == "cc" else "cp-rbac/mds",
        "kind": "RoleBindingList",
        "metadata": {
            "target": args.target,
            **target.metadata_for(context),
            "source_file": args.input,
            "binding_count": len(bindings),
            "warning_count": len(warnings),
            "warnings": warnings,
        },
        "data": bindings,
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=True)
    print(f"wrote {len(bindings)} role bindings and {len(warnings)} warnings to {args.output}")
    if args.strict and warnings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
