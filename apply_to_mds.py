#!/usr/bin/env python3
"""Submit RoleBinding YAML to a Confluent Platform cluster via the MDS RBAC API.

Dry-run is the default. Add --apply to POST. Requires: PyYAML (pip install -r requirements.txt)

Input must come from `acl_to_rolebindings.py --target cp-mds` -- bindings
carry {"scope", "resource_patterns"} rather than IAM v2's {"crn_pattern"},
so CC-targeted RoleBinding YAML (the default `--target cc` output) will fail
validation here. See targets/cp_mds.py for the (best-guess, unverified
against a live MDS instance) wire-format assumptions.
"""
from __future__ import annotations

import argparse
import sys

import yaml

from common import apply_shell
from targets import cp_mds as target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="RoleBinding YAML from acl_to_rolebindings.py --target cp-mds")
    target.add_apply_cli_args(parser)
    parser.add_argument("--apply", action="store_true", help="Actually POST bindings; otherwise only validate and print them")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--results", default="rolebinding-results.json")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    bindings = document.get("data", [])
    apply_shell.validate_bindings(bindings, target)

    results, failed = apply_shell.run(bindings, target, args)
    if args.apply:
        apply_shell.write_results(results, target.endpoint_base(args), args.results)
        print(f"wrote results to {args.results}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
