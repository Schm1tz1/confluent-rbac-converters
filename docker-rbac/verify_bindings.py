#!/usr/bin/env python3
"""Read-after-write check for a --target cp-mds RoleBinding YAML: for every
binding, ask MDS's own lookup endpoints whether it's actually there, rather
than trusting apply_to_mds.py's 204 status codes alone.

Two MDS lookup endpoints, confirmed against a live broker (mock_server.py
does not implement these -- they're read-only and only meaningful against
a real MDS auth store):

* POST /security/1.0/lookup/principals/{principal}/roleNames
  body {"clusters": {...}} (bare, no "scope" wrapper) -> ["RoleA", "RoleB"]
* POST /security/1.0/principals/{principal}/roles/{roleName}/resources
  same body shape -> [{"resourceType": ..., "name": ..., "patternType": ...}]

Usage: verify_bindings.py <rolebindings.yaml> <mds_url> <bearer_token>
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

import yaml


def lookup(mds_url: str, token: str, path: str, body: dict):
    request = urllib.request.Request(
        f"{mds_url}{path}",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else []


def main() -> int:
    rb_path, mds_url, token = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(rb_path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    bindings = document.get("data", [])

    failures: list[str] = []
    for binding in bindings:
        principal = binding["principal"]
        role = binding["role_name"]
        principal_quoted = urllib.parse.quote(principal, safe="")
        role_quoted = urllib.parse.quote(role, safe="")
        clusters = (binding.get("cluster_scope") or binding.get("scope") or {}).get("clusters")
        if not clusters:
            failures.append(f"{principal}/{role}: binding has neither cluster_scope nor scope")
            continue

        try:
            role_names = lookup(mds_url, token, f"/security/1.0/lookup/principals/{principal_quoted}/roleNames", {"clusters": clusters})
        except urllib.error.HTTPError as exc:
            failures.append(f"{principal}/{role}: roleNames lookup failed with HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}")
            continue
        if role not in role_names:
            failures.append(f"{principal}: expected role {role!r} not found in MDS lookup {role_names!r}")
            continue

        expected_patterns = binding.get("resource_patterns")
        if expected_patterns:
            try:
                actual_patterns = lookup(
                    mds_url, token, f"/security/1.0/principals/{principal_quoted}/roles/{role_quoted}/resources", {"clusters": clusters}
                )
            except urllib.error.HTTPError as exc:
                failures.append(f"{principal}/{role}: resources lookup failed with HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}")
                continue
            for pattern in expected_patterns:
                if pattern not in actual_patterns:
                    failures.append(f"{principal}/{role}: expected resource pattern {pattern!r} not found in MDS lookup {actual_patterns!r}")

    print(f"verified {len(bindings)} bindings against MDS lookup endpoints")
    if failures:
        print(f"FAIL: {len(failures)} mismatch(es):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: every binding is visible via MDS lookup, matching what apply_to_mds.py applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
