#!/usr/bin/env python3
"""Local mock of the three real APIs this pipeline talks to, for testing
--apply end to end without hitting Confluent Cloud or a real MDS broker.

Stdlib only (http.server) -- no dependencies, nothing to install.

Endpoints, matching the shapes documented by Confluent (see README.md's
Sources section for the exact doc pages this was checked against):

* GET  /kafka/v3/clusters/{cluster_id}/acls[?principal=...]
  -- what export_cc_acls.py reads. Serves a small canned dataset that
  includes a legacy numeric principal (User:12345) on the unfiltered
  request and its normalized UserV2:* counterpart (UserV2:u-12345) on a
  `?principal=UserV2:*` request, so export_cc_acls.py's real merge/
  normalization logic actually has something to do.

* POST /iam/v2/role-bindings
  -- what apply_rolebindings.py (--target cc) POSTs to.

* GET  /security/1.0/authenticate
  -- MDS login, what targets/cp_mds.py's auth_headers() calls when
  MDS_ACCESS_TOKEN isn't set.

* POST /security/1.0/principals/{principal}/roles/{role}
  -- MDS cluster-scoped role bind (targets/cp_mds.py's cluster_binding path).

* POST /security/1.0/principals/{principal}/roles/{role}/bindings
  -- MDS resource-scoped role bind (targets/cp_mds.py's locator_for path).

All endpoints require *some* well-formed Authorization header (Basic or
Bearer) but accept any credentials -- this is for exercising the scripts'
own header-building and error-handling code, not for testing real auth.

Failure injection: POST a binding with role_name "TriggerRateLimit" or
"TriggerServerError" to get a 429 (with Retry-After: 1) or 500 exactly once
per (path, principal, role); the identical request succeeds on the next
attempt, so retrying the same run with --retries >= 1 exercises the real
retry/backoff code in common/apply_shell.py.

Usage:
    python3 mock_server.py --port 8089
    # in another shell:
    export CC_API_KEY=fake CC_API_SECRET=fake
    python3 export_cc_acls.py --cluster-id lkc-mock1 --rest-base-url http://127.0.0.1:8089 -o acls.yaml
    python3 acl_to_rolebindings.py acls.yaml --organization-id org-1 --environment-id env-1 -o rb.yaml
    python3 apply_rolebindings.py rb.yaml --apply --endpoint http://127.0.0.1:8089/iam/v2/role-bindings
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.server
import json
import urllib.parse


LEGACY_ACLS = [
    {
        "kind": "KafkaAcl",
        "cluster_id": "lkc-mock1",
        "resource_type": "TOPIC",
        "resource_name": "payments",
        "pattern_type": "LITERAL",
        "principal": "User:12345",
        "host": "*",
        "operation": "READ",
        "permission": "ALLOW",
    },
    {
        "kind": "KafkaAcl",
        "cluster_id": "lkc-mock1",
        "resource_type": "TOPIC",
        "resource_name": "payments",
        "pattern_type": "LITERAL",
        "principal": "User:sa-999",
        "host": "*",
        "operation": "WRITE",
        "permission": "ALLOW",
    },
    {
        "kind": "KafkaAcl",
        "cluster_id": "lkc-mock1",
        "resource_type": "GROUP",
        "resource_name": "orders-consumer",
        "pattern_type": "LITERAL",
        "principal": "User:67890",
        "host": "*",
        "operation": "READ",
        "permission": "ALLOW",
    },
]

# The UserV2:* filtered view export_cc_acls.py additionally requests by
# default; the same ACL keys as the numeric-principal rows above, but with
# the RBAC-friendly sa- style principal -- this is what the real ACL API
# documents as the only way to retrieve normalized service-account IDs.
NORMALIZED_ACLS = [
    {**LEGACY_ACLS[0], "principal": "UserV2:u-12345"},
    {**LEGACY_ACLS[2], "principal": "UserV2:u-67890"},
]

# (path, principal, role) -> already failed once; the next identical
# request succeeds, so retry logic has something real to exercise.
_FAILED_ONCE: set[tuple[str, str, str]] = set()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class MockHandler(http.server.BaseHTTPRequestHandler):
    server_version = "MockConfluentAPIs/1.0"

    # --- helpers ---

    def _require_auth(self) -> bool:
        value = self.headers.get("Authorization", "")
        if not (value.startswith("Basic ") or value.startswith("Bearer ")):
            self._send_json(401, {"error": "missing or malformed Authorization header"})
            return False
        return True

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw) if raw else {}

    def _send_json(self, status: int, obj: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status: int, extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _maybe_inject_failure(self, path: str, principal: str, role_name: str) -> bool:
        """Return True if a canned failure was sent (caller should stop)."""
        key = (path, principal, role_name)
        if key in _FAILED_ONCE:
            return False
        if role_name == "TriggerRateLimit":
            _FAILED_ONCE.add(key)
            self._send_json(429, {"error": "rate limited (mock)"}, {"Retry-After": "1"})
            return True
        if role_name == "TriggerServerError":
            _FAILED_ONCE.add(key)
            self._send_json(500, {"error": "internal error (mock)"})
            return True
        return False

    # --- routing ---

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        query = urllib.parse.parse_qs(parsed.query)

        if len(parts) == 5 and parts[:3] == ["kafka", "v3", "clusters"] and parts[4] == "acls":
            if not self._require_auth():
                return
            cluster_id = parts[3]
            principal = query.get("principal", [None])[0]
            data = NORMALIZED_ACLS if principal == "UserV2:*" else LEGACY_ACLS
            if principal and principal != "UserV2:*":
                data = [acl for acl in data if acl["principal"] == principal]
            self_url = f"http://{self.headers.get('Host', 'localhost')}{self.path}"
            self._send_json(200, {
                "kind": "KafkaAclList",
                "metadata": {"self": self_url},
                "data": [{**acl, "cluster_id": cluster_id, "metadata": {"self": self_url}} for acl in data],
            })
            return

        if parts == ["security", "1.0", "authenticate"]:
            if not self._require_auth():
                return
            self._send_json(200, {"auth_token": "mock-token-123", "token_type": "bearer", "expires_in": 3600})
            return

        self._send_json(404, {"error": f"no mock route for GET {self.path}"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        parts = [p for p in parsed.path.split("/") if p]

        if parts == ["iam", "v2", "role-bindings"]:
            if not self._require_auth():
                return
            body = self._read_json_body()
            missing = {"principal", "role_name", "crn_pattern"} - set(body)
            if missing:
                self._send_json(400, {"error": f"missing fields: {sorted(missing)}"})
                return
            if self._maybe_inject_failure(parsed.path, body["principal"], body["role_name"]):
                return
            self._send_json(201, {
                "api_version": "iam/v2",
                "kind": "RoleBinding",
                "id": "rb-mock000001",
                "metadata": {
                    "self": f"http://{self.headers.get('Host', 'localhost')}/iam/v2/role-bindings/rb-mock000001",
                    "resource_name": body["crn_pattern"],
                    "created_at": _now(),
                    "updated_at": _now(),
                },
                "principal": body["principal"],
                "role_name": body["role_name"],
                "crn_pattern": body["crn_pattern"],
            }, {"Location": "/iam/v2/role-bindings/rb-mock000001"})
            return

        # e.g. ["security","1.0","principals","<principal>","roles","<roleName>"(,"bindings")]
        if len(parts) < 6 or parts[:3] != ["security", "1.0", "principals"]:
            self._send_json(404, {"error": f"no mock route for POST {self.path}"})
            return
        principal = urllib.parse.unquote(parts[3])
        rest = parts[4:]
        # rest is like ["roles", "<roleName>"] or ["roles", "<roleName>", "bindings"]
        if len(rest) == 2 and rest[0] == "roles":
            role_name = urllib.parse.unquote(rest[1])
            if not self._require_auth():
                return
            body = self._read_json_body()
            if "clusters" not in body:
                self._send_json(400, {"error": "expected a {'clusters': {...}} body for a cluster-scoped bind"})
                return
            if self._maybe_inject_failure(parsed.path, principal, role_name):
                return
            self._send_empty(204)
            return

        if len(rest) == 3 and rest[0] == "roles" and rest[2] == "bindings":
            role_name = urllib.parse.unquote(rest[1])
            if not self._require_auth():
                return
            body = self._read_json_body()
            missing = {"scope", "resourcePatterns"} - set(body)
            if missing:
                self._send_json(400, {"error": f"missing fields: {sorted(missing)}"})
                return
            if self._maybe_inject_failure(parsed.path, principal, role_name):
                return
            self._send_empty(204)
            return

        self._send_json(404, {"error": f"no mock route for POST {self.path}"})

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - matches BaseHTTPRequestHandler's signature
        print(f"[mock_server] {self.address_string()} - {format % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8089)
    args = parser.parse_args()

    server = http.server.HTTPServer((args.host, args.port), MockHandler)
    print(f"mock_server.py listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
