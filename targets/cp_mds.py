"""Confluent Platform RBAC target: MDS scope/resourcePattern bindings.

BEST-GUESS / NEEDS VERIFICATION: the role-binding create endpoint shape here
(POST {mds_url}/security/1.0/principals/{principal}/roles/{role}/bindings
with a {"scope", "resourcePatterns"} body) and the login flow (GET
{mds_url}/security/1.0/authenticate with HTTP Basic, returning an
"auth_token") follow Confluent Platform's documented MDS RBAC API shape, but
have not been verified against a live MDS instance. Confirm both against
your actual CP/MDS version before running with --apply.

Unlike Confluent Cloud, CP/MDS has no organization/environment/cloud-cluster
hierarchy -- scope is just the on-prem Kafka cluster id registered with MDS.
Role names (DeveloperRead/Write/Manage, ResourceOwner, ...) are assumed
identical to Confluent Cloud's and come from the shared common/role_table.py;
verify that assumption against your CP version's predefined roles too.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from common import role_table
from common.apply_shell import ApplyRequestError, RetryableRequestError

# MDS resourceType casing, per Kafka's own ResourceType enum used by MDS.
RESOURCE_SEGMENTS = {
    "TOPIC": "Topic",
    "GROUP": "Group",
    "TRANSACTIONAL_ID": "TransactionalId",
}

REQUIRED_APPLY_FIELDS = {"principal", "role_name", "scope", "resource_patterns"}


# --- transform side ---

def add_transform_cli_args(parser) -> None:
    parser.add_argument(
        "--kafka-cluster-id", default=os.getenv("CP_KAFKA_CLUSTER_ID"),
        help="MDS-registered Kafka cluster ID, overrides cluster_id from the source file (env: CP_KAFKA_CLUSTER_ID)",
    )
    parser.add_argument("--alter-role", default="ResourceOwner", help="Role for ALTER/ALTER_CONFIGS; default: ResourceOwner")
    parser.add_argument("--all-role", default="ResourceOwner", help="Role for ALL/ANY; default: ResourceOwner")
    parser.add_argument("--cluster-role", help="Optional role for CLUSTER ACLs; omitted by default for safety")


def resolve_context(args, source_metadata: dict) -> dict:
    cluster_id = args.kafka_cluster_id or source_metadata.get("cluster_id")
    if not cluster_id:
        raise SystemExit("No cluster ID found; use --kafka-cluster-id or CP_KAFKA_CLUSTER_ID")
    return {
        "cluster_id": cluster_id,
        "alter_role": args.alter_role,
        "all_role": args.all_role,
        "cluster_role": args.cluster_role,
    }


def metadata_for(context: dict) -> dict:
    return {"kafka_cluster_id": context["cluster_id"]}


def principal_for_target(value: str) -> str:
    # MDS expects the same User:<name>/Group:<name> form the canonical record already uses.
    return value


def _resource_name_and_pattern(record: dict) -> tuple[str, str]:
    name = record.get("resource_name")
    pattern = record.get("pattern_type", "LITERAL")
    if name is None:
        raise ValueError("missing resource_name")
    if pattern not in {"LITERAL", "PREFIXED"}:
        raise ValueError(f"unsupported pattern_type {pattern!r}; only LITERAL and PREFIXED are safe")
    return str(name), pattern


def roles_for(record: dict, context: dict) -> tuple[list[str], str | None]:
    return role_table.roles_for(record, RESOURCE_SEGMENTS, context["alter_role"], context["all_role"])


def _scope(context: dict) -> dict:
    return {"clusters": {"kafka-cluster": context["cluster_id"]}}


def locator_for(record: dict, context: dict) -> dict:
    resource_type = RESOURCE_SEGMENTS[record["resource_type"]]
    name, pattern_type = _resource_name_and_pattern(record)
    return {
        "scope": _scope(context),
        "resource_patterns": [{"resourceType": resource_type, "name": name, "patternType": pattern_type}],
    }


def cluster_binding(context: dict):
    if not context.get("cluster_role"):
        return None
    locator = {"scope": _scope(context), "resource_patterns": []}
    return context["cluster_role"], locator, "cluster ACL mapped using explicitly selected cluster role"


# --- apply side ---

def add_apply_cli_args(parser) -> None:
    parser.add_argument(
        "--mds-url", default=os.getenv("MDS_URL"),
        help="Base URL of the MDS REST API, e.g. https://mds.example.com:8090 (env: MDS_URL)",
    )


def endpoint_base(args) -> str:
    if not args.mds_url:
        raise SystemExit("Set --mds-url or MDS_URL")
    return args.mds_url.rstrip("/")


def auth_headers(args) -> dict[str, str]:
    token = os.getenv("MDS_ACCESS_TOKEN")
    if not token:
        username = os.getenv("MDS_USERNAME")
        password = os.getenv("MDS_PASSWORD")
        if not username or not password:
            raise SystemExit("Set MDS_USERNAME and MDS_PASSWORD, or MDS_ACCESS_TOKEN.")
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = urllib.request.Request(
            f"{endpoint_base(args)}/security/1.0/authenticate",
            headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                token = json.load(response)["auth_token"]
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"MDS login failed with HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}") from exc
        except urllib.error.URLError as exc:
            raise SystemExit(f"MDS login failed: {exc.reason}") from exc
    return {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}


def build_payload(binding: dict) -> dict:
    return {
        "principal": binding["principal"],
        "role_name": binding["role_name"],
        "scope": binding["scope"],
        "resource_patterns": binding["resource_patterns"],
    }


def submit_one(payload: dict, headers: dict[str, str], base: str):
    principal = urllib.parse.quote(payload["principal"], safe="")
    role = urllib.parse.quote(payload["role_name"], safe="")
    url = f"{base}/security/1.0/principals/{principal}/roles/{role}/bindings"
    body = json.dumps({"scope": payload["scope"], "resourcePatterns": payload["resource_patterns"]}).encode()
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        if exc.code == 429 or exc.code >= 500:
            retry_after = exc.headers.get("Retry-After")
            raise RetryableRequestError(f"HTTP {exc.code}: {raw}", retry_after=float(retry_after) if retry_after else None)
        raise ApplyRequestError(exc.code, raw)
    except urllib.error.URLError as exc:
        raise RetryableRequestError(str(exc.reason))
