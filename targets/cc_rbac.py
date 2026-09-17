"""Confluent Cloud IAM v2 RBAC target: CRN patterns and the IAM v2 REST API.

This is the extraction of what used to be CC-specific code baked directly
into acl_to_rolebindings.py and apply_rolebindings.py. Behavior is
unchanged from before the refactor -- same role table, same CRN shape, same
endpoint/auth/retry semantics.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from common import principals, role_table
from common.apply_shell import ApplyRequestError, RetryableRequestError

RESOURCE_SEGMENTS = {
    "TOPIC": "topic",
    "GROUP": "group",
    "TRANSACTIONAL_ID": "transactional-id",
}

DEFAULT_ENDPOINT = "https://api.confluent.cloud/iam/v2/role-bindings"
REQUIRED_APPLY_FIELDS = {"principal", "role_name", "crn_pattern"}


# --- transform side ---

def add_transform_cli_args(parser) -> None:
    parser.add_argument(
        "--organization-id", default=os.getenv("CC_ORGANIZATION_ID"),
        help="env: CC_ORGANIZATION_ID",
    )
    parser.add_argument(
        "--environment-id", default=os.getenv("CC_ENVIRONMENT_ID"),
        help="env: CC_ENVIRONMENT_ID",
    )
    parser.add_argument(
        "--kafka-cluster-id", default=os.getenv("CC_KAFKA_CLUSTER_ID"),
        help="Override cluster_id from the source file (env: CC_KAFKA_CLUSTER_ID)",
    )
    parser.add_argument("--alter-role", default="ResourceOwner", help="Role for ALTER/ALTER_CONFIGS; default: ResourceOwner")
    parser.add_argument("--all-role", default="ResourceOwner", help="Role for ALL/ANY; default: ResourceOwner")
    parser.add_argument("--cluster-role", help="Optional role for CLUSTER ACLs; omitted by default for safety")


def resolve_context(args, source_metadata: dict) -> dict:
    if not args.organization_id:
        raise SystemExit("Set --organization-id or CC_ORGANIZATION_ID")
    if not args.environment_id:
        raise SystemExit("Set --environment-id or CC_ENVIRONMENT_ID")
    cluster_id = args.kafka_cluster_id or source_metadata.get("cluster_id")
    if not cluster_id:
        raise SystemExit("No cluster ID found; use --kafka-cluster-id")
    return {
        "organization_id": args.organization_id,
        "environment_id": args.environment_id,
        "cluster_id": cluster_id,
        "alter_role": args.alter_role,
        "all_role": args.all_role,
        "cluster_role": args.cluster_role,
    }


def metadata_for(context: dict) -> dict:
    return {
        "organization_id": context["organization_id"],
        "environment_id": context["environment_id"],
        "kafka_cluster_id": context["cluster_id"],
    }


def principal_for_target(value: str) -> str:
    return principals.normalize(value)


def _resource_name(record: dict) -> str:
    name = record.get("resource_name")
    pattern = record.get("pattern_type", "LITERAL")
    if name is None:
        raise ValueError("missing resource_name")
    if pattern == "PREFIXED":
        return f"{name}*"
    if pattern == "LITERAL":
        return str(name)
    raise ValueError(f"unsupported pattern_type {pattern!r}; only LITERAL and PREFIXED are safe")


def roles_for(record: dict, context: dict) -> tuple[list[str], str | None]:
    return role_table.roles_for(record, RESOURCE_SEGMENTS, context["alter_role"], context["all_role"])


def locator_for(record: dict, context: dict) -> dict:
    segment = RESOURCE_SEGMENTS[record["resource_type"]]
    name = urllib.parse.quote(_resource_name(record), safe="*-._")
    crn = (
        f"crn://confluent.cloud/organization={context['organization_id']}"
        f"/environment={context['environment_id']}/cloud-cluster={context['cluster_id']}"
        f"/kafka={context['cluster_id']}/{segment}={name}"
    )
    return {"crn_pattern": crn}


def cluster_binding(context: dict):
    if not context.get("cluster_role"):
        return None
    crn = (
        f"crn://confluent.cloud/organization={context['organization_id']}"
        f"/environment={context['environment_id']}/cloud-cluster={context['cluster_id']}"
    )
    return context["cluster_role"], {"crn_pattern": crn}, "cluster ACL mapped using explicitly selected cluster role"


# --- apply side ---

def add_apply_cli_args(parser) -> None:
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)


def endpoint_base(args) -> str:
    return args.endpoint


def auth_headers(args) -> dict[str, str]:
    token = os.getenv("CC_ACCESS_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}
    key = os.getenv("CC_IAM_API_KEY") or os.getenv("CC_API_KEY")
    secret = os.getenv("CC_IAM_API_SECRET") or os.getenv("CC_API_SECRET")
    if not key or not secret:
        raise SystemExit("Set CC_API_KEY and CC_API_SECRET, or CC_ACCESS_TOKEN.")
    basic = base64.b64encode(f"{key}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {basic}", "Accept": "application/json", "Content-Type": "application/json"}


def build_payload(binding: dict) -> dict:
    return {
        "principal": binding["principal"],
        "role_name": binding["role_name"],
        "crn_pattern": binding["crn_pattern"],
    }


def submit_one(payload: dict, headers: dict[str, str], endpoint: str):
    body = json.dumps(payload).encode()
    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
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
