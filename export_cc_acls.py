#!/usr/bin/env python3
"""Export all ACLs for one Confluent Cloud Kafka cluster to YAML.

Requires: PyYAML (pip install -r requirements.txt)
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import yaml


def auth_headers(api_key: str | None, api_secret: str | None, token: str | None) -> dict[str, str]:
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if not api_key or not api_secret:
        raise SystemExit("Set CC_API_KEY and CC_API_SECRET, or CC_ACCESS_TOKEN.")
    value = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
    return {"Authorization": f"Basic {value}", "Accept": "application/json"}


def get_json(url: str, headers: dict[str, str]) -> dict:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise SystemExit(f"GET {url} failed with HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"GET {url} failed: {exc.reason}") from exc


def fetch(base_url: str, cluster_id: str, headers: dict[str, str], principal: str | None) -> list[dict]:
    path = f"/kafka/v3/clusters/{urllib.parse.quote(cluster_id, safe='')}/acls"
    params = {"principal": principal} if principal else {}
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if params:
        url += "?" + urllib.parse.urlencode(params)
    payload = get_json(url, headers)
    data = payload.get("data", [])
    if not isinstance(data, list):
        raise SystemExit(f"Unexpected ACL response: data is {type(data).__name__}, not a list")
    return data


def acl_key(acl: dict) -> tuple:
    return tuple(acl.get(field) for field in (
        "cluster_id", "resource_type", "resource_name", "pattern_type",
        "principal", "host", "operation", "permission",
    ))


def acl_key_without_principal(acl: dict) -> tuple:
    return tuple(acl.get(field) for field in (
        "cluster_id", "resource_type", "resource_name", "pattern_type",
        "host", "operation", "permission",
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cluster-id", default=os.getenv("CC_CLUSTER_ID"),
        help="Kafka cluster ID, for example lkc-123abc (env: CC_CLUSTER_ID)",
    )
    parser.add_argument(
        "--rest-base-url", default=os.getenv("CC_REST_BASE_URL"),
        help="Kafka REST endpoint, for example https://pkc-...confluent.cloud (env: CC_REST_BASE_URL)",
    )
    parser.add_argument("-o", "--output", default="acls.yaml")
    parser.add_argument("--principal", help="Optional ACL principal filter")
    parser.add_argument(
        "--legacy-principals", action="store_true",
        help="Do not make the additional UserV2:* request used to normalize service-account IDs",
    )
    args = parser.parse_args()
    if not args.cluster_id:
        raise SystemExit("Set --cluster-id or CC_CLUSTER_ID")
    if not args.rest_base_url:
        raise SystemExit("Set --rest-base-url or CC_REST_BASE_URL")

    headers = auth_headers(
        os.getenv("CC_KAFKA_API_KEY") or os.getenv("CC_API_KEY"),
        os.getenv("CC_KAFKA_API_SECRET") or os.getenv("CC_API_SECRET"),
        os.getenv("CC_ACCESS_TOKEN"),
    )
    acls = fetch(args.rest_base_url, args.cluster_id, headers, args.principal)

    # The ACL API documents UserV2:* as the way to retrieve service accounts in sa-xxx form.
    # Merge it with the unfiltered result so the export remains complete and uses RBAC-friendly IDs.
    if not args.principal and not args.legacy_principals:
        normalized = fetch(args.rest_base_url, args.cluster_id, headers, "UserV2:*")
        normalized_by_acl = {}
        for acl in normalized:
            normalized_by_acl.setdefault(acl_key_without_principal(acl), []).append(acl)
        legacy_by_acl = {}
        for acl in acls:
            legacy_by_acl.setdefault(acl_key_without_principal(acl), []).append(acl)
        merged = []
        for key, legacy_items in legacy_by_acl.items():
            normalized_items = normalized_by_acl.get(key, [])
            numeric = [item for item in legacy_items if item.get("principal", "").removeprefix("User:").isdigit()]
            if numeric and len(numeric) == len(normalized_items):
                merged.extend(item for item in legacy_items if item not in numeric)
                merged.extend(normalized_items)
            else:
                merged.extend(legacy_items)
        for key, normalized_items in normalized_by_acl.items():
            if key not in legacy_by_acl:
                merged.extend(normalized_items)
        acls = merged

    document = {
        "api_version": "kafka/v3",
        "kind": "KafkaAclList",
        "metadata": {
            "cluster_id": args.cluster_id,
            "source_url": args.rest_base_url.rstrip("/") + f"/kafka/v3/clusters/{args.cluster_id}/acls",
            "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "count": len(acls),
        },
        "data": acls,
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=True)
    print(json.dumps({"output": args.output, "acl_count": len(acls)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
