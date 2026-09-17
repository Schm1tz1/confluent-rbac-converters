"""Generic dry-run/apply/retry/results-log shell shared by every apply target.

Only the 429/5xx-vs-other-4xx retry decision and the request/response shape
are target-specific (see targets/*.py's submit_one()); the surrounding
loop -- dry-run short-circuit, exponential backoff honoring Retry-After,
--continue-on-error, and the JSON results log -- is transport-generic and
lives here exactly once.
"""
from __future__ import annotations

import json
import time


class RetryableRequestError(Exception):
    """A 429/5xx response or a transport-level failure; may be retried."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ApplyRequestError(Exception):
    """A non-retryable 4xx response."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def validate_bindings(bindings: list[dict], target) -> None:
    required = target.REQUIRED_APPLY_FIELDS
    for index, binding in enumerate(bindings):
        missing = required - set(binding)
        if missing:
            raise SystemExit(f"binding {index} is missing: {', '.join(sorted(missing))}")


def submit_with_retry(binding: dict, target, request_headers: dict[str, str], retries: int, base: str) -> dict:
    payload = target.build_payload(binding)
    for attempt in range(retries + 1):
        try:
            status, response = target.submit_one(payload, request_headers, base)
            return {"status": status, "request": payload, "response": response}
        except RetryableRequestError as exc:
            if attempt < retries:
                delay = exc.retry_after if exc.retry_after is not None else min(2 ** attempt, 30)
                time.sleep(delay)
                continue
            return {"status": None, "request": payload, "error": str(exc)}
        except ApplyRequestError as exc:
            return {"status": exc.status, "request": payload, "error": str(exc)}
    raise AssertionError("unreachable")


def dry_run_report(bindings: list[dict], target) -> dict:
    return {
        "dry_run": True,
        "binding_count": len(bindings),
        "bindings": [target.build_payload(binding) for binding in bindings],
    }


def run(bindings: list[dict], target, args) -> tuple[list[dict], bool]:
    if not args.apply:
        print(json.dumps(dry_run_report(bindings, target), indent=2))
        return [], False

    request_headers = target.auth_headers(args)
    base = target.endpoint_base(args)
    results = []
    failed = False
    for binding in bindings:
        result = submit_with_retry(binding, target, request_headers, args.retries, base)
        results.append(result)
        print(json.dumps(result, indent=2))
        if not result.get("status") or result["status"] >= 300:
            failed = True
            if not args.continue_on_error:
                break
    return results, failed


def write_results(results: list[dict], endpoint: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"endpoint": endpoint, "results": results}, handle, indent=2)
