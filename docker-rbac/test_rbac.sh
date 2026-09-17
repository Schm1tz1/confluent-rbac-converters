#!/usr/bin/env bash
# End-to-end test: brings up a real, minimal Confluent Platform broker with
# RBAC/MDS enabled, waits for it to be ready, sanity-checks both MDS
# role-binding endpoints with raw curl, then runs the actual pipeline
# (acl_to_rolebindings.py --target cp-mds -> apply_to_mds.py --apply)
# against it for BOTH sources -- examples/cc-acls.yaml directly, and
# examples/ranger-kafka-policies.json via export_ranger_policies.py first --
# proving targets/cp_mds.py's wire format against a live broker for both,
# not just mock_server.py.
#
# Usage: ./test_rbac.sh [--keep]   (--keep leaves the broker running after)
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"
PYTHON="${PYTHON:-python3}"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

if [[ ! -f secrets/tokenKeypair.pem ]]; then
  echo "== generating MDS token keypair =="
  ./gen-keypair.sh
fi

cleanup() {
  if [[ "$KEEP" -eq 0 ]]; then
    echo "== tearing down =="
    docker compose down -v > /dev/null 2>&1 || true
  else
    echo "== leaving broker running (docker compose -f docker-rbac/docker-compose.yml down -v to stop it) =="
  fi
}
trap cleanup EXIT

echo "== starting broker =="
docker compose up -d

CLUSTER_ID="${CLUSTER_ID:-Y0TWB4uSQfO0oZyvyng4Yw}"
MDS_URL="http://127.0.0.1:8090"

echo "== waiting for MDS to answer (up to 90s) =="
for i in $(seq 1 45); do
  if curl -s -o /dev/null -w '' -u mds:mds1 "$MDS_URL/security/1.0/authenticate" 2>/dev/null; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -u mds:mds1 "$MDS_URL/security/1.0/authenticate")
    if [[ "$code" == "200" ]]; then
      echo "MDS is up after ${i}x2s"
      break
    fi
  fi
  if [[ "$i" -eq 45 ]]; then
    echo "MDS never came up; broker logs:"
    docker compose logs broker | tail -100
    exit 1
  fi
  sleep 2
done

TOKEN="$(curl -s -u mds:mds1 "$MDS_URL/security/1.0/authenticate" | $PYTHON -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")"

echo "== raw-curl sanity check: resource-scoped bind =="
code=$(curl -s -o /tmp/rbac-sanity-resource.json -w '%{http_code}' -X POST \
  "$MDS_URL/security/1.0/principals/User:clienta/roles/DeveloperRead/bindings" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"scope\":{\"clusters\":{\"kafka-cluster\":\"$CLUSTER_ID\"}},\"resourcePatterns\":[{\"resourceType\":\"Topic\",\"name\":\"sanity-topic\",\"patternType\":\"LITERAL\"}]}")
[[ "$code" == "204" ]] || { echo "FAIL: expected 204, got $code"; cat /tmp/rbac-sanity-resource.json; exit 1; }
echo "OK ($code)"

echo "== raw-curl sanity check: cluster-scoped bind =="
code=$(curl -s -o /tmp/rbac-sanity-cluster.json -w '%{http_code}' -X POST \
  "$MDS_URL/security/1.0/principals/User:clienta/roles/ClusterAdmin" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"clusters\":{\"kafka-cluster\":\"$CLUSTER_ID\"}}")
[[ "$code" == "204" ]] || { echo "FAIL: expected 204, got $code"; cat /tmp/rbac-sanity-cluster.json; exit 1; }
echo "OK ($code)"

WORKDIR="$(mktemp -d)"

# Runs acl_to_rolebindings.py --target cp-mds -> apply_to_mds.py --apply on
# an already-canonical ACL-record YAML, and fails loudly on any non-2xx result.
run_case() {
  local label="$1"
  local canonical_yaml="$2"
  local rb_out="$WORKDIR/rb-$label.yaml"
  local results_out="$WORKDIR/results-$label.json"
  echo "== [$label] acl_to_rolebindings.py --target cp-mds -> apply_to_mds.py --apply =="
  "$PYTHON" "$REPO_ROOT/acl_to_rolebindings.py" "$canonical_yaml" \
    --target cp-mds --kafka-cluster-id "$CLUSTER_ID" --cluster-role ClusterAdmin \
    -o "$rb_out"

  MDS_USERNAME=mds MDS_PASSWORD=mds1 "$PYTHON" "$REPO_ROOT/apply_to_mds.py" "$rb_out" \
    --apply --mds-url "$MDS_URL" --results "$results_out"

  local failures
  failures="$($PYTHON -c "
import json
doc = json.load(open('$results_out'))
bad = [r for r in doc['results'] if not r.get('status') or r['status'] >= 300]
print(len(bad))
for r in bad:
    print('  ', r)
")"
  if [[ "$(echo "$failures" | head -1)" != "0" ]]; then
    echo "FAIL [$label]: $failures non-2xx results (see $results_out)"
    exit 1
  fi
  echo "PASS [$label]"
}

# Source 1: an already-canonical CC ACL export.
run_case cc-acls "$REPO_ROOT/examples/cc-acls.yaml"

# Source 2: Ranger policies, via export_ranger_policies.py first.
"$PYTHON" "$REPO_ROOT/export_ranger_policies.py" \
  --input-file "$REPO_ROOT/examples/ranger-kafka-policies.json" \
  --cluster-id "$CLUSTER_ID" -o "$WORKDIR/ranger-acls.yaml"
run_case ranger "$WORKDIR/ranger-acls.yaml"

echo
echo "PASS: both examples/cc-acls.yaml and examples/ranger-kafka-policies.json applied successfully against a live RBAC/MDS broker."
rm -rf "$WORKDIR"
