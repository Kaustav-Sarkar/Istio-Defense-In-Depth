#!/usr/bin/env bash
set -euo pipefail

APP_HOST="${APP_HOST:-app.localtest.me}"
APP_URL="${APP_URL:-https://${APP_HOST}}"
RESOLVE_IP="${RESOLVE_IP:-127.0.0.1}"
UNKNOWN_EMPLOYEE_ID="${UNKNOWN_EMPLOYEE_ID:-00000000-0000-0000-0000-000000000000}"

curl_status() {
  curl -s -o /dev/null -w "%{http_code}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "$@"
}

expect_denied() {
  local name="$1"
  local status="$2"
  if [[ "$status" == "401" || "$status" == "403" ]]; then
    echo "PASS: ${name} denied with ${status}"
  else
    echo "FAIL: ${name} returned ${status}, expected 401/403"
    exit 1
  fi
}

echo "Checking unauthenticated protected route denial..."
status=$(curl_status "${APP_URL}/api/profile/${UNKNOWN_EMPLOYEE_ID}")
expect_denied "unauthenticated profile request" "$status"

echo "Checking spoofed external identity header denial..."
status=$(curl_status \
  -H "x-ms1-user: attacker" \
  -H "x-ms1-role: hr_admin" \
  -H "x-mesh-identity: forged" \
  -H "x-platform-user: attacker" \
  "${APP_URL}/api/profile/${UNKNOWN_EMPLOYEE_ID}")
expect_denied "spoofed header request" "$status"

echo "Checking direct Tier 2 access through gateway is not routed..."
status=$(curl_status "${APP_URL}/api/employees/${UNKNOWN_EMPLOYEE_ID}")
if [[ "$status" == "404" || "$status" == "401" || "$status" == "403" ]]; then
  echo "PASS: direct Tier 2 gateway path unavailable with ${status}"
else
  echo "FAIL: direct Tier 2 gateway path returned ${status}, expected 404/401/403"
  exit 1
fi

echo "Checking in-cluster non-MS1 caller cannot reach MS2..."
direct_output=$(kubectl run zt-curl-check -n zt-apps --rm -i --restart=Never --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' http://ms2-employee-details:8000/api/employees/${UNKNOWN_EMPLOYEE_ID}" \
  2>/dev/null || true)
direct_status=$(printf "%s\n" "$direct_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
expect_denied "non-MS1 in-cluster MS2 request" "$direct_status"

echo "Checking wrong audience denied..."
TOKEN=$(curl -s -X POST https://idp.localtest.me/realms/istio-security-poc/protocol/openid-connect/token \
  -k --resolve idp.localtest.me:443:127.0.0.1 \
  -d "client_id=auth-service" \
  -d "client_secret=auth-service-client-secret-local-poc" \
  -d "username=alice.employee" \
  -d "password=alice-password" \
  -d "grant_type=password" | jq -r .access_token)

WRONG_MESH_TOKEN=$(kubectl exec -n zt-apps deploy/auth-service -- env TOKEN="$TOKEN" python -c "
import urllib.request, os
req = urllib.request.Request('http://localhost:8000/verify/api/holidays', headers={'Authorization': 'Bearer ' + os.environ['TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.headers.get('x-mesh-identity'))
except Exception as e:
    pass
")

wrong_aud_status=$(kubectl exec -n zt-apps deploy/ms1-profile-aggregator -- env WRONG_TOKEN="$WRONG_MESH_TOKEN" python -c "
import urllib.request, os
req = urllib.request.Request('http://ms2-employee-details:8000/api/employees/${UNKNOWN_EMPLOYEE_ID}', headers={'Authorization': 'Bearer ' + os.environ['WRONG_TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(e)
")
expect_denied "wrong audience request" "$wrong_aud_status"

echo "Checking expired token denied..."
kubectl exec -n zt-apps deploy/auth-service -- python -c "
import json, base64, time
import vault_client

key_version = vault_client.get_latest_key_version()
header = {'alg': 'RS256', 'typ': 'JWT', 'kid': str(key_version)}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')

payload = {
    'iss': 'auth-service',
    'sub': 'user:alice',
    'aud': ['ms2-employee-details'],
    'act': {'sub': 'ms1-profile-aggregator'},
    'exp': int(time.time()) - 3600,
    'iat': int(time.time()) - 7200
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

signing_input = f'{header_b64}.{payload_b64}'.encode()
sig_b64 = vault_client.sign_payload(signing_input)
sig_b64url = base64.urlsafe_b64encode(base64.b64decode(sig_b64)).decode().rstrip('=')

print(f'{header_b64}.{payload_b64}.{sig_b64url}')
" > /tmp/expired_token.txt
EXPIRED_TOKEN=$(cat /tmp/expired_token.txt)

expired_status=$(kubectl exec -n zt-apps deploy/ms1-profile-aggregator -- env EXPIRED_TOKEN="$EXPIRED_TOKEN" python -c "
import urllib.request, os
req = urllib.request.Request('http://ms2-employee-details:8000/api/employees/${UNKNOWN_EMPLOYEE_ID}', headers={'Authorization': 'Bearer ' + os.environ['EXPIRED_TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(e)
")
if [[ "$expired_status" == "401" || "$expired_status" == "403" ]]; then
  echo "PASS: expired token denied with $expired_status"
else
  echo "FAIL: expired token returned $expired_status, expected 401/403"
  exit 1
fi

echo "Checking MS1 database access denied..."
ms1_db_output=$(kubectl run ms1-psql-check -n zt-apps --rm -i --restart=Never --image=postgres:15-alpine --overrides='{"spec": {"serviceAccountName": "ms1-profile-aggregator-sa"}}' -- sh -c "PGPASSWORD=ms2_pass psql -h postgres.zt-data.svc.cluster.local -U ms2_app -d hr_directory -c 'SELECT 1;'" 2>&1 || true)
if echo "$ms1_db_output" | grep -q "server closed the connection unexpectedly"; then
  echo "PASS: MS1 database access denied"
else
  echo "FAIL: MS1 database access was not denied as expected"
  echo "Output: $ms1_db_output"
  exit 1
fi

echo "Checking outage fail-closed behavior..."
echo "Scaling down auth-service..."
kubectl scale deploy/auth-service -n zt-apps --replicas=0
kubectl wait --for=delete pod -l app=auth-service -n zt-apps --timeout=60s || true
status=$(curl_status "${APP_URL}/api/profile/${UNKNOWN_EMPLOYEE_ID}")
if [[ "$status" == "503" || "$status" == "401" || "$status" == "403" ]]; then
  echo "PASS: auth-service outage fails closed with $status"
else
  echo "FAIL: auth-service outage returned $status"
  kubectl scale deploy/auth-service -n zt-apps --replicas=1
  exit 1
fi
kubectl scale deploy/auth-service -n zt-apps --replicas=1
kubectl rollout status deploy/auth-service -n zt-apps

echo "Security negative-path checks passed."
