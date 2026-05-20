#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

UNKNOWN_ID="00000000-0000-0000-0000-000000000000"

write_section "Category 01: Header Spoofing Past EnvoyFilter"

# Variant 1: Unauthenticated plain spoof
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}" -H "x-ms1-user: attacker" -H "x-ms1-role: hr_admin")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app -H "x-ms1-user: attacker" -H "x-ms1-role: hr_admin" "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "unauthenticated-plain-spoof" "$status" "401,403" "200" "$body"

# Variant 2: Case variation spoof
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}" -H "X-MS1-USER: attacker" -H "X-MS1-ROLE: hr_admin")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app -H "X-MS1-USER: attacker" -H "X-MS1-ROLE: hr_admin" "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "case-variation-spoof" "$status" "401,403" "200" "$body"

# Variant 3: x-mesh-identity forged alg:none
FORGED_HEADER=$(python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'attacker','roles':['hr_admin'],'iss':'auth-service'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
")
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}" -H "x-mesh-identity: ${FORGED_HEADER}")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app -H "x-mesh-identity: ${FORGED_HEADER}" "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "x-mesh-identity-forged-no-sig" "$status" "401,403" "200" "$body"

# Variant 4: x-platform-user spoof
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}" -H "x-platform-user: attacker" -H "x-platform-role: admin")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app -H "x-platform-user: attacker" -H "x-platform-role: admin" "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "x-platform-user-spoof" "$status" "401,403" "200" "$body"

# Variant 5: Duplicate header different case
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}" \
  -H "x-mesh-identity: ${FORGED_HEADER}" \
  -H "X-Mesh-Identity: ${FORGED_HEADER}")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app \
    -H "x-mesh-identity: ${FORGED_HEADER}" \
    -H "X-Mesh-Identity: ${FORGED_HEADER}" \
    "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "duplicate-header-one-cased" "$status" "401,403" "200" "$body"

# Variant 6: In-cluster direct injection via kubectl run
direct_output=$(kubectl run zt-header-spoof-01 -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' -H 'x-ms2-user: attacker' -H 'x-ms2-role: hr_admin' http://ms2-employee-details:8000/api/employees/${UNKNOWN_ID}" \
  2>/dev/null || true)
status=$(printf "%s\n" "$direct_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
body=""
if [[ "$status" == "200" ]]; then
  body=$(kubectl run zt-header-spoof-01b -n zt-apps --rm -i --restart=Never \
    --image=curlimages/curl:8.7.1 -- \
    sh -c "curl -s -H 'x-ms2-user: attacker' -H 'x-ms2-role: hr_admin' http://ms2-employee-details:8000/api/employees/${UNKNOWN_ID}" \
    2>/dev/null || true)
fi
run_variant "in-cluster-direct-injection" "$status" "401,403" "200" "$body"

# Variant 7: In-cluster mesh-identity alg:none
direct_output=$(kubectl run zt-header-spoof-02 -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' -H 'x-mesh-identity: ${FORGED_HEADER}' http://ms2-employee-details:8000/api/employees/${UNKNOWN_ID}" \
  2>/dev/null || true)
status=$(printf "%s\n" "$direct_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
body=""
if [[ "$status" == "200" ]]; then
  body=$(kubectl run zt-header-spoof-02b -n zt-apps --rm -i --restart=Never \
    --image=curlimages/curl:8.7.1 -- \
    sh -c "curl -s -H 'x-mesh-identity: ${FORGED_HEADER}' http://ms2-employee-details:8000/api/employees/${UNKNOWN_ID}" \
    2>/dev/null || true)
fi
run_variant "in-cluster-mesh-identity-alg-none" "$status" "401,403" "200" "$body"

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
