#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

UNKNOWN_ID="00000000-0000-0000-0000-000000000000"

write_section "Category 08: ExtAuthz Fail-Open"

# Save current replica count
ORIGINAL_REPLICAS=$(kubectl get deploy/auth-service -n zt-apps -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")

restore_auth() {
  echo "Restoring auth-service to ${ORIGINAL_REPLICAS} replicas..."
  kubectl scale deploy/auth-service -n zt-apps --replicas="$ORIGINAL_REPLICAS" &>/dev/null
  kubectl rollout status deploy/auth-service -n zt-apps --timeout=120s &>/dev/null || true
}
trap restore_auth EXIT

# Variant 4: Config check (run first, doesn't require scale-down)
failopen_found=$(kubectl get envoyfilter,authorizationpolicy -A -o yaml 2>/dev/null | grep -i "failOpen: true" || true)
if [[ -z "$failopen_found" ]]; then
  echo "PASS: failopen-config-check — no failOpen:true found"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "failopen-config-check" "N/A" "" ""
else
  echo "FAIL: failopen-config-check — failOpen:true present"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "failopen-config-check" "N/A" "" "$failopen_found"
fi

# Scale down auth-service
echo "Scaling down auth-service for fail-open test..."
kubectl scale deploy/auth-service -n zt-apps --replicas=0
kubectl wait --for=delete pod -l app=auth-service -n zt-apps --timeout=60s 2>/dev/null || true
sleep 3

# Variant 1: Protected route should be denied when auth is down
status=$(http_status "${APP_URL}/api/profile/${UNKNOWN_ID}")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app "${APP_URL}/api/profile/${UNKNOWN_ID}")
fi
run_variant "auth-down-denies-request" "$status" "403,503,401" "200" "$body"

# Variant 2: Public route should still work (offices GET is public via VirtualService or similar)
status=$(http_status "${APP_URL}/api/offices")
run_variant "auth-down-public-still-works" "$status" "200,503" "403,401"

# Variant 3: Health endpoint should still work
status=$(http_status "${APP_URL}/healthz")
run_variant "auth-down-healthz-works" "$status" "200,503" "403,401"

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
