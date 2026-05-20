#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

write_section "Category 12: Istio Configuration Audit"

# Variant 1: istioctl analyze
if command -v istioctl &>/dev/null; then
  analyze_output=$(istioctl analyze --all-namespaces 2>&1 || true)
  errors=$(echo "$analyze_output" | grep -c "Error" || true)
  warnings=$(echo "$analyze_output" | grep -c "Warning" || true)
  if [[ "$errors" -eq 0 ]]; then
    echo "PASS: istioctl-analyze — ${warnings} warnings, 0 errors"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "istioctl-analyze" "${warnings}W/0E" "" "$analyze_output"
  else
    echo "FAIL: istioctl-analyze — ${errors} errors found"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "istioctl-analyze" "${errors} errors" "" "$analyze_output"
  fi
else
  echo "ERROR: istioctl-analyze — istioctl not found"
  ((ERROR_COUNT++)) || true
fi

# Variant 2: Gateway prestrip filter presence
prestrip=$(kubectl get envoyfilter gateway-prestrip -n istio-system -o jsonpath='{.metadata.name}' 2>/dev/null || true)
if [[ "$prestrip" == "gateway-prestrip" ]]; then
  echo "PASS: gateway-prestrip-present — EnvoyFilter exists"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "gateway-prestrip-present" "exists" "" ""
else
  echo "FAIL: gateway-prestrip-present — EnvoyFilter missing"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "gateway-prestrip-present" "missing" "" "gateway-prestrip EnvoyFilter not found in istio-system"
fi

# Variant 3: RequestAuthentication coverage
ra_list=$(kubectl get requestauthentication -n zt-apps -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
expected_services=("ms1" "ms2" "ms3" "ms4" "ms5")
missing_ra=()
for svc in "${expected_services[@]}"; do
  if ! echo "$ra_list" | grep -q "$svc"; then
    missing_ra+=("$svc")
  fi
done
if [[ ${#missing_ra[@]} -eq 0 ]]; then
  echo "PASS: request-auth-coverage — all services covered"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "request-auth-coverage" "5/5" "" ""
else
  echo "FAIL: request-auth-coverage — missing: ${missing_ra[*]}"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "request-auth-coverage" "${#missing_ra[@]} missing" "" "Missing RequestAuthentication for: ${missing_ra[*]}"
fi

# Variant 4: Default-deny check (no ALLOW-all policies)
allow_all=$(kubectl get authorizationpolicy -A -o json 2>/dev/null | \
  jq -r '.items[] | select(.spec.rules == null and .spec.action == "ALLOW") | .metadata.namespace + "/" + .metadata.name' 2>/dev/null || true)
if [[ -z "$allow_all" ]]; then
  echo "PASS: default-deny-check — no permissive ALLOW-all policies"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "default-deny-check" "OK" "" ""
else
  echo "FAIL: default-deny-check — ALLOW-all policies found"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "default-deny-check" "found" "" "$allow_all"
fi

# Variant 5: ExtAuthz path coverage
extauthz_gw=$(kubectl get authorizationpolicy -n zt-apps -o yaml 2>/dev/null | grep -c "auth-service-extauthz" || true)
if [[ "$extauthz_gw" -gt 0 ]]; then
  echo "PASS: extauthz-path-coverage — ExtAuthz referenced in policies"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "extauthz-path-coverage" "${extauthz_gw} refs" "" ""
else
  # Check in gateway-level config
  extauthz_istio=$(kubectl get envoyfilter -A -o yaml 2>/dev/null | grep -c "ext_authz" || true)
  if [[ "$extauthz_istio" -gt 0 ]]; then
    echo "PASS: extauthz-path-coverage — ExtAuthz in EnvoyFilter config"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "extauthz-path-coverage" "envoyfilter" "" ""
  else
    echo "FAIL: extauthz-path-coverage — no ExtAuthz reference found"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "extauthz-path-coverage" "none" "" "No ext_authz reference found in policies or filters"
  fi
fi

# Variant 6: PeerAuthentication audit
pa_all=$(kubectl get peerauthentication -A -o json 2>/dev/null || true)
permissive_ns=$(echo "$pa_all" | jq -r '.items[] | select(.spec.mtls.mode != "STRICT") | .metadata.namespace + "/" + .metadata.name' 2>/dev/null || true)
if [[ -z "$permissive_ns" ]]; then
  echo "PASS: peer-auth-audit — all PeerAuth policies are STRICT"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "peer-auth-audit" "all STRICT" "" ""
else
  echo "FAIL: peer-auth-audit — non-STRICT policies found"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "peer-auth-audit" "non-STRICT" "" "$permissive_ns"
fi

# Variant 7: EnvoyFilter priority order
prestrip_priority=$(kubectl get envoyfilter gateway-prestrip -n istio-system -o jsonpath='{.spec.priority}' 2>/dev/null || echo "0")
if [[ "$prestrip_priority" -lt 0 ]]; then
  echo "PASS: envoyfilter-priority-order — prestrip priority=${prestrip_priority} (runs before authz)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "envoyfilter-priority-order" "priority=${prestrip_priority}" "" ""
else
  echo "FAIL: envoyfilter-priority-order — prestrip priority=${prestrip_priority} (may run after authz)"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "envoyfilter-priority-order" "priority=${prestrip_priority}" "" "Prestrip filter should have negative priority to run before ext_authz"
fi

# Variant 8: JWKS endpoint health
jwks_status=$(curl -s -o /dev/null -w "%{http_code}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "${APP_URL}/auth/jwks" 2>/dev/null || echo "000")
if [[ "$jwks_status" == "200" ]]; then
  echo "PASS: jwks-health — JWKS endpoint returns 200"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "jwks-health" "200" "" ""
else
  echo "FAIL: jwks-health — JWKS endpoint returns ${jwks_status}"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "jwks-health" "$jwks_status" "" "JWKS endpoint not healthy — token validation may fail"
fi

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
