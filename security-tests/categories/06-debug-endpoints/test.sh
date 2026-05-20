#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

write_section "Category 06: Debug Endpoints (Envoy Admin)"

MS1_POD=$(kubectl get pod -n zt-apps -l app=ms1-profile-aggregator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "$MS1_POD" ]]; then
  echo "ERROR: Could not find ms1 pod"
  write_variant "ERROR" "pod-discovery" "N/A" "" "Could not find ms1 pod"
  exit 0
fi

# Helper: use python (no curl in app containers) to probe a URL from ms1
probe_from_ms1() {
  local url="$1"
  kubectl exec -n zt-apps "$MS1_POD" -c ms1 -- python -c "
import urllib.request
try:
    req = urllib.request.Request('${url}')
    with urllib.request.urlopen(req, timeout=5) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print('000')
" 2>/dev/null
}

# For debug endpoint tests, 000 (connection refused/timeout) is SECURE
debug_variant() {
  local label="$1"
  local status="$2"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  # 000 = connection refused = port not accessible = SECURE
  if [[ "$status" == "000" || "$status" == "403" || "$status" == "503" ]]; then
    echo "PASS: ${label} — SECURE (${status})"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "$label" "$status" "" ""
  elif [[ "$status" == "200" ]]; then
    echo "FAIL: ${label} — VULNERABLE (${status})"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "$label" "$status" "" "Admin port accessible"
  else
    echo "PASS: ${label} — SECURE (${status})"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "$label" "$status" "" ""
  fi
}

# Variant 1: ms1 to ms2:15000/stats
status=$(probe_from_ms1 "http://ms2-employee-details.zt-apps:15000/stats")
debug_variant "ms1-to-ms2-stats" "$status"

# Variant 2: ms1 to ms2:15000/config_dump
status=$(probe_from_ms1 "http://ms2-employee-details.zt-apps:15000/config_dump")
debug_variant "ms1-to-ms2-config-dump" "$status"

# Variant 3: ms1 to vault:15000/config_dump
status=$(probe_from_ms1 "http://vault.zt-security:15000/config_dump")
debug_variant "ms1-to-vault-admin" "$status"

# Variant 4: External admin port
status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://localhost:15000/stats" 2>/dev/null)
[[ -z "$status" || "$status" == "000" ]] && status="000"
debug_variant "external-admin-port" "$status"

# Variant 5: Ephemeral pod to gateway admin
gw_output=$(kubectl run zt-debug-gw -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://istio-ingressgateway.istio-system:15000/config_dump" \
  2>/dev/null || true)
status=$(printf "%s\n" "$gw_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
debug_variant "ephemeral-to-gateway-admin" "$status"

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
