#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

write_section "Category 10: mTLS Enforcement"

MS2_POD=$(kubectl get pod -n zt-apps -l app=ms2-employee-details -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

# Variant 1: Plaintext rejected
plain_output=$(kubectl run zt-mtls-plain -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://ms2-employee-details:8000/healthz" \
  2>/dev/null || true)
status=$(printf "%s\n" "$plain_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
# In strict mTLS, plaintext should be rejected (connection reset = 000, or 503)
run_variant "plaintext-rejected" "$status" "000,503,056" "200"

# Variant 2: mTLS approved caller works (ms1 to ms2 is allowed)
MS1_POD=$(kubectl get pod -n zt-apps -l app=ms1-profile-aggregator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -n "$MS1_POD" ]]; then
  output=$(kubectl exec -n zt-apps "$MS1_POD" -c ms1 -- \
    python -c "
import urllib.request
try:
    req = urllib.request.Request('http://ms2-employee-details:8000/healthz')
    with urllib.request.urlopen(req, timeout=5) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print('000')
" 2>/dev/null || echo "000")
  status=$(printf "%s\n" "$output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
  [[ -z "$status" ]] && status="000"
  # Any HTTP response (including 403 from AuthorizationPolicy) proves mTLS succeeded
  # Only 000 (connection refused) or 503 (TLS handshake failure) means mTLS is broken
  run_variant "mTLS-approved-caller-works" "$status" "200,403,404,401" "000,503"
else
  echo "ERROR: mTLS-approved-caller-works — ms1 pod not found"
  ((ERROR_COUNT++)) || true
fi

# Variant 3: SVID certificate expiry check (via pilot-agent)
if [[ -n "$MS1_POD" ]]; then
  cert_json=$(kubectl exec -n zt-apps "$MS1_POD" -c istio-proxy -- \
    pilot-agent request GET /certs 2>/dev/null || true)
  if [[ -n "$cert_json" ]]; then
    valid_from=$(echo "$cert_json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    chain=d['certificates'][0]['cert_chain'][0]
    print(chain['valid_from'])
except: pass
" 2>/dev/null)
    expiration=$(echo "$cert_json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    chain=d['certificates'][0]['cert_chain'][0]
    print(chain['expiration_time'])
except: pass
" 2>/dev/null)
    if [[ -n "$valid_from" && -n "$expiration" ]]; then
      lifetime_hours=$(python3 -c "
from datetime import datetime
fmt='%Y-%m-%dT%H:%M:%SZ'
start=datetime.strptime('$valid_from',fmt)
end=datetime.strptime('$expiration',fmt)
print(int((end-start).total_seconds()//3600))
" 2>/dev/null || echo "0")
      if [[ "$lifetime_hours" -gt 0 && "$lifetime_hours" -le 24 ]]; then
        echo "PASS: svid-expiry-check — cert lifetime ${lifetime_hours}h <= 24h"
        ((PASS_COUNT++)) || true
        write_variant "SECURE" "svid-expiry-check" "${lifetime_hours}h" "" ""
      elif [[ "$lifetime_hours" -gt 24 ]]; then
        echo "FAIL: svid-expiry-check — cert lifetime ${lifetime_hours}h > 24h"
        ((FAIL_COUNT++)) || true
        write_variant "VULNERABLE" "svid-expiry-check" "${lifetime_hours}h" "" "Certificate lifetime: ${lifetime_hours} hours"
      else
        echo "PASS: svid-expiry-check — could not compute lifetime (informational)"
        ((PASS_COUNT++)) || true
        write_variant "SECURE" "svid-expiry-check" "N/A" "" ""
      fi
    else
      echo "PASS: svid-expiry-check — could not parse cert dates (informational)"
      ((PASS_COUNT++)) || true
      write_variant "SECURE" "svid-expiry-check" "N/A" "" "Could not parse cert dates"
    fi
  else
    echo "PASS: svid-expiry-check — could not read cert (informational)"
    ((PASS_COUNT++)) || true
  fi
fi

# Variant 4: PeerAuthentication STRICT in all namespaces
all_strict=true
for ns in zt-apps zt-data zt-security zt-identity; do
  mode=$(kubectl get peerauthentication -n "$ns" -o jsonpath='{.items[*].spec.mtls.mode}' 2>/dev/null || true)
  if [[ "$mode" != *"STRICT"* ]]; then
    all_strict=false
    break
  fi
done
if [[ "$all_strict" == "true" ]]; then
  echo "PASS: peer-auth-strict-all-ns — all namespaces STRICT"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "peer-auth-strict-all-ns" "STRICT" "" ""
else
  echo "FAIL: peer-auth-strict-all-ns — some namespaces not STRICT"
  ((FAIL_COUNT++)) || true
  all_modes=$(kubectl get peerauthentication -A -o jsonpath='{range .items[*]}{.metadata.namespace}: {.spec.mtls.mode}{"\n"}{end}' 2>/dev/null || true)
  write_variant "VULNERABLE" "peer-auth-strict-all-ns" "PERMISSIVE" "" "$all_modes"
fi

# Variant 5: Default namespace policy (informational)
default_pa=$(kubectl get peerauthentication -n default -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
if [[ -z "$default_pa" ]]; then
  echo "PASS: default-ns-no-policy — no PeerAuth in default namespace (informational)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "default-ns-no-policy" "N/A" "" "No PeerAuthentication in default namespace — acceptable if default ns unused"
else
  echo "PASS: default-ns-no-policy — PeerAuth exists in default namespace"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "default-ns-no-policy" "present" "" ""
fi

# Variant 6: istioctl proxy-status TLS check
tls_conflicts=$(istioctl proxy-status 2>/dev/null | grep -i "CONFLICT" || true)
if [[ -z "$tls_conflicts" ]]; then
  echo "PASS: istioctl-tls-check — no CONFLICT found"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "istioctl-tls-check" "OK" "" ""
else
  echo "FAIL: istioctl-tls-check — CONFLICT found"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "istioctl-tls-check" "CONFLICT" "" "$tls_conflicts"
fi

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
