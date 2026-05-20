#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

write_section "Category 05: SSRF"

# Variant 1: UUID parameter path traversal injection
status=$(http_status "${APP_URL}/api/profile/../../etc/passwd")
run_variant "uuid-param-injection" "$status" "422,404,400,401,403" "200"

# Variant 2: UUID encoded slash
status=$(http_status "${APP_URL}/api/profile/..%2f..%2fetc%2fpasswd")
run_variant "uuid-encoded-slash" "$status" "422,404,400,401,403" "200"

# Variant 3: Internal vault from ephemeral pod (unauthorized SA)
vault_output=$(kubectl run zt-ssrf-vault -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' http://vault.zt-security:8200/v1/sys/health" \
  2>/dev/null || true)
status=$(printf "%s\n" "$vault_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
run_variant "internal-vault-from-ephemeral" "$status" "403,000,503" "200"

# Variant 4: Kubernetes API from ephemeral pod
k8s_output=$(kubectl run zt-ssrf-k8s -n zt-apps --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' -k https://kubernetes.default.svc/api/v1/namespaces" \
  2>/dev/null || true)
status=$(printf "%s\n" "$k8s_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
run_variant "kubernetes-api-from-ephemeral" "$status" "403,401,000" "200"

# Variant 5: ms1 SA to vault
ms1_vault_output=$(kubectl run zt-ssrf-ms1-vault -n zt-apps --rm -i --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"ms1-profile-aggregator-sa"}}' \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' http://vault.zt-security:8200/v1/sys/health" \
  2>/dev/null || true)
status=$(printf "%s\n" "$ms1_vault_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
run_variant "ms1-sa-to-vault" "$status" "403,000,503" "200"

# Variant 6: ms1 SA to cerbos
ms1_cerbos_output=$(kubectl run zt-ssrf-ms1-cerbos -n zt-apps --rm -i --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"ms1-profile-aggregator-sa"}}' \
  --image=curlimages/curl:8.7.1 -- \
  sh -c "curl -s -o /dev/null -w '%{http_code}' http://cerbos.zt-security:3592/api/check" \
  2>/dev/null || true)
status=$(printf "%s\n" "$ms1_cerbos_output" | awk 'match($0, /[0-9][0-9][0-9]/) {print substr($0, RSTART, 3); exit}')
[[ -z "$status" ]] && status="000"
run_variant "ms1-sa-to-cerbos" "$status" "403,000,503" "200"

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
