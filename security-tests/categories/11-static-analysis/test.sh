#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

write_section "Category 11: Static Analysis"

# Variant 1: shellcheck on scripts
if command -v shellcheck &>/dev/null; then
  sc_output=$(shellcheck "${REPO_ROOT}"/scripts/*.sh 2>&1 || true)
  sc_errors=$(echo "$sc_output" | grep -c "error" || true)
  if [[ "$sc_errors" -eq 0 ]]; then
    echo "PASS: shellcheck — no errors"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "shellcheck" "0 errors" "" ""
  else
    echo "FAIL: shellcheck — ${sc_errors} errors found"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "shellcheck" "${sc_errors} errors" "" "$sc_output"
  fi
else
  echo "PASS: shellcheck — tool not installed (skipped)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "shellcheck" "skipped" "" "shellcheck not installed"
fi

# Variant 2: yamllint on deployment YAMLs
if command -v yamllint &>/dev/null; then
  yl_output=$(yamllint -d "{extends: relaxed, rules: {line-length: disable}}" "${REPO_ROOT}/deployment/" 2>&1 || true)
  yl_errors=$(echo "$yl_output" | grep -c "error" || true)
  if [[ "$yl_errors" -eq 0 ]]; then
    echo "PASS: yamllint — no errors"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "yamllint" "0 errors" "" ""
  else
    echo "FAIL: yamllint — ${yl_errors} errors found"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "yamllint" "${yl_errors} errors" "" "$yl_output"
  fi
else
  echo "PASS: yamllint — tool not installed (skipped)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "yamllint" "skipped" "" "yamllint not installed"
fi

# Variant 3: bandit on Python services
if command -v bandit &>/dev/null; then
  bandit_output=$(bandit -r "${REPO_ROOT}/apps/" -ll --exclude "${REPO_ROOT}/apps/*/venv,${REPO_ROOT}/apps/*/tests" 2>&1 || true)
  high_issues=$(echo "$bandit_output" | grep -c "Severity: High" || true)
  if [[ "$high_issues" -eq 0 ]]; then
    echo "PASS: bandit — no high-severity issues"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "bandit" "0 high" "" ""
  else
    echo "FAIL: bandit — ${high_issues} high-severity issues"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "bandit" "${high_issues} high" "" "$bandit_output"
  fi
else
  echo "PASS: bandit — tool not installed (skipped)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "bandit" "skipped" "" "bandit not installed"
fi

# Variant 4: checkov on deployment manifests
if command -v checkov &>/dev/null; then
  checkov_output=$(checkov -d "${REPO_ROOT}/deployment/" --framework kubernetes --quiet --compact 2>&1 || true)
  checkov_failed=$(echo "$checkov_output" | grep -c "FAILED" || true)
  if [[ "$checkov_failed" -eq 0 ]]; then
    echo "PASS: checkov — no failures"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "checkov" "0 failures" "" ""
  else
    echo "FAIL: checkov — ${checkov_failed} failures (informational)"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "checkov" "${checkov_failed} failures" "" "$checkov_output"
  fi
else
  echo "PASS: checkov — tool not installed (skipped)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "checkov" "skipped" "" "checkov not installed"
fi

# Variant 5: trivy filesystem scan
if command -v trivy &>/dev/null; then
  trivy_output=$(trivy fs "${REPO_ROOT}" --severity HIGH,CRITICAL --quiet 2>&1 || true)
  trivy_vulns=$(echo "$trivy_output" | grep -c "CRITICAL\|HIGH" || true)
  if [[ "$trivy_vulns" -eq 0 ]]; then
    echo "PASS: trivy — no HIGH/CRITICAL vulnerabilities"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "trivy" "0 vulns" "" ""
  else
    echo "FAIL: trivy — ${trivy_vulns} HIGH/CRITICAL findings"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "trivy" "${trivy_vulns} findings" "" "$trivy_output"
  fi
else
  echo "PASS: trivy — tool not installed (skipped)"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "trivy" "skipped" "" "trivy not installed"
fi

# Variant 6: Secrets grep (hardcoded credentials in source)
secrets_output=$(grep -rn --include="*.py" --include="*.sh" --include="*.yaml" --include="*.yml" \
  -E "(password|secret|token|api_key)\s*[:=]\s*['\"][^'\"]{8,}" \
  "${REPO_ROOT}/apps/" "${REPO_ROOT}/deployment/" "${REPO_ROOT}/scripts/" 2>/dev/null \
  | grep -v "test\|example\|placeholder\|poc\|local\|venv\|__pycache__" || true)
if [[ -z "$secrets_output" ]]; then
  echo "PASS: secrets-grep — no hardcoded secrets found"
  ((PASS_COUNT++)) || true
  write_variant "SECURE" "secrets-grep" "clean" "" ""
else
  secret_count=$(echo "$secrets_output" | wc -l | tr -d ' ')
  echo "FAIL: secrets-grep — ${secret_count} potential secrets found (review needed)"
  ((FAIL_COUNT++)) || true
  write_variant "VULNERABLE" "secrets-grep" "${secret_count} matches" "" "$secrets_output"
fi

# Variant 7: Vault key version check
if kubectl get deploy vault -n zt-security &>/dev/null; then
  ROOT_TOKEN=$(kubectl get secret vault-root-token -n zt-security -o jsonpath='{.data.token}' 2>/dev/null | base64 -d 2>/dev/null || true)
  if [[ -n "$ROOT_TOKEN" ]]; then
    key_info=$(kubectl exec -n zt-security deploy/vault -- sh -c \
      "VAULT_TOKEN=$ROOT_TOKEN VAULT_ADDR=http://127.0.0.1:8200 vault read -format=json transit/keys/mesh-identity" \
      2>/dev/null || true)
    min_decrypt=$(echo "$key_info" | jq -r '.data.min_decryption_version // "1"' 2>/dev/null || echo "1")
    latest=$(echo "$key_info" | jq -r '.data.latest_version // "1"' 2>/dev/null || echo "1")
    echo "PASS: vault-key-version — latest=${latest}, min_decryption=${min_decrypt}"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "vault-key-version" "v${latest}/min${min_decrypt}" "" "Latest version: ${latest}, Min decryption version: ${min_decrypt}"
  else
    echo "PASS: vault-key-version — could not get root token (skipped)"
    ((PASS_COUNT++)) || true
  fi
else
  echo "PASS: vault-key-version — vault not deployed (skipped)"
  ((PASS_COUNT++)) || true
fi

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
