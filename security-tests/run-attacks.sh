#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATEGORIES_DIR="${SCRIPT_DIR}/categories"
REPORTS_DIR="${SCRIPT_DIR}/reports"

declare -A CATEGORY_MAP=(
  [01]="01-header-spoofing"
  [02]="02-jwt-attacks"
  [03]="03-token-replay"
  [04]="04-path-normalization"
  [05]="05-ssrf"
  [06]="06-debug-endpoints"
  [07]="07-rls-scope-leak"
  [08]="08-extauthz-failopen"
  [09]="09-cerbos-attr-spoofing"
  [10]="10-mtls-enforcement"
  [11]="11-static-analysis"
  [12]="12-istio-config-audit"
)

declare -A SLUG_TO_NUM=(
  [header-spoofing]="01"
  [jwt-attacks]="02"
  [token-replay]="03"
  [path-normalization]="04"
  [ssrf]="05"
  [debug-endpoints]="06"
  [rls-scope-leak]="07"
  [extauthz-failopen]="08"
  [cerbos-attr-spoofing]="09"
  [mtls-enforcement]="10"
  [static-analysis]="11"
  [istio-config-audit]="12"
)

# --- Argument Parsing ---
SELECTED=()
if [[ $# -eq 0 ]]; then
  for num in $(printf '%s\n' "${!CATEGORY_MAP[@]}" | sort); do
    SELECTED+=("$num")
  done
else
  for arg in "$@"; do
    if [[ -n "${CATEGORY_MAP[$arg]:-}" ]]; then
      SELECTED+=("$arg")
    elif [[ -n "${SLUG_TO_NUM[$arg]:-}" ]]; then
      SELECTED+=("${SLUG_TO_NUM[$arg]}")
    else
      echo "ERROR: Unknown category '$arg'"
      echo "Usage: $0 [01|02|...|12|header-spoofing|jwt-attacks|...]"
      exit 1
    fi
  done
fi

# --- Prerequisite Checks ---
echo "=== Prerequisite Checks ==="

MISSING_TOOLS=()
for tool in kubectl jq python3 curl istioctl; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_TOOLS+=("$tool")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo "ERROR: Missing tools: ${MISSING_TOOLS[*]}"
  exit 1
fi

# Check Python dependencies
python3 -c "import jwt, cryptography, requests" 2>/dev/null || {
  echo "ERROR: Missing Python packages. Run: pip install -r ${SCRIPT_DIR}/requirements.txt"
  exit 1
}

# Check cluster connectivity
if ! kubectl get nodes &>/dev/null; then
  echo "ERROR: Cannot reach Kubernetes cluster"
  exit 1
fi

# Check key namespaces have running pods
for ns in zt-apps zt-security zt-data zt-identity; do
  running=$(kubectl get pods -n "$ns" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
  if [[ "$running" -eq 0 ]]; then
    echo "ERROR: No running pods in namespace $ns"
    exit 1
  fi
done

echo "All prerequisites satisfied."
echo ""

# --- Report Setup ---
mkdir -p "$REPORTS_DIR"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export REPORT_FILE="${REPORTS_DIR}/attack-report-${TIMESTAMP//:/}.md"

cat > "$REPORT_FILE" <<EOF
# Security Attack Test Report
**Run:** ${TIMESTAMP} | **Cluster:** $(kubectl config current-context) | **Categories:** ${#SELECTED[@]}/12

## Summary
| # | Category | Status | Detail |
|---|----------|--------|--------|
EOF

# --- Execute Categories ---
declare -A RESULTS
TOTAL_ERRORS=0

for num in "${SELECTED[@]}"; do
  category="${CATEGORY_MAP[$num]}"
  category_name="${category#*-}"
  echo "=== Category ${num}: ${category_name} ==="

  test_script=""
  if [[ -f "${CATEGORIES_DIR}/${category}/test.sh" ]]; then
    test_script="${CATEGORIES_DIR}/${category}/test.sh"
  elif [[ -f "${CATEGORIES_DIR}/${category}/test.py" ]]; then
    test_script="${CATEGORIES_DIR}/${category}/test.py"
  else
    echo "ERROR: No test script found for ${category}"
    RESULTS[$num]="ERROR|no test script"
    ((TOTAL_ERRORS++)) || true
    continue
  fi

  output=""
  if [[ "$test_script" == *.sh ]]; then
    output=$(bash "$test_script" 2>&1) || true
  else
    output=$(python3 "$test_script" 2>&1) || true
  fi

  echo "$output"

  pass_count=$(echo "$output" | grep -c "^PASS:" || true)
  fail_count=$(echo "$output" | grep -c "^FAIL:" || true)
  error_count=$(echo "$output" | grep -c "^ERROR:" || true)

  if [[ "$error_count" -gt 0 ]]; then
    RESULTS[$num]="ERROR|${pass_count}P/${fail_count}F/${error_count}E"
    ((TOTAL_ERRORS++)) || true
  elif [[ "$fail_count" -gt 0 ]]; then
    RESULTS[$num]="VULNERABLE|${pass_count}P/${fail_count}F"
  else
    RESULTS[$num]="SECURE|${pass_count}/${pass_count}"
  fi

  echo ""
done

# --- Write Summary Table ---
SUMMARY_FILE=$(mktemp)
for num in "${SELECTED[@]}"; do
  category="${CATEGORY_MAP[$num]}"
  category_name="${category#*-}"
  result="${RESULTS[$num]:-ERROR|unknown}"
  status="${result%%|*}"
  detail="${result#*|}"
  echo "| ${num} | ${category_name} | ${status} | ${detail} |" >> "$SUMMARY_FILE"
done

# Insert summary into report (after the table header)
TEMP_REPORT=$(mktemp)
head -8 "$REPORT_FILE" > "$TEMP_REPORT"
cat "$SUMMARY_FILE" >> "$TEMP_REPORT"
tail -n +9 "$REPORT_FILE" >> "$TEMP_REPORT"
mv "$TEMP_REPORT" "$REPORT_FILE"
rm -f "$SUMMARY_FILE"

echo "=== Complete ==="
echo "Report: ${REPORT_FILE}"
echo "Categories: ${#SELECTED[@]} | Errors: ${TOTAL_ERRORS}"

if [[ "$TOTAL_ERRORS" -gt 0 ]]; then
  exit 1
fi
exit 0
