#!/usr/bin/env bash
set -euo pipefail

RESULTS_FILE="docs/security-validation-results.md"

echo "# Security Validation Results" > "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Generated at: $(date -u)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

FAILED=0

run_and_capture() {
  local script_name="$1"
  echo "## $script_name" >> "$RESULTS_FILE"
  echo "\`\`\`text" >> "$RESULTS_FILE"
  echo "Running $script_name..."
  if ./scripts/"$script_name" >> "$RESULTS_FILE" 2>&1; then
    echo "PASS: $script_name"
  else
    echo "FAIL: $script_name"
    echo "FAIL: $script_name exited with error" >> "$RESULTS_FILE"
    FAILED=1
  fi
  echo "\`\`\`" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"
}

run_and_capture "test-python.sh"
run_and_capture "test-cerbos.sh"
run_and_capture "test-manifests.sh"
run_and_capture "test-e2e-smoke.sh"
run_and_capture "test-security-negative-paths.sh"
run_and_capture "test-rls.sh"
run_and_capture "test-vault-rotation.sh"

echo "Evidence collection complete. Results saved to $RESULTS_FILE"

if [ "$FAILED" -ne 0 ]; then
  echo "ERROR: One or more validation scripts failed."
  exit 1
fi
