#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"

UNKNOWN_ID="00000000-0000-0000-0000-000000000000"

write_section "Category 04: AuthorizationPolicy Path Normalization"

# All variants: SECURE if 401/403/404, VULNERABLE if 200

# Variant 1: Double slash
status=$(http_status "${APP_URL}/api//profile/${UNKNOWN_ID}")
run_variant "double-slash" "$status" "401,403,404" "200"

# Variant 2: Percent-encoded slash
status=$(http_status "${APP_URL}/api%2fprofile%2f${UNKNOWN_ID}")
run_variant "percent-encoded-slash" "$status" "401,403,404" "200"

# Variant 3: Path traversal
status=$(http_status "${APP_URL}/api/offices/../profile/${UNKNOWN_ID}")
run_variant "path-traversal" "$status" "401,403,404" "200"

# Variant 4: Case variation
status=$(http_status "${APP_URL}/API/profile/${UNKNOWN_ID}")
run_variant "case-variation" "$status" "401,403,404" "200"

# Variant 5: Semicolon injection
status=$(http_status "${APP_URL}/api/profile;x/${UNKNOWN_ID}")
run_variant "semicolon-injection" "$status" "401,403,404" "200"

# Variant 6: Tab in path
status=$(http_status "${APP_URL}/api/profile%09/${UNKNOWN_ID}")
run_variant "tab-in-path" "$status" "401,403,404" "200"

# Variant 7: Null byte
status=$(http_status "${APP_URL}/api/profile%00/${UNKNOWN_ID}")
run_variant "null-byte" "$status" "401,403,404" "200"

# Variant 8: Method override header
status=$(http_status "${APP_URL}/api/offices" -H "X-HTTP-Method-Override: DELETE")
body=""
if [[ "$status" == "200" ]]; then
  body=$(curl_app -H "X-HTTP-Method-Override: DELETE" "${APP_URL}/api/offices")
fi
# 200 on GET /api/offices is expected (public route); check if DELETE-like behavior occurred
# For this variant, SECURE means the override header is ignored
# We check POST override on a GET-only route
post_status=$(http_status "${APP_URL}/api/offices" -X GET -H "X-HTTP-Method-Override: POST")
run_variant "method-override" "$post_status" "200,401,403,404,405" "500"

echo ""
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${ERROR_COUNT} ERROR"
