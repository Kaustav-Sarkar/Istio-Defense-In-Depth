#!/usr/bin/env bash
# Shared helpers for security attack test scripts

APP_HOST="${APP_HOST:-app.localtest.me}"
IDP_HOST="${IDP_HOST:-idp.localtest.me}"
APP_URL="${APP_URL:-https://${APP_HOST}}"
IDP_URL="${IDP_URL:-https://${IDP_HOST}}"
RESOLVE_IP="${RESOLVE_IP:-127.0.0.1}"

PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

curl_app() {
  curl -s -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "$@"
}

curl_idp() {
  curl -s -k --resolve "${IDP_HOST}:443:${RESOLVE_IP}" "$@"
}

get_keycloak_token() {
  local user="$1"
  local pass="$2"
  curl_idp -X POST \
    "${IDP_URL}/realms/istio-security-poc/protocol/openid-connect/token" \
    -d "client_id=auth-service" \
    -d "client_secret=auth-service-client-secret-local-poc" \
    -d "username=${user}" \
    -d "password=${pass}" \
    -d "grant_type=password" | jq -r .access_token
}

get_mesh_token() {
  local kc_token="$1"
  local path="$2"
  kubectl exec -n zt-apps deploy/auth-service -- env TOKEN="$kc_token" python -c "
import urllib.request, os
req = urllib.request.Request('http://localhost:8000/verify${path}', headers={'Authorization': 'Bearer ' + os.environ['TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.headers.get('x-mesh-identity'))
except Exception as e:
    pass
"
}

http_status() {
  local url="$1"
  shift
  curl -s -o /dev/null -w "%{http_code}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "$@" "$url"
}

http_full() {
  local url="$1"
  shift
  local tmpfile
  tmpfile=$(mktemp)
  local status
  status=$(curl -s -D "$tmpfile" -o /dev/null -w "%{http_code}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "$@" "$url")
  local headers
  headers=$(cat "$tmpfile")
  rm -f "$tmpfile"
  printf "%s\n---HEADERS---\n%s" "$status" "$headers"
}

verdict() {
  local label="$1"
  local actual_status="$2"
  local secure_codes="$3"
  local vuln_codes="$4"

  if [[ -z "$actual_status" || "$actual_status" == "000" ]]; then
    echo "ERROR: ${label} — connection failed"
    ((ERROR_COUNT++)) || true
    return
  fi

  local IFS=','
  for code in $secure_codes; do
    if [[ "$actual_status" == "$code" ]]; then
      echo "PASS: ${label} — SECURE (${actual_status})"
      ((PASS_COUNT++)) || true
      return
    fi
  done

  for code in $vuln_codes; do
    if [[ "$actual_status" == "$code" ]]; then
      echo "FAIL: ${label} — VULNERABLE (${actual_status})"
      ((FAIL_COUNT++)) || true
      return
    fi
  done

  echo "PASS: ${label} — unexpected status ${actual_status} (not in vulnerable set)"
  ((PASS_COUNT++)) || true
}

write_section() {
  local heading="$1"
  if [[ -n "${REPORT_FILE:-}" ]]; then
    printf "\n## %s\n\n" "$heading" >> "$REPORT_FILE"
  fi
}

write_variant() {
  local verdict_val="$1"
  local label="$2"
  local status="$3"
  local headers="${4:-}"
  local body="${5:-}"

  if [[ -z "${REPORT_FILE:-}" ]]; then
    return
  fi

  printf "### Variant: %s\n" "$label" >> "$REPORT_FILE"
  printf "**Verdict:** %s | **Status:** %s" "$verdict_val" "$status" >> "$REPORT_FILE"
  if [[ -n "$headers" ]]; then
    printf " | **Headers:** %s" "$headers" >> "$REPORT_FILE"
  fi
  printf "\n" >> "$REPORT_FILE"

  if [[ "$verdict_val" == "VULNERABLE" && -n "$body" ]]; then
    printf "**Evidence:**\n\`\`\`\n%s\n\`\`\`\n" "$body" >> "$REPORT_FILE"
  fi
  printf "\n" >> "$REPORT_FILE"
}

run_variant() {
  local label="$1"
  local actual_status="$2"
  local secure_codes="$3"
  local vuln_codes="$4"
  local response_body="${5:-}"

  local result=""
  local IFS=','

  if [[ -z "$actual_status" || "$actual_status" == "000" ]]; then
    result="ERROR"
    echo "ERROR: ${label} — connection failed"
    ((ERROR_COUNT++)) || true
    write_variant "ERROR" "$label" "$actual_status" "" "Connection failed"
    return
  fi

  for code in $secure_codes; do
    if [[ "$actual_status" == "$code" ]]; then
      result="SECURE"
      break
    fi
  done

  if [[ -z "$result" ]]; then
    for code in $vuln_codes; do
      if [[ "$actual_status" == "$code" ]]; then
        result="VULNERABLE"
        break
      fi
    done
  fi

  if [[ -z "$result" ]]; then
    result="SECURE"
  fi

  if [[ "$result" == "SECURE" ]]; then
    echo "PASS: ${label} — SECURE (${actual_status})"
    ((PASS_COUNT++)) || true
    write_variant "SECURE" "$label" "$actual_status" "" ""
  else
    echo "FAIL: ${label} — VULNERABLE (${actual_status})"
    ((FAIL_COUNT++)) || true
    write_variant "VULNERABLE" "$label" "$actual_status" "" "$response_body"
  fi
}
