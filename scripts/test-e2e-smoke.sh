#!/usr/bin/env bash
set -euo pipefail

APP_HOST="${APP_HOST:-app.localtest.me}"
IDP_HOST="${IDP_HOST:-idp.localtest.me}"
APP_URL="${APP_URL:-https://${APP_HOST}}"
IDP_URL="${IDP_URL:-https://${IDP_HOST}}"
RESOLVE_IP="${RESOLVE_IP:-127.0.0.1}"

curl_status() {
  local host="$1"
  shift
  curl -s -o /dev/null -w "%{http_code}" -k --resolve "${host}:443:${RESOLVE_IP}" "$@"
}

echo "Checking gateway health..."
status=$(curl_status "$APP_HOST" "${APP_URL}/healthz")
[[ "$status" == "200" ]] || { echo "FAIL: gateway health returned ${status}"; exit 1; }
echo "PASS: gateway health returned 200"

echo "Checking auth login redirects to public Keycloak host..."
location=$(curl -s -o /dev/null -w "%{redirect_url}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" "${APP_URL}/auth/login")
case "$location" in
  "${IDP_URL}"/*) echo "PASS: login redirects to ${IDP_HOST}" ;;
  *) echo "FAIL: login redirected to ${location}"; exit 1 ;;
esac

echo "Checking Keycloak OIDC discovery route..."
status=$(curl_status "$IDP_HOST" "${IDP_URL}/realms/istio-security-poc/.well-known/openid-configuration")
[[ "$status" == "200" ]] || { echo "FAIL: Keycloak discovery returned ${status}"; exit 1; }
echo "PASS: Keycloak discovery returned 200"

echo "Checking auth-service JWKS route..."
status=$(curl_status "$APP_HOST" "${APP_URL}/auth/jwks")
[[ "$status" == "200" ]] || { echo "FAIL: JWKS returned ${status}"; exit 1; }
echo "PASS: JWKS returned 200"

ALICE_ID="${ALICE_ID:-66fff187-7648-53fc-89a3-e62da432c943}"

echo "Checking it_admin profile access with public fields and hardware assets..."
IVAN_TOKEN=$(curl -s -X POST "${IDP_URL}/realms/istio-security-poc/protocol/openid-connect/token" \
  -k --resolve "${IDP_HOST}:443:${RESOLVE_IP}" \
  -d "client_id=auth-service" \
  -d "client_secret=auth-service-client-secret-local-poc" \
  -d "username=ivan.itadmin" \
  -d "password=ivan-password" \
  -d "grant_type=password" | jq -r .access_token)

if [[ -z "$IVAN_TOKEN" || "$IVAN_TOKEN" == "null" ]]; then
  echo "FAIL: could not obtain Keycloak token for ivan.itadmin"
  exit 1
fi

profile_response=$(curl -s -w "\n%{http_code}" -k --resolve "${APP_HOST}:443:${RESOLVE_IP}" \
  -H "Authorization: Bearer ${IVAN_TOKEN}" \
  "${APP_URL}/api/profile/${ALICE_ID}")
profile_body=$(printf "%s\n" "$profile_response" | sed '$d')
profile_status=$(printf "%s\n" "$profile_response" | tail -n 1)

[[ "$profile_status" == "200" ]] || { echo "FAIL: it_admin profile query returned ${profile_status}"; exit 1; }

employee_ssn=$(printf "%s" "$profile_body" | jq -r '.employee.ssn // empty')
employee_salary=$(printf "%s" "$profile_body" | jq -r '.employee.base_salary // empty')
assets_count=$(printf "%s" "$profile_body" | jq -r '.assets | length')
first_serial=$(printf "%s" "$profile_body" | jq -r '.assets[0].serial_number // empty')

if [[ -n "$employee_ssn" || -n "$employee_salary" ]]; then
  echo "FAIL: it_admin profile exposed sensitive HR fields"
  exit 1
fi

if [[ "$assets_count" -lt 1 ]]; then
  echo "FAIL: it_admin profile returned no hardware assets"
  exit 1
fi

if [[ "$first_serial" == "***"* ]]; then
  echo "FAIL: it_admin profile returned masked hardware serial"
  exit 1
fi

echo "PASS: it_admin profile returned public employee fields and full hardware assets"

echo "E2E smoke checks passed."
