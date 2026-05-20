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

echo "E2E smoke checks passed."
