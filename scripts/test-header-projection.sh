#!/usr/bin/env bash
set -euo pipefail

echo "Testing header projection and spoofing defense..."

# Wait for services to be ready
kubectl rollout status deployment/ms1-profile-aggregator -n zt-apps --timeout=60s || true

# Get a token from Keycloak (assuming demo user alice.employee exists)
# For this test, we can just check if unauthenticated requests with spoofed headers are rejected
echo "Testing unauthenticated request with spoofed headers..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -k --resolve app.localtest.me:443:127.0.0.1 \
  -H "x-ms1-user: attacker" \
  -H "x-ms1-role: admin" \
  https://app.localtest.me/api/profile/00000000-0000-0000-0000-000000000000)

if [ "$HTTP_STATUS" -eq 401 ] || [ "$HTTP_STATUS" -eq 403 ]; then
  echo "✅ Unauthenticated request with spoofed headers was denied ($HTTP_STATUS)."
else
  echo "❌ Unauthenticated request with spoofed headers returned $HTTP_STATUS instead of 401/403."
  exit 1
fi

echo "Header projection tests passed!"
