#!/usr/bin/env bash
set -euo pipefail

echo "Testing Vault Transit key rotation..."

TOKEN=$(curl -s -X POST https://idp.localtest.me/realms/istio-security-poc/protocol/openid-connect/token \
  -k --resolve idp.localtest.me:443:127.0.0.1 \
  -d "client_id=auth-service" \
  -d "client_secret=auth-service-client-secret-local-poc" \
  -d "username=alice.employee" \
  -d "password=alice-password" \
  -d "grant_type=password" | jq -r .access_token)

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "FAIL: Could not get Keycloak token"
  exit 1
fi

MESH_TOKEN_1=$(kubectl exec -n zt-apps deploy/auth-service -- env TOKEN="$TOKEN" python -c "
import urllib.request, os
req = urllib.request.Request('http://localhost:8000/verify/api/profile/11111111-1111-1111-1111-111111111111', headers={'Authorization': 'Bearer ' + os.environ['TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.headers.get('x-mesh-identity'))
except Exception as e:
    pass
")

if [ -z "$MESH_TOKEN_1" ]; then
  echo "FAIL: Could not mint mesh token 1"
  exit 1
fi

KID_1=$(python3 -c "import sys, json, base64; print(json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[0] + '==').decode('utf-8'))['kid'])" "$MESH_TOKEN_1")
echo "Minted token 1 with kid: $KID_1"

echo "Rotating Vault Transit key..."
ROOT_TOKEN=$(kubectl get secret vault-root-token -n zt-security -o jsonpath='{.data.token}' | base64 -d)
kubectl exec -n zt-security deploy/vault -- sh -c "VAULT_TOKEN=$ROOT_TOKEN VAULT_ADDR=http://127.0.0.1:8200 vault write -f transit/keys/mesh-identity/rotate"

echo "Bumping min_decryption_version to invalidate old key..."
NEW_LATEST=$(kubectl exec -n zt-security deploy/vault -- sh -c "VAULT_TOKEN=$ROOT_TOKEN VAULT_ADDR=http://127.0.0.1:8200 vault read -format=json transit/keys/mesh-identity" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['latest_version'])")
kubectl exec -n zt-security deploy/vault -- sh -c "VAULT_TOKEN=$ROOT_TOKEN VAULT_ADDR=http://127.0.0.1:8200 vault write transit/keys/mesh-identity/config min_decryption_version=$NEW_LATEST"

MESH_TOKEN_2=$(kubectl exec -n zt-apps deploy/auth-service -- env TOKEN="$TOKEN" python -c "
import urllib.request, os
req = urllib.request.Request('http://localhost:8000/verify/api/profile/11111111-1111-1111-1111-111111111111', headers={'Authorization': 'Bearer ' + os.environ['TOKEN']})
try:
    with urllib.request.urlopen(req) as response:
        print(response.headers.get('x-mesh-identity'))
except Exception as e:
    pass
")

if [ -z "$MESH_TOKEN_2" ]; then
  echo "FAIL: Could not mint mesh token 2"
  exit 1
fi

KID_2=$(python3 -c "import sys, json, base64; print(json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[0] + '==').decode('utf-8'))['kid'])" "$MESH_TOKEN_2")
echo "Minted token 2 with kid: $KID_2"

if [ "$KID_1" == "$KID_2" ]; then
  echo "FAIL: kid did not change after rotation!"
  exit 1
fi
echo "PASS: kid changed successfully from $KID_1 to $KID_2"

echo "Vault rotation test passed."
