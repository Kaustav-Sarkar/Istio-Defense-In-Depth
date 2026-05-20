#!/usr/bin/env bash
set -euo pipefail

# Complete Vault Transit key rotation for mesh-identity.
# This performs both the rotation AND bumps min_decryption_version to invalidate
# old key versions from the JWKS endpoint.
#
# Usage:
#   ./scripts/rotate-vault-key.sh          # rotate and immediately invalidate old keys
#   ./scripts/rotate-vault-key.sh --grace  # rotate but keep old key valid for one token TTL (5 min)

GRACE_MODE=false
if [[ "${1:-}" == "--grace" ]]; then
  GRACE_MODE=true
fi

echo "=== Vault Transit Key Rotation ==="

ROOT_TOKEN=$(kubectl get secret vault-root-token -n zt-security -o jsonpath='{.data.token}' | base64 -d)
if [[ -z "$ROOT_TOKEN" ]]; then
  echo "FAIL: Could not retrieve vault root token"
  exit 1
fi

VAULT_CMD="VAULT_TOKEN=$ROOT_TOKEN VAULT_ADDR=http://127.0.0.1:8200"

# Get current state
BEFORE=$(kubectl exec -n zt-security deploy/vault -- sh -c "$VAULT_CMD vault read -format=json transit/keys/mesh-identity")
OLD_LATEST=$(echo "$BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['latest_version'])")
OLD_MIN=$(echo "$BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['min_decryption_version'])")
echo "Before: latest=$OLD_LATEST, min_decryption_version=$OLD_MIN"

# Step 1: Rotate the key (creates new version, does not invalidate old)
echo "Rotating key..."
kubectl exec -n zt-security deploy/vault -- sh -c "$VAULT_CMD vault write -f transit/keys/mesh-identity/rotate" > /dev/null

# Get new latest
AFTER=$(kubectl exec -n zt-security deploy/vault -- sh -c "$VAULT_CMD vault read -format=json transit/keys/mesh-identity")
NEW_LATEST=$(echo "$AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['latest_version'])")
echo "New key version: $NEW_LATEST"

# Step 2: Bump min_decryption_version to invalidate old keys
if [[ "$GRACE_MODE" == "true" ]]; then
  echo "Grace mode: waiting 5 minutes for in-flight tokens to expire before invalidating old key..."
  echo "(Old key v${OLD_LATEST} remains valid during this window)"
  sleep 300
fi

echo "Bumping min_decryption_version to $NEW_LATEST..."
kubectl exec -n zt-security deploy/vault -- sh -c "$VAULT_CMD vault write transit/keys/mesh-identity/config min_decryption_version=$NEW_LATEST" > /dev/null

# Verify
FINAL=$(kubectl exec -n zt-security deploy/vault -- sh -c "$VAULT_CMD vault read -format=json transit/keys/mesh-identity")
FINAL_MIN=$(echo "$FINAL" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['min_decryption_version'])")
FINAL_LATEST=$(echo "$FINAL" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['latest_version'])")
KEYS_COUNT=$(echo "$FINAL" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['data']['keys']))")

echo ""
echo "=== Rotation Complete ==="
echo "  latest_version:        $FINAL_LATEST"
echo "  min_decryption_version: $FINAL_MIN"
echo "  active keys in JWKS:   $KEYS_COUNT"
echo ""
echo "Old key versions have been removed from the JWKS endpoint."
echo "Istio sidecars will pick up the new JWKS on next refresh (default: 20 min)."
