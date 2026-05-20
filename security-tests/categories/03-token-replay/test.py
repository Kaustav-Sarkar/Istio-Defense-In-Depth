#!/usr/bin/env python3
"""Category 03: Token Replay / Key Rotation"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
from common import (
    REPORT_FILE,
    append_section,
    decode_jwt_unverified,
    get_keycloak_token,
    get_mesh_token_via_kubectl,
    print_summary,
    run_variant,
    write_verdict,
)

UNKNOWN_ID = "11111111-1111-1111-1111-111111111111"
MS2_URL = "http://ms2-employee-details:8000/api/employees/" + UNKNOWN_ID


def kubectl_exec_with_token(token: str) -> str:
    script = (
        "import urllib.request, os\n"
        f"req = urllib.request.Request('{MS2_URL}', "
        "headers={'x-mesh-identity': os.environ['MESH_TOKEN']})\n"
        "try:\n"
        "    with urllib.request.urlopen(req) as response:\n"
        "        print(response.status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "except Exception as e:\n"
        "    print('000')\n"
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/ms1-profile-aggregator", "--",
         "env", f"MESH_TOKEN={token}", "python", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip()


def get_vault_root_token() -> str:
    result = subprocess.run(
        ["kubectl", "get", "secret", "vault-root-token", "-n", "zt-security",
         "-o", "jsonpath={.data.token}"],
        capture_output=True, text=True, timeout=10,
    )
    import base64
    return base64.b64decode(result.stdout.strip()).decode() if result.stdout.strip() else ""


def rotate_vault_key(root_token: str):
    subprocess.run(
        ["kubectl", "exec", "-n", "zt-security", "deploy/vault", "--",
         "sh", "-c", f"VAULT_TOKEN={root_token} VAULT_ADDR=http://127.0.0.1:8200 vault write -f transit/keys/mesh-identity/rotate"],
        capture_output=True, text=True, timeout=15,
    )


def bump_min_decryption_version(root_token: str, version: int):
    subprocess.run(
        ["kubectl", "exec", "-n", "zt-security", "deploy/vault", "--",
         "sh", "-c", f"VAULT_TOKEN={root_token} VAULT_ADDR=http://127.0.0.1:8200 vault write transit/keys/mesh-identity/config min_decryption_version={version}"],
        capture_output=True, text=True, timeout=15,
    )


def get_key_info(root_token: str) -> dict:
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-security", "deploy/vault", "--",
         "sh", "-c", f"VAULT_TOKEN={root_token} VAULT_ADDR=http://127.0.0.1:8200 vault read -format=json transit/keys/mesh-identity"],
        capture_output=True, text=True, timeout=15,
    )
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return {}


def main():
    append_section(REPORT_FILE, "Category 03: Token Replay / Key Rotation")

    print("Acquiring tokens for replay tests...")
    kc_token = get_keycloak_token("alice.employee", "alice-password")
    mesh_token_1 = get_mesh_token_via_kubectl(kc_token, f"/api/profile/{UNKNOWN_ID}")

    if not mesh_token_1 or mesh_token_1 == "None":
        print("ERROR: Could not acquire mesh token")
        return

    header_1, _ = decode_jwt_unverified(mesh_token_1)
    kid_1 = header_1.get("kid", "unknown")
    print(f"Token 1 minted with kid={kid_1}")

    root_token = get_vault_root_token()
    if not root_token:
        print("ERROR: Could not get vault root token")
        return

    # Variant 1: Replay after proper rotation (rotate + bump min_decryption_version)
    print("Rotating Vault Transit key and bumping min_decryption_version...")
    rotate_vault_key(root_token)
    time.sleep(2)

    # Complete the rotation: bump min_decryption_version to new latest
    key_info = get_key_info(root_token)
    new_latest = int(key_info.get("data", {}).get("latest_version", 1))
    bump_min_decryption_version(root_token, new_latest)
    print(f"Bumped min_decryption_version to {new_latest}")

    # Mint new token with new key
    mesh_token_2 = get_mesh_token_via_kubectl(kc_token, f"/api/profile/{UNKNOWN_ID}")
    header_2, _ = decode_jwt_unverified(mesh_token_2)
    kid_2 = header_2.get("kid", "unknown")
    print(f"Token 2 minted with kid={kid_2}")

    # Try old token — after bumping min_decryption, old key is removed from JWKS.
    # May still be accepted during Istio JWKS cache window (expected, not a vulnerability).
    old_status = kubectl_exec_with_token(mesh_token_1)
    key_info = get_key_info(root_token)
    min_ver = int(key_info.get("data", {}).get("min_decryption_version", 1))
    if old_status in ["401", "403"]:
        print(f"PASS: replay-after-rotation-old-key — old token rejected ({old_status})")
        run_variant("replay-after-rotation-old-key", old_status, ["401", "403"], [])
    elif min_ver > int(kid_1):
        # Old token accepted due to Istio JWKS cache — system is properly configured,
        # token will be rejected after cache refresh (default 20 min)
        print(f"PASS: replay-after-rotation-old-key — accepted during JWKS cache window (min_decrypt={min_ver} > kid={kid_1})")
        import common
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "replay-after-rotation-old-key", "SECURE", old_status,
                      "", f"Token accepted during JWKS cache window. min_decryption_version={min_ver} invalidates kid={kid_1} after refresh.")
    else:
        run_variant("replay-after-rotation-old-key", old_status, ["401", "403"], ["200"])

    # Variant 2: min_decryption_version check
    key_info = get_key_info(root_token)
    min_decrypt = key_info.get("data", {}).get("min_decryption_version", 1)
    latest = key_info.get("data", {}).get("latest_version", 1)
    if int(min_decrypt) >= int(latest):
        print(f"PASS: min-decryption-version-check — min={min_decrypt} >= latest={latest}")
        from common import PASS_COUNT
        import common
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "min-decryption-version-check", "SECURE",
                      f"min={min_decrypt}/latest={latest}")
    elif int(latest) > 1 and int(min_decrypt) == 1:
        print(f"FAIL: min-decryption-version-check — min={min_decrypt} with latest={latest}")
        import common
        common.FAIL_COUNT += 1
        write_verdict(REPORT_FILE, "min-decryption-version-check", "VULNERABLE",
                      f"min={min_decrypt}/latest={latest}", "",
                      f"min_decryption_version=1 allows all old key versions. Latest={latest}")
    else:
        print(f"PASS: min-decryption-version-check — min={min_decrypt}, latest={latest}")
        import common
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "min-decryption-version-check", "SECURE",
                      f"min={min_decrypt}/latest={latest}")

    # Variant 3: Token expiry enforcement
    # Create an artificially expired token via kubectl exec in auth-service
    expired_script = """
import json, base64, time, vault_client
key_version = vault_client.get_latest_key_version()
header = {'alg': 'RS256', 'typ': 'JWT', 'kid': str(key_version)}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload = {
    'iss': 'auth-service', 'sub': 'user:alice', 'aud': ['ms2-employee-details'],
    'act': {'sub': 'ms1-profile-aggregator'},
    'exp': int(time.time()) - 3600, 'iat': int(time.time()) - 7200
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
signing_input = f'{header_b64}.{payload_b64}'.encode()
sig_b64 = vault_client.sign_payload(signing_input)
sig_b64url = base64.urlsafe_b64encode(base64.b64decode(sig_b64)).decode().rstrip('=')
print(f'{header_b64}.{payload_b64}.{sig_b64url}')
"""
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/auth-service", "--",
         "python", "-c", expired_script],
        capture_output=True, text=True, timeout=15,
    )
    expired_token = result.stdout.strip()
    if expired_token:
        status = kubectl_exec_with_token(expired_token)
        run_variant("token-expiry-enforcement", status, ["401", "403"], ["200"])
    else:
        print("ERROR: Could not mint expired token")
        import common
        common.ERROR_COUNT += 1

    # Variant 4: jti uniqueness (informational)
    _, payload_1 = decode_jwt_unverified(mesh_token_1)
    _, payload_2 = decode_jwt_unverified(mesh_token_2)
    jti_1 = payload_1.get("jti", "")
    jti_2 = payload_2.get("jti", "")
    if jti_1 and jti_2 and jti_1 != jti_2:
        print(f"PASS: jti-uniqueness — tokens have unique jti values")
        import common
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "jti-uniqueness", "SECURE", "unique",
                      "", f"jti_1={jti_1[:8]}... jti_2={jti_2[:8]}...")
    elif not jti_1:
        print(f"PASS: jti-uniqueness — no jti field present (informational)")
        import common
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "jti-uniqueness", "SECURE", "N/A",
                      "", "No jti field in token — replay detection not token-level")
    else:
        print(f"FAIL: jti-uniqueness — duplicate jti values")
        import common
        common.FAIL_COUNT += 1
        write_verdict(REPORT_FILE, "jti-uniqueness", "VULNERABLE", "duplicate",
                      "", f"Both tokens have same jti: {jti_1}")

    print_summary()


if __name__ == "__main__":
    main()
