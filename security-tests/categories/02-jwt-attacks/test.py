#!/usr/bin/env python3
"""Category 02: JWT Attack Playbook"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
from common import (
    REPORT_FILE,
    append_section,
    decode_jwt_unverified,
    forge_alg_none,
    forge_expired_token,
    forge_jwk_header_injection,
    forge_kid_injection,
    forge_wrong_act_sub,
    forge_wrong_audience,
    get_keycloak_token,
    get_mesh_token_via_kubectl,
    print_summary,
    run_variant,
)

UNKNOWN_ID = "00000000-0000-0000-0000-000000000000"
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


def main():
    append_section(REPORT_FILE, "Category 02: JWT Attack Playbook")

    print("Acquiring legitimate mesh token...")
    kc_token = get_keycloak_token("alice.employee", "alice-password")
    mesh_token = get_mesh_token_via_kubectl(kc_token, f"/api/profile/{UNKNOWN_ID}")

    if not mesh_token or mesh_token == "None":
        print("ERROR: Could not acquire mesh token")
        return

    # Variant 1: alg=none
    forged = forge_alg_none(mesh_token)
    status = kubectl_exec_with_token(forged)
    run_variant("alg-none", status, ["401", "403"], ["200"])

    # Variant 2: RS256 to HS256 (needs JWKS public key)
    jwks_output = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/auth-service", "--",
         "python", "-c", "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/auth/jwks').read().decode())"],
        capture_output=True, text=True, timeout=15,
    )
    if jwks_output.stdout.strip():
        import json
        try:
            jwks = json.loads(jwks_output.stdout.strip())
            if jwks.get("keys"):
                from cryptography.hazmat.primitives.asymmetric import rsa
                pub_pem = "fake-public-key-for-hmac-attack"
                # Forge HS256 token using public key bytes as HMAC secret
                import base64, hashlib, hmac as hmac_mod
                parts = mesh_token.split(".")
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                header["alg"] = "HS256"
                new_header = base64.urlsafe_b64encode(
                    json.dumps(header, separators=(",", ":")).encode()
                ).decode().rstrip("=")
                signing_input = f"{new_header}.{parts[1]}".encode()
                # Use first JWK 'n' value as key material
                key_material = jwks["keys"][0].get("n", "").encode()
                sig = hmac_mod.new(key_material, signing_input, hashlib.sha256).digest()
                new_sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
                hs256_token = f"{new_header}.{parts[1]}.{new_sig}"
                status = kubectl_exec_with_token(hs256_token)
                run_variant("rs256-to-hs256", status, ["401", "403"], ["200"])
            else:
                run_variant("rs256-to-hs256", "000", ["401", "403"], ["200"])
        except (json.JSONDecodeError, KeyError):
            run_variant("rs256-to-hs256", "000", ["401", "403"], ["200"])
    else:
        run_variant("rs256-to-hs256", "000", ["401", "403"], ["200"])

    # Variant 3: kid path traversal
    forged = forge_kid_injection(mesh_token, "../../../../dev/null")
    status = kubectl_exec_with_token(forged)
    run_variant("kid-path-traversal", status, ["401", "403"], ["200"])

    # Variant 4: kid SQL injection
    forged = forge_kid_injection(mesh_token, "1 OR 1=1")
    status = kubectl_exec_with_token(forged)
    run_variant("kid-sql-injection", status, ["401", "403"], ["200"])

    # Variant 5: JWK header injection
    forged = forge_jwk_header_injection(mesh_token)
    status = kubectl_exec_with_token(forged)
    run_variant("jwk-header-injection", status, ["401", "403"], ["200"])

    # Variant 6: Expired token
    forged = forge_expired_token(mesh_token)
    status = kubectl_exec_with_token(forged)
    run_variant("expired-token", status, ["401", "403"], ["200"])

    # Variant 7: Wrong audience (token for ms3 sent to ms2)
    forged = forge_wrong_audience(mesh_token, "ms3-hardware-assets")
    status = kubectl_exec_with_token(forged)
    run_variant("wrong-audience", status, ["401", "403"], ["200"])

    # Variant 8: Wrong act.sub
    forged = forge_wrong_act_sub(mesh_token, "attacker-service")
    status = kubectl_exec_with_token(forged)
    run_variant("wrong-act-sub", status, ["401", "403"], ["200"])

    print_summary()


if __name__ == "__main__":
    main()
