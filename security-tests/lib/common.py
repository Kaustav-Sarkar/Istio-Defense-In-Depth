"""Shared helpers for Python-based security attack tests."""

import base64
import json
import os
import subprocess
import sys

import jwt
import requests

APP_HOST = os.environ.get("APP_HOST", "app.localtest.me")
IDP_HOST = os.environ.get("IDP_HOST", "idp.localtest.me")
APP_URL = os.environ.get("APP_URL", f"https://{APP_HOST}")
IDP_URL = os.environ.get("IDP_URL", f"https://{IDP_HOST}")
RESOLVE_IP = os.environ.get("RESOLVE_IP", "127.0.0.1")
REPORT_FILE = os.environ.get("REPORT_FILE", "")

PASS_COUNT = 0
FAIL_COUNT = 0
ERROR_COUNT = 0


def get_keycloak_token(user: str, password: str) -> str:
    resp = requests.post(
        f"{IDP_URL}/realms/istio-security-poc/protocol/openid-connect/token",
        data={
            "client_id": "auth-service",
            "client_secret": "auth-service-client-secret-local-poc",
            "username": user,
            "password": password,
            "grant_type": "password",
        },
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_mesh_token_via_kubectl(kc_token: str, path: str) -> str:
    script = (
        "import urllib.request, os\n"
        f"req = urllib.request.Request('http://localhost:8000/verify{path}', "
        "headers={'Authorization': 'Bearer ' + os.environ['TOKEN']})\n"
        "try:\n"
        "    with urllib.request.urlopen(req) as response:\n"
        "        print(response.headers.get('x-mesh-identity'))\n"
        "except Exception as e:\n"
        "    pass\n"
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/auth-service", "--",
         "env", f"TOKEN={kc_token}", "python", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip()


def decode_jwt_unverified(token: str) -> tuple:
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def forge_alg_none(token: str) -> str:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def forge_hs256_with_pubkey(token: str, pubkey_pem: str) -> str:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    header["alg"] = "HS256"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{new_payload}".encode()
    import hmac
    import hashlib
    sig = hmac.HMAC(pubkey_pem.encode(), signing_input, hashlib.sha256).digest()
    new_sig = _b64url_encode(sig)
    return f"{new_header}.{new_payload}.{new_sig}"


def forge_kid_injection(token: str, kid_value: str) -> str:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    header["kid"] = kid_value
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def forge_wrong_audience(token: str, new_aud: str) -> str:
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    payload["aud"] = [new_aud]
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}."


def forge_jwk_header_injection(token: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    pub_numbers = private_key.public_key().public_numbers()

    def _int_to_b64url(n, length):
        return _b64url_encode(n.to_bytes(length, "big"))

    jwk = {
        "kty": "RSA",
        "n": _int_to_b64url(pub_numbers.n, 256),
        "e": _int_to_b64url(pub_numbers.e, 3),
    }

    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    header["jwk"] = jwk
    header["alg"] = "RS256"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = parts[1]
    signing_input = f"{new_header}.{payload_b64}".encode()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    new_sig = _b64url_encode(sig)
    return f"{new_header}.{payload_b64}.{new_sig}"


def forge_expired_token(token: str) -> str:
    import time
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    payload["exp"] = int(time.time()) - 3600
    payload["iat"] = int(time.time()) - 7200
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}."


def forge_wrong_act_sub(token: str, new_act_sub: str) -> str:
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    payload["act"] = {"sub": new_act_sub}
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}."


def kubectl_exec_status(namespace: str, deploy: str, url: str, headers: dict = None) -> str:
    header_args = ""
    if headers:
        for k, v in headers.items():
            header_args += f", '{k}': '{v}'"
    script = (
        "import urllib.request, os\n"
        f"req = urllib.request.Request('{url}', headers={{'_placeholder': '1'{header_args}}})\n"
        "del req.headers['_placeholder']\n"
        "try:\n"
        "    with urllib.request.urlopen(req) as response:\n"
        "        print(response.status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "except Exception as e:\n"
        "    print('000')\n"
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", namespace, f"deploy/{deploy}", "--",
         "python", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip()


def append_section(report_file: str, heading: str):
    if not report_file:
        return
    with open(report_file, "a") as f:
        f.write(f"\n## {heading}\n\n")


def write_verdict(report_file: str, variant: str, verdict_val: str,
                  status: str, headers: str = "", body: str = ""):
    if not report_file:
        return
    with open(report_file, "a") as f:
        f.write(f"### Variant: {variant}\n")
        f.write(f"**Verdict:** {verdict_val} | **Status:** {status}")
        if headers:
            f.write(f" | **Headers:** {headers}")
        f.write("\n")
        if verdict_val == "VULNERABLE" and body:
            f.write(f"**Evidence:**\n```\n{body}\n```\n")
        f.write("\n")


def run_variant(label: str, actual_status: str, secure_codes: list,
                vuln_codes: list, body: str = "") -> str:
    global PASS_COUNT, FAIL_COUNT, ERROR_COUNT

    if not actual_status or actual_status == "000":
        print(f"ERROR: {label} — connection failed")
        ERROR_COUNT += 1
        write_verdict(REPORT_FILE, label, "ERROR", actual_status, "", "Connection failed")
        return "ERROR"

    if actual_status in secure_codes:
        print(f"PASS: {label} — SECURE ({actual_status})")
        PASS_COUNT += 1
        write_verdict(REPORT_FILE, label, "SECURE", actual_status)
        return "SECURE"

    if actual_status in vuln_codes:
        print(f"FAIL: {label} — VULNERABLE ({actual_status})")
        FAIL_COUNT += 1
        write_verdict(REPORT_FILE, label, "VULNERABLE", actual_status, "", body)
        return "VULNERABLE"

    print(f"PASS: {label} — unexpected status {actual_status} (not in vulnerable set)")
    PASS_COUNT += 1
    write_verdict(REPORT_FILE, label, "SECURE", actual_status)
    return "SECURE"


def print_summary():
    total = PASS_COUNT + FAIL_COUNT + ERROR_COUNT
    print(f"\nResults: {PASS_COUNT} PASS, {FAIL_COUNT} FAIL, {ERROR_COUNT} ERROR (total {total})")
    return ERROR_COUNT == 0
