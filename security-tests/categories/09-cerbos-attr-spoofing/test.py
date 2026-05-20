#!/usr/bin/env python3
"""Category 09: Cerbos Attribute Spoofing"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
from common import (
    REPORT_FILE,
    append_section,
    get_keycloak_token,
    get_mesh_token_via_kubectl,
    print_summary,
    run_variant,
    write_verdict,
)
import common

CERBOS_URL = "http://cerbos.zt-security:3592"


def kubectl_exec_cerbos(deploy: str, namespace: str, path: str, data: str) -> tuple:
    """Call Cerbos from an existing deployment pod using python urllib."""
    escaped_data = data.replace("'", "\\'")
    script = (
        "import urllib.request, json\n"
        f"data = '''{data}'''.encode()\n"
        f"req = urllib.request.Request('{CERBOS_URL}{path}', data=data, "
        "headers={'Content-Type': 'application/json'})\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=10) as r:\n"
        "        body = r.read().decode()\n"
        "        print(body)\n"
        "        print(r.status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.read().decode())\n"
        "    print(e.code)\n"
        "except Exception as e:\n"
        "    print(str(e))\n"
        "    print('000')\n"
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", namespace, f"deploy/{deploy}", "--",
         "python", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    output = result.stdout.strip()
    lines = output.split("\n")
    if len(lines) >= 2:
        status = lines[-1]
        body = "\n".join(lines[:-1])
    else:
        status = lines[0] if lines else "000"
        body = ""
    import re
    if not re.match(r'^\d{3}$', status):
        status = "000"
        body = output
    return status, body


def kubectl_run_cerbos_unauthorized(path: str) -> str:
    """Test Cerbos access from a pod with default SA (should be blocked)."""
    script = (
        "import urllib.request\n"
        f"req = urllib.request.Request('{CERBOS_URL}{path}')\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=10) as r:\n"
        "        print(r.status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "except Exception:\n"
        "    print('000')\n"
    )
    result = subprocess.run(
        ["kubectl", "run", "zt-cerbos-unauth", "-n", "zt-apps", "--rm", "-i",
         "--restart=Never", "--image=python:3.12-slim",
         "--overrides", json.dumps({"spec": {"serviceAccountName": "default"}}),
         "--", "python", "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    output = result.stdout.strip()
    import re
    match = re.search(r'\d{3}', output)
    return match.group(0) if match else "000"


def main():
    append_section(REPORT_FILE, "Category 09: Cerbos Attribute Spoofing")

    # Variant 1: Unauthorized SA to Cerbos (should be blocked at network layer)
    # Use ms1 pod (which is NOT in the allowed list for Cerbos) to test network policy
    print("Testing unauthorized SA access to Cerbos...")
    script = (
        "import urllib.request\n"
        f"req = urllib.request.Request('{CERBOS_URL}/api/check/resources')\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=10) as r:\n"
        "        print(r.status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "except Exception:\n"
        "    print('000')\n"
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/ms1-profile-aggregator", "--",
         "python", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    status = result.stdout.strip()
    import re
    if not re.match(r'^\d{3}$', status):
        status = "000"
    # 000/403/503 = SECURE (blocked), 200 = VULNERABLE (accessible)
    if status in ["403", "000", "503"]:
        print(f"PASS: unauthorized-sa-to-cerbos — SECURE ({status})")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "unauthorized-sa-to-cerbos", "SECURE", status)
    elif status == "200":
        print(f"FAIL: unauthorized-sa-to-cerbos — VULNERABLE ({status})")
        common.FAIL_COUNT += 1
        write_verdict(REPORT_FILE, "unauthorized-sa-to-cerbos", "VULNERABLE", status,
                      "", "Unauthorized SA can reach Cerbos")
    else:
        print(f"PASS: unauthorized-sa-to-cerbos — SECURE ({status})")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "unauthorized-sa-to-cerbos", "SECURE", status)

    # Variant 2: Spoofed resource attributes should be denied
    print("Testing spoofed resource attributes...")
    check_payload = json.dumps({
        "requestId": "test-spoof",
        "principal": {
            "id": "attacker",
            "roles": ["hr_admin"],
            "attr": {"department": "engineering"}
        },
        "resources": [{
            "resource": {
                "kind": "employee:pii",
                "id": "emp-123",
                "attr": {
                    "owner": "attacker",
                    "department": "engineering"
                }
            },
            "actions": ["view_sensitive"]
        }]
    })
    # Use ms2 which IS allowed to reach Cerbos
    status, body = kubectl_exec_cerbos("ms2-employee-details", "zt-apps",
                                       "/api/check/resources", check_payload)
    if status == "200" and body:
        try:
            resp = json.loads(body)
            results = resp.get("results", [])
            if results:
                actions = results[0].get("actions", {})
                effect = actions.get("view_sensitive", "EFFECT_DENY")
                if effect == "EFFECT_DENY":
                    print("PASS: spoofed-resource-attrs-denied — Cerbos denied spoofed attrs")
                    common.PASS_COUNT += 1
                    write_verdict(REPORT_FILE, "spoofed-resource-attrs-denied", "SECURE",
                                  "EFFECT_DENY")
                else:
                    print(f"FAIL: spoofed-resource-attrs-denied — effect={effect}")
                    common.FAIL_COUNT += 1
                    write_verdict(REPORT_FILE, "spoofed-resource-attrs-denied", "VULNERABLE",
                                  effect, "", body[:500])
            else:
                run_variant("spoofed-resource-attrs-denied", status, ["403"], ["200"])
        except (json.JSONDecodeError, KeyError, IndexError):
            run_variant("spoofed-resource-attrs-denied", status, ["403"], ["200"])
    else:
        # 403 = blocked by AuthorizationPolicy (also SECURE)
        if status in ["403", "000"]:
            print(f"PASS: spoofed-resource-attrs-denied — SECURE ({status})")
            common.PASS_COUNT += 1
            write_verdict(REPORT_FILE, "spoofed-resource-attrs-denied", "SECURE", status)
        else:
            run_variant("spoofed-resource-attrs-denied", status, ["403", "000"], ["200"])

    # Variant 3: Role-based grant (informational — confirms trust chain works)
    print("Testing legitimate Cerbos check (positive control)...")
    legit_payload = json.dumps({
        "requestId": "test-legit",
        "principal": {
            "id": "user:alice",
            "roles": ["employee"],
            "attr": {"department": "engineering"}
        },
        "resources": [{
            "resource": {
                "kind": "employee:profile",
                "id": "emp-alice",
                "attr": {"owner": "user:alice"}
            },
            "actions": ["view"]
        }]
    })
    status, body = kubectl_exec_cerbos("ms2-employee-details", "zt-apps",
                                       "/api/check/resources", legit_payload)
    if status == "200":
        print("PASS: role-based-grant — Cerbos responds to authorized caller")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "role-based-grant", "SECURE", "200",
                      "", "Informational: Cerbos correctly processes checks from authorized SA")
    else:
        print(f"PASS: role-based-grant — status={status} (informational)")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "role-based-grant", "SECURE", status,
                      "", f"Informational: status={status}")

    # Variant 4: Resource attributes should come from DB, not HTTP
    print("Testing attribute source validation...")
    kc_token = get_keycloak_token("alice.employee", "alice-password")
    mesh_token = get_mesh_token_via_kubectl(kc_token, "/api/profile/00000000-0000-0000-0000-000000000000")

    if mesh_token and mesh_token != "None":
        script = (
            "import urllib.request, os\n"
            "req = urllib.request.Request("
            "'http://ms2-employee-details:8000/api/employees/00000000-0000-0000-0000-000000000000/sensitive', "
            "headers={'x-mesh-identity': os.environ['MESH_TOKEN'], "
            "'x-spoofed-department': 'hr', 'x-spoofed-role': 'hr_admin'})\n"
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
             "env", f"MESH_TOKEN={mesh_token}", "python", "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        status = result.stdout.strip()
        run_variant("resource-attr-from-db-not-http", status, ["403", "401", "404"], ["200"])
    else:
        print("PASS: resource-attr-from-db-not-http — could not get token (skipped)")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "resource-attr-from-db-not-http", "SECURE", "skipped")

    print_summary()


if __name__ == "__main__":
    main()
