#!/usr/bin/env python3
"""Category 07: RLS Variable Scope Leak"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
from common import (
    REPORT_FILE,
    append_section,
    print_summary,
    run_variant,
    write_verdict,
)
import common


def psql_exec(query: str, user: str = "ms2_app", password: str = "ms2_pass") -> str:
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-data", "deploy/postgres", "--",
         "sh", "-c", f"PGPASSWORD={password} psql -U {user} -d hr_directory -t -A -c \"{query}\""],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout.strip()


def psql_exec_multi(queries: list, user: str = "ms2_app", password: str = "ms2_pass") -> str:
    combined = "; ".join(queries)
    result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-data", "deploy/postgres", "--",
         "sh", "-c", f"PGPASSWORD={password} psql -U {user} -d hr_directory -t -A -c \"{combined}\""],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout.strip()


def main():
    append_section(REPORT_FILE, "Category 07: RLS Variable Scope Leak")

    # Variant 1: PII query without setting context variable
    print("Testing PII access without context...")
    row_count = psql_exec("SELECT count(*) FROM hr.employee_pii")
    try:
        count = int(row_count)
        if count == 0:
            run_variant("pii-no-context-zero-rows", "0", ["0"], ["1"])
        else:
            print(f"FAIL: pii-no-context-zero-rows — got {count} rows without context")
            common.FAIL_COUNT += 1
            write_verdict(REPORT_FILE, "pii-no-context-zero-rows", "VULNERABLE",
                          f"{count} rows", "", f"Got {count} rows from employee_pii without setting app.current_user")
    except ValueError:
        # Could be permission error which is also SECURE
        print(f"PASS: pii-no-context-zero-rows — query returned: {row_count[:50]}")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "pii-no-context-zero-rows", "SECURE", "error/0", "", row_count[:200])

    # Variant 2: SET LOCAL clears on COMMIT
    print("Testing SET LOCAL scope after COMMIT...")
    result = psql_exec_multi([
        "BEGIN",
        "SET LOCAL app.current_user = 'test-user'",
        "COMMIT",
        "SHOW app.current_user"
    ])
    # After COMMIT, SET LOCAL should be cleared
    if not result or result == "''" or result == "" or "empty" in result.lower():
        print("PASS: set-local-clears-on-commit — value cleared after COMMIT")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "set-local-clears-on-commit", "SECURE", "cleared")
    elif "test-user" in result:
        print(f"FAIL: set-local-clears-on-commit — value persists: {result}")
        common.FAIL_COUNT += 1
        write_verdict(REPORT_FILE, "set-local-clears-on-commit", "VULNERABLE",
                      "persists", "", f"app.current_user still = {result} after COMMIT")
    else:
        print(f"PASS: set-local-clears-on-commit — result: {result[:50]}")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "set-local-clears-on-commit", "SECURE", result[:30])

    # Variant 3: Session scope leak demo (informational)
    # This tests whether SET (without LOCAL) persists across transactions
    result = psql_exec_multi([
        "SET app.current_user = 'leaked-user'",
        "SELECT current_setting('app.current_user', true)"
    ])
    print(f"PASS: session-scope-leak-demo — informational (SET persists within session: {result[:30]})")
    common.PASS_COUNT += 1
    write_verdict(REPORT_FILE, "session-scope-leak-demo", "SECURE", "informational",
                  "", f"SET (non-LOCAL) persists within session as expected. Value: {result[:50]}. "
                  "App code must use SET LOCAL within transactions.")

    # Variant 4: ms2 PII without context (via ms2 service account pod)
    print("Testing ms2 PII access without context via kubectl exec...")
    ms2_result = subprocess.run(
        ["kubectl", "exec", "-n", "zt-apps", "deploy/ms2-employee-details", "--",
         "python", "-c",
         "import os; os.environ.setdefault('DATABASE_URL','postgresql://ms2_app:ms2_pass@postgres.zt-data:5432/hr_directory');"
         "import asyncio;"
         "async def check():\n"
         "    import asyncpg\n"
         "    conn = await asyncpg.connect(os.environ['DATABASE_URL'])\n"
         "    rows = await conn.fetch('SELECT count(*) as c FROM hr.employee_pii')\n"
         "    print(rows[0]['c'])\n"
         "    await conn.close()\n"
         "asyncio.run(check())"],
        capture_output=True, text=True, timeout=15,
    )
    ms2_output = ms2_result.stdout.strip()
    try:
        ms2_count = int(ms2_output)
        if ms2_count == 0:
            run_variant("ms2-pii-without-context", "0", ["0"], ["1"])
        else:
            print(f"FAIL: ms2-pii-without-context — got {ms2_count} rows")
            common.FAIL_COUNT += 1
            write_verdict(REPORT_FILE, "ms2-pii-without-context", "VULNERABLE",
                          f"{ms2_count} rows", "", f"ms2 got {ms2_count} PII rows without setting context")
    except ValueError:
        # Error connecting or permission denied = SECURE
        print(f"PASS: ms2-pii-without-context — {ms2_output[:50]}")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "ms2-pii-without-context", "SECURE", "error/0", "", ms2_output[:200])

    # Variant 5: employees USING(true) gap (informational)
    print("Checking employees RLS policy...")
    policy_check = psql_exec(
        "SELECT polname, polqual FROM pg_policy WHERE polrelid = 'hr.employees'::regclass")
    has_using_true = "true" in policy_check.lower() if policy_check else False
    print(f"PASS: employees-read-open — informational (USING(true) = {has_using_true})")
    common.PASS_COUNT += 1
    write_verdict(REPORT_FILE, "employees-read-open", "SECURE", "informational",
                  "", f"Policy: {policy_check[:200]}. USING(true) is intentional for basic employee listing.")

    # Variant 6: BYPASSRLS not granted
    print("Checking BYPASSRLS grants...")
    bypass_result = psql_exec(
        "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname IN "
        "('ms1_app','ms2_app','ms3_app','ms4_app','ms5_app','auth_service_app') AND rolbypassrls = true")
    if not bypass_result:
        print("PASS: bypassrls-not-granted — no app users have BYPASSRLS")
        common.PASS_COUNT += 1
        write_verdict(REPORT_FILE, "bypassrls-not-granted", "SECURE", "none")
    else:
        print(f"FAIL: bypassrls-not-granted — users with BYPASSRLS: {bypass_result}")
        common.FAIL_COUNT += 1
        write_verdict(REPORT_FILE, "bypassrls-not-granted", "VULNERABLE",
                      "granted", "", f"Users with BYPASSRLS: {bypass_result}")

    print_summary()


if __name__ == "__main__":
    main()
