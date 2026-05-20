#!/usr/bin/env bash
set -euo pipefail

EMPLOYEE_ID="${EMPLOYEE_ID:-11111111-1111-1111-1111-111111111111}"

echo "Seeding one HR row as database owner..."
kubectl exec -i -n zt-data postgres-0 -- sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" >/dev/null" <<SQL
INSERT INTO hr.employees (
  id, first_name, last_name, work_email, job_title, department, hire_date, status
) VALUES (
  '${EMPLOYEE_ID}', 'Rls', 'Probe', 'rls.probe@example.com', 'Engineer', 'Engineering', '2026-01-01', 'Active'
) ON CONFLICT (id) DO NOTHING;
SQL

echo "Checking runtime role without RLS context sees no protected rows..."
no_context_count=$(kubectl exec -n zt-data postgres-0 -- sh -c "PGPASSWORD=ms2_pass psql -h localhost -U ms2_app -d hr_directory -tAc 'SELECT count(*) FROM hr.employees;'")
if [[ "${no_context_count//[[:space:]]/}" != "0" ]]; then
  echo "FAIL: ms2_app saw ${no_context_count} rows without RLS context"
  exit 1
fi
echo "PASS: missing RLS context returned zero rows"

echo "Checking runtime role with authenticated context sees directory rows..."
with_context_output=$(kubectl exec -i -n zt-data postgres-0 -- sh -c "PGPASSWORD=ms2_pass psql -h localhost -U ms2_app -d hr_directory -qAt" <<SQL
BEGIN;
SET LOCAL app.current_user_id = '${EMPLOYEE_ID}';
SET LOCAL app.current_roles = 'employee';
SELECT count(*) FROM hr.employees;
COMMIT;
SQL
)
with_context_count=$(printf "%s\n" "$with_context_output" | awk '/^[[:space:]]*[0-9]+[[:space:]]*$/ {print $1; exit}')
if [[ "${with_context_count//[[:space:]]/}" -lt 1 ]]; then
  echo "FAIL: ms2_app saw ${with_context_count} rows with authenticated RLS context, expected at least 1"
  exit 1
fi
echo "PASS: authenticated RLS context returned ${with_context_count} directory row(s)"

echo "Checking it_admin context can see hardware assets..."
it_admin_assets_count=$(kubectl exec -i -n zt-data postgres-0 -- sh -c "PGPASSWORD=ms3_pass psql -h localhost -U ms3_app -d hr_directory -qAt" <<'SQL'
BEGIN;
SET LOCAL app.current_user_id = 'ivan-uuid';
SET LOCAL app.current_roles = 'employee,it_admin';
SELECT count(*) FROM it.hardware_assets;
COMMIT;
SQL
)
it_admin_assets_count=$(printf "%s\n" "$it_admin_assets_count" | awk '/^[[:space:]]*[0-9]+[[:space:]]*$/ {print $1; exit}')
it_admin_assets_count="${it_admin_assets_count//[[:space:]]/}"
if [[ -z "$it_admin_assets_count" || "$it_admin_assets_count" -lt 1 ]]; then
  echo "FAIL: it_admin context saw ${it_admin_assets_count:-0} hardware asset rows, expected at least 1"
  exit 1
fi
echo "PASS: it_admin context returned ${it_admin_assets_count} hardware asset row(s)"

echo "RLS checks passed."
