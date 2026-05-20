-- Runtime roles for microservices
-- Phase 2 requires separating migration ownership from runtime roles

-- Application Roles
DO $$ BEGIN
    CREATE ROLE ms1_user WITH NOLOGIN;
    CREATE ROLE ms2_hr_role WITH NOLOGIN;
    CREATE ROLE ms3_it_role WITH NOLOGIN;
    CREATE ROLE ms4_public_readwrite_role WITH NOLOGIN;
    CREATE ROLE ms5_public_readwrite_role WITH NOLOGIN;
    CREATE ROLE auth_service_role WITH NOLOGIN;
    CREATE ROLE db_seeder_role WITH NOLOGIN;
    CREATE ROLE zt_migration_owner WITH NOLOGIN;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Application users (passwords should be injected, these are local POC defaults)
DO $$ BEGIN
    CREATE USER ms1_app WITH PASSWORD 'ms1_pass';
    CREATE USER ms2_app WITH PASSWORD 'ms2_pass';
    CREATE USER ms3_app WITH PASSWORD 'ms3_pass';
    CREATE USER ms4_app WITH PASSWORD 'ms4_pass';
    CREATE USER ms5_app WITH PASSWORD 'ms5_pass';
    CREATE USER auth_service_app WITH PASSWORD 'auth_pass';
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Grant roles to users
GRANT ms1_user TO ms1_app;
GRANT ms2_hr_role TO ms2_app;
GRANT ms3_it_role TO ms3_app;
GRANT ms4_public_readwrite_role TO ms4_app;
GRANT ms5_public_readwrite_role TO ms5_app;
GRANT auth_service_role TO auth_service_app;

-- Grant usage on schemas
GRANT USAGE ON SCHEMA hr TO ms2_hr_role;
GRANT USAGE ON SCHEMA it TO ms3_it_role;
GRANT USAGE ON SCHEMA public_data TO ms4_public_readwrite_role;
GRANT USAGE ON SCHEMA public_data TO ms5_public_readwrite_role;
GRANT USAGE ON SCHEMA auth TO auth_service_role;

-- Auth service needs CRUD on sessions
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.sessions TO auth_service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.oauth_states TO auth_service_role;

GRANT CONNECT ON DATABASE hr_directory TO ms1_app, ms2_app, ms3_app, ms4_app, ms5_app, auth_service_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON hr.employees TO ms2_hr_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON hr.employee_pii TO ms2_hr_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON hr.employee_financials TO ms2_hr_role;
GRANT REFERENCES ON hr.employees TO ms3_it_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON it.hardware_assets TO ms3_it_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public_data.company_holidays TO ms4_public_readwrite_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public_data.office_locations TO ms5_public_readwrite_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public_data TO ms4_public_readwrite_role, ms5_public_readwrite_role;

ALTER TABLE hr.employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE hr.employee_pii ENABLE ROW LEVEL SECURITY;
ALTER TABLE hr.employee_financials ENABLE ROW LEVEL SECURITY;
ALTER TABLE it.hardware_assets ENABLE ROW LEVEL SECURITY;

ALTER TABLE hr.employees FORCE ROW LEVEL SECURITY;
ALTER TABLE hr.employee_pii FORCE ROW LEVEL SECURITY;
ALTER TABLE hr.employee_financials FORCE ROW LEVEL SECURITY;
ALTER TABLE it.hardware_assets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS employees_visibility ON hr.employees;
CREATE POLICY employees_visibility ON hr.employees
  USING (
    current_setting('app.current_roles', true) LIKE '%hr_admin%'
    OR id::text = current_setting('app.current_user_id', true)
    OR manager_id::text = current_setting('app.current_user_id', true)
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');

DROP POLICY IF EXISTS employee_pii_visibility ON hr.employee_pii;
CREATE POLICY employee_pii_visibility ON hr.employee_pii
  USING (
    current_setting('app.current_roles', true) LIKE '%hr_admin%'
    OR employee_id::text = current_setting('app.current_user_id', true)
    OR EXISTS (
      SELECT 1 FROM hr.employees e
      WHERE e.id = employee_id
        AND e.manager_id::text = current_setting('app.current_user_id', true)
    )
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');

DROP POLICY IF EXISTS employee_financials_visibility ON hr.employee_financials;
CREATE POLICY employee_financials_visibility ON hr.employee_financials
  USING (
    current_setting('app.current_roles', true) LIKE '%hr_admin%'
    OR employee_id::text = current_setting('app.current_user_id', true)
    OR EXISTS (
      SELECT 1 FROM hr.employees e
      WHERE e.id = employee_id
        AND e.manager_id::text = current_setting('app.current_user_id', true)
    )
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');

DROP POLICY IF EXISTS hardware_assets_visibility ON it.hardware_assets;
CREATE POLICY hardware_assets_visibility ON it.hardware_assets
  USING (
    current_setting('app.current_roles', true) LIKE '%it_admin%'
    OR employee_id::text = current_setting('app.current_user_id', true)
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%it_admin%');
