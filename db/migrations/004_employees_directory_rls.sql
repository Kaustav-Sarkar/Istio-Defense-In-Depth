-- Open hr.employees directory reads to any authenticated principal.
-- Cerbos controls field-level masking; PII/financials tables keep stricter RLS.

DROP POLICY IF EXISTS employees_visibility ON hr.employees;
CREATE POLICY employees_visibility ON hr.employees
  USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');
