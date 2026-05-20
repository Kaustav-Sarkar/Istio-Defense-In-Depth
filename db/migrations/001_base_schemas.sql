-- Base schemas and domain tables as per Phase 2 requirements

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS hr;
CREATE SCHEMA IF NOT EXISTS it;
CREATE SCHEMA IF NOT EXISTS public_data;

-- Ensure public cannot mess with the schemas
REVOKE ALL ON SCHEMA hr FROM PUBLIC;
REVOKE ALL ON SCHEMA it FROM PUBLIC;
REVOKE ALL ON SCHEMA public_data FROM PUBLIC;

CREATE TABLE IF NOT EXISTS hr.employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    work_email VARCHAR(255) UNIQUE NOT NULL,
    work_phone VARCHAR(50),
    job_title VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    manager_id UUID REFERENCES hr.employees(id),
    hire_date DATE NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS hr.employee_pii (
    employee_id UUID PRIMARY KEY REFERENCES hr.employees(id),
    ssn VARCHAR(20) UNIQUE NOT NULL,
    date_of_birth DATE NOT NULL,
    personal_phone VARCHAR(50),
    home_address TEXT,
    gender VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS hr.employee_financials (
    employee_id UUID PRIMARY KEY REFERENCES hr.employees(id),
    base_salary DECIMAL(12, 2) NOT NULL,
    bonus DECIMAL(12, 2),
    bank_account_number VARCHAR(50),
    routing_number VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS it.hardware_assets (
    asset_tag VARCHAR(50) PRIMARY KEY,
    employee_id UUID REFERENCES hr.employees(id),
    device_type VARCHAR(50) NOT NULL,
    model_name VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100),
    mac_address VARCHAR(50),
    issue_date DATE NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS public_data.office_locations (
    id SERIAL PRIMARY KEY,
    city_name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    country_code VARCHAR(10) NOT NULL,
    capacity INT NOT NULL,
    status VARCHAR(50) DEFAULT 'Open',
    latitude DECIMAL(10, 7),
    longitude DECIMAL(10, 7),
    established_date VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS public_data.company_holidays (
    id SERIAL PRIMARY KEY,
    holiday_date DATE NOT NULL,
    holiday_name VARCHAR(100) NOT NULL,
    country_code VARCHAR(10)
);
