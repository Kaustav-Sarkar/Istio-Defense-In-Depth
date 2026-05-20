-- ==========================================
-- 1. Database Security & RBAC
-- ==========================================
-- Revoke default public access
REVOKE ALL ON DATABASE hr_directory FROM PUBLIC;

-- Create Service Accounts
CREATE USER ms2_user WITH PASSWORD 'ms2_secure_pass';
CREATE USER ms3_user WITH PASSWORD 'ms3_secure_pass';
CREATE USER ms4_user WITH PASSWORD 'ms4_secure_pass';
CREATE USER ms5_user WITH PASSWORD 'ms5_secure_pass';

-- Explicitly grant connect to the database
GRANT CONNECT ON DATABASE hr_directory TO ms2_user, ms3_user, ms4_user, ms5_user;

-- Create Schemas
CREATE SCHEMA hr;
CREATE SCHEMA it;
CREATE SCHEMA public_data;

-- Note: The 'auth' schema and Row-Level Security (RLS) policies are 
-- deferred to future Phase 3 platform work.

-- Grant Schema Usage
GRANT USAGE ON SCHEMA hr TO ms2_user, ms3_user;
GRANT USAGE ON SCHEMA it TO ms3_user;
GRANT USAGE ON SCHEMA public_data TO ms4_user, ms5_user;

-- MS3 needs REFERENCES on hr.employees for foreign key validation
GRANT REFERENCES ON hr.employees TO ms3_user;

-- ==========================================
-- 2. Table Definitions (Segregated Zero-Trust Schema)
-- ==========================================

-- Schema: HR (Public Directory Data)
CREATE TABLE hr.employees (
    id UUID PRIMARY KEY,
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

-- Schema: HR (Highly Sensitive Personal Data)
CREATE TABLE hr.employee_pii (
    employee_id UUID PRIMARY KEY REFERENCES hr.employees(id),
    ssn VARCHAR(20) UNIQUE NOT NULL,
    date_of_birth DATE NOT NULL,
    personal_phone VARCHAR(50),
    home_address TEXT,
    gender VARCHAR(20)
);

-- Schema: HR (Highly Sensitive Financial Data)
CREATE TABLE hr.employee_financials (
    employee_id UUID PRIMARY KEY REFERENCES hr.employees(id),
    base_salary DECIMAL(12, 2) NOT NULL,
    bonus DECIMAL(12, 2),
    bank_account_number VARCHAR(50),
    routing_number VARCHAR(20)
);

-- Schema: IT (Hardware Assets)
CREATE TABLE it.hardware_assets (
    asset_tag VARCHAR(50) PRIMARY KEY,
    employee_id UUID REFERENCES hr.employees(id),
    device_type VARCHAR(50) NOT NULL,
    model_name VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100),
    mac_address VARCHAR(50),
    issue_date DATE NOT NULL,
    status VARCHAR(50) NOT NULL
);

-- Schema: Public Data (Offices & Holidays)
CREATE TABLE public_data.office_locations (
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

CREATE TABLE public_data.company_holidays (
    id SERIAL PRIMARY KEY,
    holiday_date DATE NOT NULL,
    holiday_name VARCHAR(100) NOT NULL,
    country_code VARCHAR(10)
);

-- Grant permissions to sequences for auto-incrementing IDs
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public_data TO ms4_user, ms5_user;

-- Grant Table Permissions explicitly to all tables created above
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA hr TO ms2_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA it TO ms3_user;

-- MS4 owns holidays CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON public_data.company_holidays TO ms4_user;

-- MS5 owns office locations CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON public_data.office_locations TO ms5_user;
