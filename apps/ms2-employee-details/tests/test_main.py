import os
import sys
import uuid
from datetime import date
from decimal import Decimal
from unittest.mock import AsyncMock, patch

# Patches applied inside tests (not as decorators above @pytest.mark.asyncio) avoid
# unittest.mock/asyncio loop conflicts.

import pytest
from sqlalchemy import select

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Employee, EmployeeFinancials, EmployeePII  # noqa: E402

AUTH_HEADERS = {"x-ms2-user": "admin", "x-ms2-role": "admin"}
HR_ADMIN_HEADERS = {"x-ms2-user": "admin", "x-ms2-role": "hr_admin"}


async def insert_employee(
    db_session,
    *,
    first_name="John",
    last_name="Doe",
    work_email=None,
    work_phone="123-456-7890",
    job_title="Engineer",
    department="Engineering",
    manager_id=None,
    hire_date=None,
    status="Active",
):
    hire_date = hire_date or date(2023, 1, 1)
    work_email = work_email or f"{uuid.uuid4().hex[:12]}@example.com"
    emp = Employee(
        first_name=first_name,
        last_name=last_name,
        work_email=work_email,
        work_phone=work_phone,
        job_title=job_title,
        department=department,
        manager_id=manager_id,
        hire_date=hire_date,
        status=status,
    )
    db_session.add(emp)
    await db_session.commit()
    await db_session.refresh(emp)
    return emp


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_headers(client):
    response = await client.get("/api/employees")
    assert response.status_code == 401
    assert "Missing required legacy headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_wrong_role_on_write(client):
    emp_data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "work_email": "jane.doe@example.com",
        "job_title": "Manager",
        "department": "Sales",
        "hire_date": "2024-01-15",
        "status": "Active",
    }
    response = await client.post(
        "/api/employees",
        json=emp_data,
        headers={"x-ms2-user": "user", "x-ms2-role": "user"},
    )
    assert response.status_code == 403
    assert "hr_admin role required" in response.json()["detail"]


# ==========================================
# Employees Tests
# ==========================================


@pytest.mark.asyncio
async def test_get_employees(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"visible_fields": ["name", "work_email"]},
        }
        await insert_employee(
            db_session, first_name="John", last_name="Doe", work_email="john.doe@example.com"
        )

        response = await client.get("/api/employees", headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["first_name"] == "John"
    assert data[0]["work_email"] == "john.doe@example.com"


@pytest.mark.asyncio
async def test_get_employees_passes_request_id_to_cerbos(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"visible_fields": ["name", "work_email"]},
        }
        await insert_employee(
            db_session, first_name="John", last_name="Doe", work_email="john.doe@example.com"
        )
        headers = {**AUTH_HEADERS, "x-request-id": "req-ms2-list"}
        response = await client.get("/api/employees", headers=headers)
    assert response.status_code == 200
    mock_check_cerbos.assert_called_once()
    assert mock_check_cerbos.call_args.kwargs["request_id"] == "req-ms2-list"


@pytest.mark.asyncio
async def test_get_employee_not_found(client):
    response = await client.get(f"/api/employees/{uuid.uuid4()}", headers=AUTH_HEADERS)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_employee_real_db(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"visible_fields": ["name", "work_email"]},
        }
        emp = await insert_employee(
            db_session,
            first_name="Real",
            last_name="Employee",
            work_email="real.employee@example.com",
        )
        response = await client.get(f"/api/employees/{emp.id}", headers=AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["first_name"] == "Real"
    assert body["last_name"] == "Employee"
    assert body["work_email"] == "real.employee@example.com"


@pytest.mark.asyncio
async def test_create_employee(client, db_session):
    emp_data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "work_email": "jane.doe@example.com",
        "job_title": "Manager",
        "department": "Sales",
        "hire_date": "2024-01-15",
        "status": "Active",
    }

    response = await client.post("/api/employees", json=emp_data, headers=HR_ADMIN_HEADERS)
    assert response.status_code == 201
    payload = response.json()
    assert payload["first_name"] == "Jane"
    assert "id" in payload

    result = await db_session.execute(select(Employee).where(Employee.work_email == "jane.doe@example.com"))
    stored = result.scalars().first()
    assert stored is not None
    assert stored.first_name == "Jane"


@pytest.mark.asyncio
async def test_update_employee(client, db_session):
    emp = await insert_employee(db_session)
    update_data = {"status": "On Leave"}

    response = await client.put(f"/api/employees/{emp.id}", json=update_data, headers=HR_ADMIN_HEADERS)
    assert response.status_code == 200

    await db_session.refresh(emp)
    assert emp.status == "On Leave"


@pytest.mark.asyncio
async def test_delete_employee(client, db_session):
    emp = await insert_employee(db_session)

    response = await client.delete(f"/api/employees/{emp.id}", headers=HR_ADMIN_HEADERS)
    assert response.status_code == 204

    result = await db_session.execute(select(Employee).where(Employee.id == emp.id))
    assert result.scalars().first() is None


# ==========================================
# Employee PII Tests
# ==========================================


@pytest.mark.asyncio
async def test_get_employee_pii(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"visible_fields": ["ssn"]},
        }
        emp = await insert_employee(db_session)
        pii = EmployeePII(
            employee_id=emp.id,
            ssn="123-45-6789",
            date_of_birth=date(1990, 5, 15),
            personal_phone="555-1234",
            home_address="123 Main St",
            gender="Male",
        )
        db_session.add(pii)
        await db_session.commit()

        response = await client.get(f"/api/employees/{emp.id}/pii", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert response.json()["ssn"] == "123-45-6789"


@pytest.mark.asyncio
async def test_create_employee_pii(client, db_session):
    emp = await insert_employee(db_session)
    pii_data = {
        "ssn": "987-65-4321",
        "date_of_birth": "1992-08-20",
    }

    response = await client.post(
        f"/api/employees/{emp.id}/pii",
        json=pii_data,
        headers=HR_ADMIN_HEADERS,
    )
    assert response.status_code == 201
    assert response.json()["ssn"] == "987-65-4321"


@pytest.mark.asyncio
async def test_update_employee_pii(client, db_session):
    emp = await insert_employee(db_session)
    pii = EmployeePII(
        employee_id=emp.id,
        ssn="123-45-6789",
        date_of_birth=date(1990, 5, 15),
        personal_phone="555-1234",
        home_address="123 Main St",
        gender="Male",
    )
    db_session.add(pii)
    await db_session.commit()

    update_data = {"personal_phone": "555-9999"}

    response = await client.put(
        f"/api/employees/{emp.id}/pii",
        json=update_data,
        headers=HR_ADMIN_HEADERS,
    )
    assert response.status_code == 200

    await db_session.refresh(pii)
    assert pii.personal_phone == "555-9999"


@pytest.mark.asyncio
async def test_delete_employee_pii(client, db_session):
    emp = await insert_employee(db_session)
    pii = EmployeePII(
        employee_id=emp.id,
        ssn="123-45-6789",
        date_of_birth=date(1990, 5, 15),
    )
    db_session.add(pii)
    await db_session.commit()

    response = await client.delete(f"/api/employees/{emp.id}/pii", headers=HR_ADMIN_HEADERS)
    assert response.status_code == 204

    result = await db_session.execute(select(EmployeePII).where(EmployeePII.employee_id == emp.id))
    assert result.scalars().first() is None


# ==========================================
# Employee Financials Tests
# ==========================================


@pytest.mark.asyncio
async def test_get_employee_financials(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"visible_fields": ["salary_band"]},
        }
        emp = await insert_employee(db_session)
        fin = EmployeeFinancials(
            employee_id=emp.id,
            base_salary=Decimal("100000.00"),
            bonus=Decimal("15000.00"),
            bank_account_number="ACCT123",
            routing_number="ROUT456",
        )
        db_session.add(fin)
        await db_session.commit()

        response = await client.get(f"/api/employees/{emp.id}/financials", headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["salary_band"] == "100k-149k"
    assert "base_salary" not in data
    assert "bonus" not in data


@pytest.mark.asyncio
async def test_create_employee_financials(client, db_session):
    emp = await insert_employee(db_session)
    fin_data = {
        "base_salary": "120000.00",
        "bonus": "20000.00",
    }

    response = await client.post(
        f"/api/employees/{emp.id}/financials",
        json=fin_data,
        headers=HR_ADMIN_HEADERS,
    )
    assert response.status_code == 201
    assert response.json()["base_salary"] == "120000.00"


@pytest.mark.asyncio
async def test_update_employee_financials(client, db_session):
    emp = await insert_employee(db_session)
    fin = EmployeeFinancials(
        employee_id=emp.id,
        base_salary=Decimal("100000.00"),
        bonus=Decimal("15000.00"),
        bank_account_number="ACCT123",
        routing_number="ROUT456",
    )
    db_session.add(fin)
    await db_session.commit()

    update_data = {"base_salary": "105000.00"}

    response = await client.put(
        f"/api/employees/{emp.id}/financials",
        json=update_data,
        headers=HR_ADMIN_HEADERS,
    )
    assert response.status_code == 200

    await db_session.refresh(fin)
    assert fin.base_salary == Decimal("105000.00")


@pytest.mark.asyncio
async def test_delete_employee_financials(client, db_session):
    emp = await insert_employee(db_session)
    fin = EmployeeFinancials(
        employee_id=emp.id,
        base_salary=Decimal("100000.00"),
        bonus=Decimal("15000.00"),
    )
    db_session.add(fin)
    await db_session.commit()

    response = await client.delete(f"/api/employees/{emp.id}/financials", headers=HR_ADMIN_HEADERS)
    assert response.status_code == 204

    result = await db_session.execute(
        select(EmployeeFinancials).where(EmployeeFinancials.employee_id == emp.id)
    )
    assert result.scalars().first() is None
