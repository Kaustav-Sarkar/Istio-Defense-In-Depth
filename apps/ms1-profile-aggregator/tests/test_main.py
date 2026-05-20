import importlib.util
import json
import os
import sys
import uuid
from datetime import date
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import httpx
import pytest
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient, Response
from pydantic import ValidationError

_apps_root = Path(__file__).resolve().parents[2]


def _load_schemas(module_name: str, relative_path: str):
    path = _apps_root / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ms2_schemas = _load_schemas("ms1_tests_ms2_schemas", "ms2-employee-details/schemas.py")
_ms3_schemas = _load_schemas("ms1_tests_ms3_schemas", "ms3-hardware-assets/schemas.py")

EmployeeResponse = _ms2_schemas.EmployeeResponse
EmployeeFinancialsResponse = _ms2_schemas.EmployeeFinancialsResponse
EmployeePIIResponse = _ms2_schemas.EmployeePIIResponse
HardwareAssetResponse = _ms3_schemas.HardwareAssetResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app


@pytest.fixture
def emp_id():
    return str(uuid.uuid4())


@pytest.fixture
def mock_ms2_ms3(respx_mock, emp_id):
    emp_uuid = UUID(emp_id)
    emp = EmployeeResponse(
        id=emp_uuid,
        first_name="John",
        last_name="Doe",
        work_email="john@example.com",
        job_title="Engineer",
        department="Engineering",
        hire_date=date(2020, 1, 15),
        status="active",
    )
    fin = EmployeeFinancialsResponse(
        employee_id=emp_uuid,
        base_salary=Decimal("100000"),
    )
    pii = EmployeePIIResponse(
        employee_id=emp_uuid,
        ssn="123-45-678",
        date_of_birth=date(1990, 5, 1),
    )
    asset = HardwareAssetResponse(
        asset_tag="LPT-123",
        employee_id=emp_uuid,
        device_type="laptop",
        model_name="MacBook Pro",
        issue_date=date(2024, 6, 1),
        status="active",
    )

    route_ms2 = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}"
    ).mock(return_value=httpx.Response(200, content=emp.model_dump_json()))
    route_fin = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/financials"
    ).mock(return_value=httpx.Response(200, content=fin.model_dump_json()))
    route_pii = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/pii"
    ).mock(return_value=httpx.Response(200, content=pii.model_dump_json()))
    route_ms3 = respx_mock.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(
        return_value=httpx.Response(
            200, content=json.dumps([asset.model_dump(mode="json")])
        )
    )
    yield route_ms2, route_fin, route_pii, route_ms3


@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def test_ms3_contract_failure():
    """Ensure ms3 HardwareAssetResponse rejects drift (e.g. `model` vs `model_name`)."""
    emp_uuid = UUID("00000000-0000-0000-0000-000000000001")
    try:
        HardwareAssetResponse(
            asset_tag="123",
            employee_id=emp_uuid,
            device_type="laptop",
            model="MacBook",  # bad field name; schema expects model_name
            issue_date=date.today(),
            status="active",
        )
        pytest.fail("Should have raised ValidationError")
    except ValidationError:
        pass


def test_health_check():
    # Sync TestClient keeps a minimal smoke path for the sync stack.
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_get_profile_missing_headers():
    from fastapi.testclient import TestClient

    client = TestClient(app)
    emp_id = str(uuid.uuid4())
    response = client.get(f"/api/profile/{emp_id}")
    assert response.status_code == 401
    assert "Missing required legacy headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_profile_success(async_client: AsyncClient, mock_ms2_ms3, emp_id):
    ms2_route, ms2_fin_route, ms2_pii_route, ms3_route = mock_ms2_ms3

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "employee" in data
    assert data["employee"]["first_name"] == "John"
    assert data["employee"]["base_salary"] in (100000, "100000.00", "100000")
    assert data["employee"]["ssn"] == "123-45-678"
    assert "assets" in data
    assert len(data["assets"]) == 1
    assert data["assets"][0]["model_name"] == "MacBook Pro"
    assert ms2_route.called
    assert ms2_fin_route.called
    assert ms2_pii_route.called
    assert ms3_route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_profile_ms2_404(async_client: AsyncClient, emp_id):
    ms2_route = respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}"
    ).mock(return_value=Response(404, json={"detail": "Employee not found"}))
    ms2_fin_route = respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/financials"
    ).mock(return_value=Response(404, json={"detail": "Not found"}))
    ms2_pii_route = respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/pii"
    ).mock(return_value=Response(404, json={"detail": "Not found"}))
    respx.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(return_value=Response(200, json=[]))

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 404
    assert ms2_route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_profile_ms2_500(async_client: AsyncClient, emp_id):
    ms2_route = respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}"
    ).mock(
        return_value=Response(500, json={"detail": "Internal Server Error"})
    )
    respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/financials"
    ).mock(return_value=Response(500, json={"detail": "Internal Server Error"}))
    respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/pii"
    ).mock(return_value=Response(500, json={"detail": "Internal Server Error"}))
    respx.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(return_value=Response(200, json=[]))

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 502
    assert ms2_route.called


def _stub_ms2_fin_pii_assets(respx_mock, emp_id):
    emp_uuid = UUID(emp_id)
    emp = EmployeeResponse(
        id=emp_uuid,
        first_name="John",
        last_name="Doe",
        work_email="john@example.com",
        job_title="Engineer",
        department="Engineering",
        hire_date=date(2020, 1, 15),
        status="active",
    )
    fin = EmployeeFinancialsResponse(
        employee_id=emp_uuid,
        base_salary=Decimal("100000"),
    )
    pii = EmployeePIIResponse(
        employee_id=emp_uuid,
        ssn="123-45-678",
        date_of_birth=date(1990, 5, 1),
    )
    route_emp = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}"
    ).mock(return_value=httpx.Response(200, content=emp.model_dump_json()))
    route_fin = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/financials"
    ).mock(return_value=httpx.Response(200, content=fin.model_dump_json()))
    route_pii = respx_mock.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/pii"
    ).mock(return_value=httpx.Response(200, content=pii.model_dump_json()))
    return route_emp, route_fin, route_pii


@pytest.mark.asyncio
@respx.mock
async def test_get_profile_ms3_500_graceful_degradation(async_client: AsyncClient, emp_id):
    ms2_route, _, _ = _stub_ms2_fin_pii_assets(respx, emp_id)
    ms3_route = respx.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(return_value=Response(500, json={"detail": "Internal Server Error"}))

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "employee" in data
    assert data["employee"]["first_name"] == "John"
    assert "assets" in data
    assert len(data["assets"]) == 0
    assert ms2_route.called
    assert ms3_route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_profile_ms2_timeout(async_client: AsyncClient, emp_id):
    ms2_route = respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}"
    ).mock(side_effect=httpx.TimeoutException("Timeout"))
    respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/financials"
    ).mock(side_effect=httpx.TimeoutException("Timeout"))
    respx.get(
        f"http://ms2-employee-details.zt-apps.svc.cluster.local:8000/api/employees/{emp_id}/pii"
    ).mock(side_effect=httpx.TimeoutException("Timeout"))
    respx.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(return_value=Response(200, json=[]))

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 502
    assert ms2_route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_profile_ms3_timeout_graceful_degradation(async_client: AsyncClient, emp_id):
    ms2_route, _, _ = _stub_ms2_fin_pii_assets(respx, emp_id)
    ms3_route = respx.get(
        f"http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000/api/assets?employee_id={emp_id}"
    ).mock(side_effect=httpx.TimeoutException("Timeout"))

    response = await async_client.get(
        f"/api/profile/{emp_id}",
        headers={"x-ms1-user": "admin", "x-ms1-role": "admin"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "employee" in data
    assert data["employee"]["first_name"] == "John"
    assert "assets" in data
    assert len(data["assets"]) == 0
    assert ms2_route.called
    assert ms3_route.called
