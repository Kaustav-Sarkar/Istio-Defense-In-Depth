import os
import sys
from datetime import date
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import HardwareAsset  # noqa: E402

AUTH_HEADERS = {"x-ms3-user": "admin", "x-ms3-role": "admin"}
IT_ADMIN_HEADERS = {"x-ms3-user": "admin", "x-ms3-role": "it_admin"}


async def insert_asset(
    db_session,
    *,
    asset_tag="MAC-001",
    employee_id=None,
    device_type="Laptop",
    model_name="MacBook Pro M3",
    serial_number="C02XYZ123",
    mac_address="00:11:22:33:44:55",
    issue_date=None,
    status="Assigned",
):
    issue_date = issue_date or date(2026, 1, 15)
    asset = HardwareAsset(
        asset_tag=asset_tag,
        employee_id=employee_id,
        device_type=device_type,
        model_name=model_name,
        serial_number=serial_number,
        mac_address=mac_address,
        issue_date=issue_date,
        status=status,
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(asset)
    return asset


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_headers(client):
    response = await client.get("/api/assets")
    assert response.status_code == 401
    assert "Missing required legacy headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_wrong_role_on_write(client):
    asset_data = {
        "asset_tag": "MAC-002",
        "device_type": "Laptop",
        "model_name": "MacBook Air",
        "issue_date": "2026-03-01",
        "status": "Available",
    }
    response = await client.post(
        "/api/assets",
        json=asset_data,
        headers={"x-ms3-user": "user", "x-ms3-role": "user"},
    )
    assert response.status_code == 403
    assert "it_admin role required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_assets(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"asset_serial_mode": "truncated"},
        }
        await insert_asset(db_session)
        response = await client.get("/api/assets", headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["asset_tag"] == "MAC-001"
    assert data[0]["device_type"] == "Laptop"
    assert data[0]["serial_number"] == "Z123"
    assert data[0]["mac_address"] == "XX:XX:XX:XX:44:55"


@pytest.mark.asyncio
async def test_get_assets_passes_request_id_to_cerbos(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"asset_serial_mode": "truncated"},
        }
        await insert_asset(db_session)
        headers = {**AUTH_HEADERS, "x-request-id": "req-ms3-list"}
        response = await client.get("/api/assets", headers=headers)
    assert response.status_code == 200
    mock_check_cerbos.assert_called_once()
    assert mock_check_cerbos.call_args.kwargs["request_id"] == "req-ms3-list"


@pytest.mark.asyncio
async def test_get_asset(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {
            "allowed": True,
            "outputs": {"asset_serial_mode": "full"},
        }
        await insert_asset(db_session)
        response = await client.get("/api/assets/MAC-001", headers=IT_ADMIN_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["asset_tag"] == "MAC-001"
    assert body["serial_number"] == "C02XYZ123"


@pytest.mark.asyncio
async def test_get_asset_not_found(client):
    response = await client.get("/api/assets/UNKNOWN", headers=AUTH_HEADERS)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_asset(client, db_session):
    with patch("main.set_rls_context", new_callable=AsyncMock) as mock_set_rls:
        asset_data = {
            "asset_tag": "MAC-002",
            "device_type": "Laptop",
            "model_name": "MacBook Air",
            "issue_date": "2026-03-01",
            "status": "Available",
        }
        response = await client.post("/api/assets", json=asset_data, headers=IT_ADMIN_HEADERS)
    assert response.status_code == 201
    assert response.json()["asset_tag"] == "MAC-002"
    assert response.json()["device_type"] == "Laptop"
    mock_set_rls.assert_awaited()

    result = await db_session.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == "MAC-002"))
    assert result.scalars().first() is not None


@pytest.mark.asyncio
async def test_update_asset(client, db_session):
    await insert_asset(db_session)
    update_data = {"status": "Maintenance"}
    response = await client.put(
        "/api/assets/MAC-001",
        json=update_data,
        headers=IT_ADMIN_HEADERS,
    )
    assert response.status_code == 200
    result = await db_session.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == "MAC-001"))
    row = result.scalars().one()
    assert row.status == "Maintenance"


@pytest.mark.asyncio
async def test_delete_asset(client, db_session):
    await insert_asset(db_session)
    response = await client.delete("/api/assets/MAC-001", headers=IT_ADMIN_HEADERS)
    assert response.status_code == 204
    result = await db_session.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == "MAC-001"))
    assert result.scalars().first() is None
