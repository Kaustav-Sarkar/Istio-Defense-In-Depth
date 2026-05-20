import os
import sys
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402
from models import OfficeLocation  # noqa: E402

ADMIN_HEADERS = {"x-ms5-user": "admin", "x-ms5-role": "admin"}
PUBLIC_DATA_ADMIN_HEADERS = {
    "x-ms5-user": "admin",
    "x-ms5-role": "public_data_admin",
}


async def insert_office(db_session, **kwargs):
    defaults = dict(
        city_name="New York",
        address="123 Broadway",
        country_code="US",
        capacity=100,
        status="Open",
        latitude=None,
        longitude=None,
        established_date=None,
    )
    defaults.update(kwargs)
    office = OfficeLocation(**defaults)
    db_session.add(office)
    await db_session.commit()
    await db_session.refresh(office)
    return office


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_headers_default_public_identity(client, db_session):
    """Absent x-ms5-* headers fall back to anonymous/public (see get_ms5_headers)."""
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {"allowed": True, "outputs": {}}
        response = await client.get("/api/offices")
    assert response.status_code == 200
    kwargs = mock_check_cerbos.call_args.kwargs
    assert kwargs.get("principal_id") == "anonymous"


@pytest.mark.asyncio
async def test_wrong_role_on_write(client):
    office_data = {
        "city_name": "London",
        "address": "456 Main St",
        "country_code": "UK",
        "capacity": 200,
        "status": "Open",
        "established_date": "2018-03-10",
    }
    response = await client.post(
        "/api/offices",
        json=office_data,
        headers={"x-ms5-user": "user", "x-ms5-role": "user"},
    )
    assert response.status_code == 403
    assert "admin role required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_offices_cerbos_deny(client, db_session, monkeypatch):
    async def _cerbos_deny(*args, **kwargs):
        return {"allowed": False}

    monkeypatch.setattr(main, "check_cerbos", _cerbos_deny)
    response = await client.get("/api/offices", headers={"x-ms5-user": "user1", "x-ms5-role": "user"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_offices(client, db_session):
    await insert_office(db_session)
    response = await client.get("/api/offices", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["city_name"] == "New York"


@pytest.mark.asyncio
async def test_get_offices_passes_request_id_to_cerbos(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {"allowed": True, "outputs": {}}
        await insert_office(db_session)
        headers = {**ADMIN_HEADERS, "x-request-id": "req-ms5-list"}
        response = await client.get("/api/offices", headers=headers)
    assert response.status_code == 200
    mock_check_cerbos.assert_called_once()
    assert mock_check_cerbos.call_args.kwargs["request_id"] == "req-ms5-list"


@pytest.mark.asyncio
async def test_create_office(client, db_session):
    office_data = {
        "city_name": "London",
        "address": "456 Main St",
        "country_code": "UK",
        "capacity": 200,
        "status": "Open",
        "established_date": "2018-03-10",
    }
    response = await client.post("/api/offices", json=office_data, headers=PUBLIC_DATA_ADMIN_HEADERS)
    assert response.status_code == 201
    body = response.json()
    assert "id" in body
    assert body["city_name"] == "London"

    result = await db_session.execute(select(OfficeLocation).where(OfficeLocation.city_name == "London"))
    assert result.scalars().first() is not None


@pytest.mark.asyncio
async def test_get_office(client, db_session):
    office = await insert_office(db_session)
    response = await client.get(f"/api/offices/{office.id}", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert response.json()["city_name"] == "New York"


@pytest.mark.asyncio
async def test_get_office_not_found(client):
    response = await client.get("/api/offices/999999", headers=ADMIN_HEADERS)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_office(client, db_session):
    office = await insert_office(db_session)
    response = await client.delete(f"/api/offices/{office.id}", headers=PUBLIC_DATA_ADMIN_HEADERS)
    assert response.status_code == 204
    result = await db_session.execute(select(OfficeLocation).where(OfficeLocation.id == office.id))
    assert result.scalars().first() is None


@pytest.mark.asyncio
async def test_update_office(client, db_session):
    office = await insert_office(db_session)
    update_data = {"status": "Closed"}
    response = await client.put(
        f"/api/offices/{office.id}",
        json=update_data,
        headers=PUBLIC_DATA_ADMIN_HEADERS,
    )
    assert response.status_code == 200
    await db_session.refresh(office)
    assert office.status == "Closed"
