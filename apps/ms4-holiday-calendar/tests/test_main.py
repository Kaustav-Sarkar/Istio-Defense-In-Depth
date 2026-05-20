import os
import sys
from datetime import date
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402
from models import CompanyHoliday  # noqa: E402

ADMIN_HEADERS = {"x-ms4-user": "admin", "x-ms4-role": "admin"}
PUBLIC_DATA_ADMIN_HEADERS = {
    "x-ms4-user": "admin",
    "x-ms4-role": "public_data_admin",
}


async def insert_holiday(
    db_session,
    *,
    holiday_date=None,
    holiday_name="New Year's Day",
    country_code="US",
):
    holiday_date = holiday_date or date(2026, 1, 1)
    holiday = CompanyHoliday(
        holiday_date=holiday_date,
        holiday_name=holiday_name,
        country_code=country_code,
    )
    db_session.add(holiday)
    await db_session.commit()
    await db_session.refresh(holiday)
    return holiday


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_headers(client):
    response = await client.get("/api/holidays")
    assert response.status_code == 401
    assert "Missing required legacy headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_wrong_role_on_write(client):
    holiday_data = {
        "holiday_date": "2026-12-25",
        "holiday_name": "Christmas Day",
        "country_code": "UK",
    }
    response = await client.post(
        "/api/holidays",
        json=holiday_data,
        headers={"x-ms4-user": "user", "x-ms4-role": "user"},
    )
    assert response.status_code == 403
    assert "admin role required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_holidays_cerbos_deny(client, db_session, monkeypatch):
    async def _cerbos_deny(*args, **kwargs):
        return {"allowed": False}

    monkeypatch.setattr(main, "check_cerbos", _cerbos_deny)
    response = await client.get("/api/holidays", headers={"x-ms4-user": "user1", "x-ms4-role": "user"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_holidays(client, db_session):
    await insert_holiday(db_session)
    response = await client.get("/api/holidays", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["holiday_name"] == "New Year's Day"
    assert data[0]["holiday_date"] == "2026-01-01"


@pytest.mark.asyncio
async def test_get_holidays_passes_request_id_to_cerbos(client, db_session):
    with patch("main.check_cerbos", new_callable=AsyncMock) as mock_check_cerbos:
        mock_check_cerbos.return_value = {"allowed": True, "outputs": {}}
        await insert_holiday(db_session)
        headers = {**PUBLIC_DATA_ADMIN_HEADERS, "x-request-id": "req-ms4-list"}
        response = await client.get("/api/holidays", headers=headers)
    assert response.status_code == 200
    mock_check_cerbos.assert_called_once()
    assert mock_check_cerbos.call_args.kwargs["request_id"] == "req-ms4-list"


@pytest.mark.asyncio
async def test_get_holiday(client, db_session):
    holiday = await insert_holiday(db_session)
    response = await client.get(f"/api/holidays/{holiday.id}", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert response.json()["holiday_name"] == "New Year's Day"


@pytest.mark.asyncio
async def test_get_holiday_not_found(client):
    response = await client.get("/api/holidays/999999", headers=ADMIN_HEADERS)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_holiday(client, db_session):
    holiday_data = {
        "holiday_date": "2026-12-25",
        "holiday_name": "Christmas Day",
        "country_code": "UK",
    }
    response = await client.post("/api/holidays", json=holiday_data, headers=PUBLIC_DATA_ADMIN_HEADERS)
    assert response.status_code == 201
    body = response.json()
    assert "id" in body
    assert body["holiday_name"] == "Christmas Day"

    result = await db_session.execute(
        select(CompanyHoliday).where(CompanyHoliday.holiday_name == "Christmas Day")
    )
    assert result.scalars().first() is not None


@pytest.mark.asyncio
async def test_update_holiday(client, db_session):
    holiday = await insert_holiday(db_session, holiday_name="New Year")
    update_data = {"holiday_name": "New Year's Day"}
    response = await client.put(
        f"/api/holidays/{holiday.id}",
        json=update_data,
        headers=PUBLIC_DATA_ADMIN_HEADERS,
    )
    assert response.status_code == 200
    await db_session.refresh(holiday)
    assert holiday.holiday_name == "New Year's Day"


@pytest.mark.asyncio
async def test_delete_holiday(client, db_session):
    holiday = await insert_holiday(db_session)
    response = await client.delete(f"/api/holidays/{holiday.id}", headers=PUBLIC_DATA_ADMIN_HEADERS)
    assert response.status_code == 204
    result = await db_session.execute(select(CompanyHoliday).where(CompanyHoliday.id == holiday.id))
    assert result.scalars().first() is None
