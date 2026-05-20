import os
import sys

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import UUID

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import Base, get_db  # noqa: E402


class HrEmployee(Base):
    """Registers hr.employees so HardwareAsset can resolve its employee_id foreign key."""

    __tablename__ = "employees"
    __table_args__ = {"schema": "hr"}
    id = Column(UUID(as_uuid=True), primary_key=True)


from main import app  # noqa: E402


@pytest_asyncio.fixture(loop_scope="session")
async def client(db_session):
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def default_cerbos_allow(monkeypatch):
    async def _allow(*args, **kwargs):
        return {"allowed": True, "outputs": {}}

    monkeypatch.setattr("main.check_cerbos", _allow)
