import pytest
from unittest.mock import MagicMock
import uuid
from datetime import datetime, timedelta
from sessions import create_session, get_session, revoke_session

@pytest.fixture
def mock_db():
    db = MagicMock()
    return db

def test_create_session(mock_db):
    session = create_session(mock_db, "user1", ["employee"])
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()
    assert session.user_id == "user1"
    assert "employee" in session.roles
    assert not session.revoked

def test_get_session_invalid_uuid(mock_db):
    assert get_session(mock_db, "invalid-uuid") is None

def test_revoke_session_invalid_uuid(mock_db):
    assert revoke_session(mock_db, "invalid-uuid") is False
