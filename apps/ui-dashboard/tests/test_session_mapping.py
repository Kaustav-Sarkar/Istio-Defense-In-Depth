import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import get_profile_employee_id, get_session_display_name, get_demo_user_id, DEMO_USERS


def test_profile_employee_id_uses_auth_session_user_id():
    session = {"user_id": "alice.employee", "username": "alice"}

    assert get_profile_employee_id(session) == "alice.employee"


def test_session_display_name_uses_auth_session_username():
    session = {"user_id": "alice.employee", "username": "alice"}

    assert get_session_display_name(session) == "alice"


def test_session_display_name_fallback_to_user_id():
    session = {"user_id": "fallback-id"}

    assert get_session_display_name(session) == "fallback-id"


def test_demo_user_id_generation():
    alice_id = get_demo_user_id("alice.employee")
    # deterministic uuid5 for istio-security://users/alice.employee
    assert len(alice_id) == 36  # UUID length
    assert "alice.employee" not in alice_id
    assert alice_id == DEMO_USERS["Alice (Employee)"]


def test_demo_users_contains_expected_keys():
    expected_keys = [
        "My Profile (Session User)",
        "Alice (Employee)",
        "Mary (Manager)",
        "Henry (HR Admin)",
        "Ivan (IT Admin)"
    ]
    for key in expected_keys:
        assert key in DEMO_USERS
