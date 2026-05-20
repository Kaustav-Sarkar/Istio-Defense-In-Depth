import sys
import os

os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost/db"
os.environ["KEYCLOAK_URL"] = "http://localhost:8080"
os.environ["KEYCLOAK_REALM"] = "test-realm"
os.environ["KEYCLOAK_CLIENT_ID"] = "test-client"
os.environ["KEYCLOAK_CLIENT_SECRET"] = "test-secret"
os.environ["VAULT_URL"] = "http://localhost:8200"
os.environ["VAULT_TOKEN"] = "test-token"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    return TestClient(app)
