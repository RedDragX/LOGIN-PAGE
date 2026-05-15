import os
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://pgroom-rental.preview.emergentagent.com').rstrip('/')


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture
def api_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def _login(email, password):
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password}, timeout=15)
    if r.status_code != 200:
        pytest.skip(f"Login failed for {email}: {r.status_code} {r.text}")
    return r.json()


@pytest.fixture(scope="session")
def admin_auth():
    return _login("admin@pgroom.in", "admin123")


@pytest.fixture(scope="session")
def owner_auth():
    return _login("owner@pgroom.in", "owner123")


@pytest.fixture(scope="session")
def tenant_auth():
    return _login("tenant@pgroom.in", "tenant123")


def _client_with(token):
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    return s


@pytest.fixture
def admin_client(admin_auth):
    return _client_with(admin_auth["token"])


@pytest.fixture
def owner_client(owner_auth):
    return _client_with(owner_auth["token"])


@pytest.fixture
def tenant_client(tenant_auth):
    return _client_with(tenant_auth["token"])
