"""
conftest.py — shared pytest fixtures for pgroom API tests.
Place this file in the same directory as test_pgroom_api.py.
"""
import os
import pytest
import requests

BASE_URL = os.environ.get(
    "REACT_APP_BACKEND_URL",
    "https://pgroom-rental.preview.emergentagent.com"
).rstrip("/")


# ─── Base HTTP client (no auth) ───────────────────────────────────────────────

@pytest.fixture(scope="session")
def api_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ─── Auth responses (login once per test session) ─────────────────────────────

@pytest.fixture(scope="session")
def admin_auth(api_client):
    r = api_client.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "admin@pgroom.in", "password": "admin123"},
    )
    assert r.status_code == 200, f"Admin login failed: {r.text}"
    return r.json()


@pytest.fixture(scope="session")
def owner_auth(api_client):
    r = api_client.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "owner@pgroom.in", "password": "pass1234"},
    )
    assert r.status_code == 200, f"Owner login failed: {r.text}"
    return r.json()


@pytest.fixture(scope="session")
def tenant_auth(api_client):
    r = api_client.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "tenant@pgroom.in", "password": "pass1234"},
    )
    assert r.status_code == 200, f"Tenant login failed: {r.text}"
    return r.json()


# ─── Authenticated HTTP clients ───────────────────────────────────────────────

@pytest.fixture(scope="session")
def admin_client(admin_auth):
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {admin_auth['token']}",
    })
    return s


@pytest.fixture(scope="session")
def owner_client(owner_auth):
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {owner_auth['token']}",
    })
    return s


@pytest.fixture(scope="session")
def tenant_client(tenant_auth):
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {tenant_auth['token']}",
    })
    return s
