"""End-to-end backend tests for pgroom API."""
import os
import uuid
from datetime import datetime, timezone
import pytest
import requests

BASE_URL = os.environ.get(
    "REACT_APP_BACKEND_URL",
    "https://pgroom-rental.preview.emergentagent.com"
).rstrip("/")


# ---------- Auth ----------
class TestAuth:
    def test_login_admin(self, admin_auth):
        assert "token" in admin_auth and admin_auth["user"]["role"] == "admin"
        assert admin_auth["user"]["email"] == "admin@pgroom.in"
        assert "_id" not in admin_auth["user"]
        assert "password" not in admin_auth["user"]

    def test_login_owner(self, owner_auth):
        assert owner_auth["user"]["role"] == "owner"

    def test_login_tenant(self, tenant_auth):
        assert tenant_auth["user"]["role"] == "tenant"

    def test_login_invalid(self, api_client):
        r = api_client.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": "admin@pgroom.in", "password": "wrong"},
        )
        assert r.status_code == 401

    def test_register_new_tenant(self, api_client):
        # Phone is randomised so this test is idempotent across runs
        email = f"TEST_{uuid.uuid4().hex[:8]}@example.com"
        phone = str(random_10_digit())
        r = api_client.post(
            f"{BASE_URL}/api/auth/register",
            json={
                "name": "Test Tenant",
                "email": email,
                "phone": phone,
                "password": "pass1234",
                "role": "tenant",
            },
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert "token" in d and d["user"]["email"] == email
        assert d["user"]["role"] == "tenant"
        assert "password" not in d["user"]

    def test_register_duplicate(self, api_client):
        r = api_client.post(
            f"{BASE_URL}/api/auth/register",
            json={
                "name": "X",
                "email": "admin@pgroom.in",
                "phone": "9000000002",
                "password": "pass1234",
                "role": "tenant",
            },
        )
        assert r.status_code == 400

    def test_auth_me(self, tenant_client):
        r = tenant_client.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 200
        assert r.json()["email"] == "tenant@pgroom.in"

    def test_auth_me_no_token(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 401

    def test_otp_send_and_verify(self, tenant_client):
        phone = "9123456780"
        r = tenant_client.post(f"{BASE_URL}/api/auth/otp/send", json={"phone": phone})
        assert r.status_code == 200
        d = r.json()
        assert "otp" in d and len(d["otp"]) == 6
        otp = d["otp"]
        v = tenant_client.post(
            f"{BASE_URL}/api/auth/otp/verify", json={"phone": phone, "otp": otp}
        )
        assert v.status_code == 200

    def test_otp_verify_invalid(self, tenant_client):
        phone = "9123456780"
        tenant_client.post(f"{BASE_URL}/api/auth/otp/send", json={"phone": phone})
        v = tenant_client.post(
            f"{BASE_URL}/api/auth/otp/verify", json={"phone": phone, "otp": "000000"}
        )
        assert v.status_code == 400

    def test_kyc_valid(self, tenant_client):
        r = tenant_client.post(
            f"{BASE_URL}/api/auth/kyc",
            json={
                "pan": "ABCDE1234F",
                "aadhaar": "123456789012",
                "emergency_contact_name": "Mom",
                "emergency_contact_phone": "9000000003",
                "emergency_contact_relation": "Mother",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["verified"] is True

    def test_kyc_invalid_pan(self, tenant_client):
        r = tenant_client.post(
            f"{BASE_URL}/api/auth/kyc",
            json={"pan": "INVALID", "aadhaar": "123456789012"},
        )
        assert r.status_code == 200
        assert r.json()["verified"] is False


# ---------- Properties ----------
class TestProperties:
    def test_list_properties_seeded(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties")
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list)
        assert len(items) >= 6, f"Expected >=6 seeded, got {len(items)}"
        for it in items:
            assert "_id" not in it
            assert "id" in it and "title" in it and "rent" in it

    def test_filter_area(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties", params={"area": "six_mile"})
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 1
        assert all(i["area"] == "six_mile" for i in items)

    def test_filter_gender(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties", params={"gender": "girls"})
        assert r.status_code == 200
        assert all(i["gender"] == "girls" for i in r.json())

    def test_filter_flood_free(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties", params={"flood_free": "true"})
        assert r.status_code == 200
        assert all(i["flood_free_zone"] is True for i in r.json())

    def test_filter_water(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties", params={"water_24_7": "true"})
        assert r.status_code == 200
        assert all(i["water_24_7"] is True for i in r.json())

    def test_filter_rent_range(self, api_client):
        r = api_client.get(
            f"{BASE_URL}/api/properties", params={"min_rent": 7000, "max_rent": 9000}
        )
        assert r.status_code == 200
        for i in r.json():
            assert 7000 <= i["rent"] <= 9000

    def test_search_q(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties", params={"q": "Beltola"})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_get_property_with_reviews(self, api_client):
        items = api_client.get(f"{BASE_URL}/api/properties").json()
        pid = items[0]["id"]
        r = api_client.get(f"{BASE_URL}/api/properties/{pid}")
        assert r.status_code == 200
        d = r.json()
        assert d["id"] == pid and "reviews" in d and isinstance(d["reviews"], list)

    def test_get_property_404(self, api_client):
        r = api_client.get(f"{BASE_URL}/api/properties/nonexistent-id")
        assert r.status_code == 404

    def test_owner_create_property(self, owner_client):
        payload = {
            "title": "TEST_Owner_Property",
            "description": "Test created",
            "location": "Guwahati",
            "address": "Test addr",
            "area": "other",
            "gender": "unisex",
            "rent": 6000,
            "deposit": 5000,
            "amenities": ["WiFi"],
            "images": [],
        }
        r = owner_client.post(f"{BASE_URL}/api/properties", json=payload)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["title"] == "TEST_Owner_Property"
        assert d["verified"] is False
        assert "id" in d
        # GET to verify persistence
        g = owner_client.get(f"{BASE_URL}/api/properties/{d['id']}")
        assert g.status_code == 200 and g.json()["title"] == "TEST_Owner_Property"

    def test_tenant_cannot_create_property(self, tenant_client):
        payload = {
            "title": "TEST_Bad",
            "description": "x",
            "location": "x",
            "address": "x",
            "area": "other",
            "gender": "unisex",
            "rent": 1000,
        }
        r = tenant_client.post(f"{BASE_URL}/api/properties", json=payload)
        assert r.status_code == 403


# ---------- Bookings & Wallet & Rent ----------
class TestBookingFlow:
    @pytest.fixture(scope="class")
    def fresh_tenant(self):
        # Phone randomised to avoid duplicate failures on re-runs
        email = f"TEST_tenant_{uuid.uuid4().hex[:8]}@example.com"
        phone = str(random_10_digit())
        r = requests.post(
            f"{BASE_URL}/api/auth/register",
            json={
                "name": "Booking Tenant",
                "email": email,
                "phone": phone,
                "password": "pass1234",
                "role": "tenant",
            },
        )
        assert r.status_code == 200, r.text
        d = r.json()
        return {"token": d["token"], "user": d["user"], "email": email}

    @pytest.fixture(scope="class")
    def fresh_tenant_client(self, fresh_tenant):
        s = requests.Session()
        s.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {fresh_tenant['token']}",
        })
        return s

    @pytest.fixture(scope="class")
    def property_id(self):
        r = requests.get(f"{BASE_URL}/api/properties")
        return r.json()[0]["id"]

    def test_create_booking(self, fresh_tenant_client, property_id):
        r = fresh_tenant_client.post(
            f"{BASE_URL}/api/bookings",
            json={"property_id": property_id, "visit_date": "2026-02-15"},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["status"] == "pending_payment"
        assert d["visit_fee"] == 500
        assert d["visit_fee_paid"] is False
        pytest.booking_id = d["id"]

    def test_pay_visit_fee(self, fresh_tenant_client):
        bid = pytest.booking_id
        r = fresh_tenant_client.post(f"{BASE_URL}/api/bookings/{bid}/pay-visit-fee")
        assert r.status_code == 200
        # Verify status updated
        bookings = fresh_tenant_client.get(f"{BASE_URL}/api/bookings/me").json()
        b = next(x for x in bookings if x["id"] == bid)
        assert b["status"] == "scheduled" and b["visit_fee_paid"] is True

    def test_owner_cannot_book(self, owner_client, property_id):
        r = owner_client.post(
            f"{BASE_URL}/api/bookings",
            json={"property_id": property_id, "visit_date": "2026-02-15"},
        )
        assert r.status_code == 403

    def test_wallet_recharge(self, fresh_tenant_client):
        r = fresh_tenant_client.post(
            f"{BASE_URL}/api/wallet/recharge", json={"amount": 5000}
        )
        assert r.status_code == 200
        assert r.json()["wallet_balance"] >= 5000

    def test_move_in(self, fresh_tenant_client):
        bid = pytest.booking_id
        r = fresh_tenant_client.post(f"{BASE_URL}/api/bookings/{bid}/move-in")
        assert r.status_code == 200, r.text
        bookings = fresh_tenant_client.get(f"{BASE_URL}/api/bookings/me").json()
        b = next(x for x in bookings if x["id"] == bid)
        assert b["status"] == "moved_in"
        assert b["advance_paid"] == 5000
        # Wallet should have been deducted to 0
        me = fresh_tenant_client.get(f"{BASE_URL}/api/auth/me").json()
        assert me["wallet_balance"] == 0

    def test_move_in_insufficient(self, fresh_tenant_client, property_id):
        # New booking, wallet is 0 — move-in should fail
        r1 = fresh_tenant_client.post(
            f"{BASE_URL}/api/bookings",
            json={"property_id": property_id, "visit_date": "2026-03-15"},
        )
        bid = r1.json()["id"]
        r = fresh_tenant_client.post(f"{BASE_URL}/api/bookings/{bid}/move-in")
        assert r.status_code == 400

    def test_pay_rent(self, fresh_tenant_client, property_id):
        # Recharge enough — rent + possible penalty
        prop = requests.get(f"{BASE_URL}/api/properties/{property_id}").json()
        today = datetime.now(timezone.utc).day
        penalty = (today - 8) * 500 if today > 8 else 0
        need = prop["rent"] + penalty
        rr = fresh_tenant_client.post(
            f"{BASE_URL}/api/wallet/recharge", json={"amount": need}
        )
        assert rr.status_code == 200
        r = fresh_tenant_client.post(
            f"{BASE_URL}/api/rent/pay",
            json={"property_id": property_id, "month": "2026-01"},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["total"] == need
        assert d["penalty"] == penalty
        assert d["invoice_no"].startswith("INV-")

    def test_exit_booking(self, fresh_tenant_client):
        bid = pytest.booking_id
        r = fresh_tenant_client.post(f"{BASE_URL}/api/bookings/{bid}/exit")
        assert r.status_code == 200
        assert "exit_after" in r.json()
        bookings = fresh_tenant_client.get(f"{BASE_URL}/api/bookings/me").json()
        b = next(x for x in bookings if x["id"] == bid)
        assert b["status"] == "exit_notice"

    def test_my_bookings_tenant(self, fresh_tenant_client):
        r = fresh_tenant_client.get(f"{BASE_URL}/api/bookings/me")
        assert r.status_code == 200
        assert isinstance(r.json(), list) and len(r.json()) >= 1


# ---------- Reviews ----------
class TestReviews:
    def test_add_review_updates_rating(self, tenant_client):
        items = requests.get(f"{BASE_URL}/api/properties").json()
        pid = items[0]["id"]
        r = tenant_client.post(
            f"{BASE_URL}/api/reviews",
            json={"property_id": pid, "rating": 5, "comment": "TEST_Great place"},
        )
        assert r.status_code == 200, r.text
        # Verify rating updated
        prop = requests.get(f"{BASE_URL}/api/properties/{pid}").json()
        assert prop["review_count"] >= 1
        assert any(x["comment"] == "TEST_Great place" for x in prop["reviews"])

    def test_owner_cannot_review(self, owner_client):
        items = requests.get(f"{BASE_URL}/api/properties").json()
        r = owner_client.post(
            f"{BASE_URL}/api/reviews",
            json={"property_id": items[0]["id"], "rating": 4, "comment": "bad"},
        )
        assert r.status_code == 403


# ---------- Admin ----------
class TestAdmin:
    def test_admin_stats(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/admin/stats")
        assert r.status_code == 200
        d = r.json()
        for k in ["users", "properties", "bookings", "revenue", "revenue_by_type", "payments_count"]:
            assert k in d, f"Missing key: {k}"
        assert d["users"] >= 3 and d["properties"] >= 6

    def test_admin_stats_forbidden_for_tenant(self, tenant_client):
        r = tenant_client.get(f"{BASE_URL}/api/admin/stats")
        assert r.status_code == 403

    def test_admin_stats_forbidden_for_owner(self, owner_client):
        r = owner_client.get(f"{BASE_URL}/api/admin/stats")
        assert r.status_code == 403

    def test_admin_verify_property(self, admin_client, owner_client):
        payload = {
            "title": "TEST_VerifyMe",
            "description": "v",
            "location": "g",
            "address": "a",
            "area": "other",
            "gender": "unisex",
            "rent": 5000,
        }
        cp = owner_client.post(f"{BASE_URL}/api/properties", json=payload).json()
        pid = cp["id"]
        r = admin_client.put(f"{BASE_URL}/api/admin/properties/{pid}/verify")
        assert r.status_code == 200
        prop = requests.get(f"{BASE_URL}/api/properties/{pid}").json()
        assert prop["verified"] is True

    def test_admin_kyc_verify(self, admin_client, tenant_auth):
        uid = tenant_auth["user"]["id"]
        r = admin_client.put(f"{BASE_URL}/api/admin/users/{uid}/kyc-verify")
        assert r.status_code == 200

    def test_admin_users_list(self, admin_client):
        r = admin_client.get(f"{BASE_URL}/api/admin/users")
        assert r.status_code == 200
        users = r.json()
        assert len(users) >= 3
        for u in users:
            assert "password" not in u
            assert "_id" not in u


# ─── Helpers ──────────────────────────────────────────────────────────────────

def random_10_digit() -> int:
    """Return a random 10-digit number suitable for use as an Indian mobile number."""
    return random_phone_int()


import random as _random

def random_phone_int() -> int:
    # Start with 7-9 to look like an Indian number, avoid clashing with seed phones
    first = _random.choice([7, 8, 9])
    rest = _random.randint(100000000, 999999999)
    return int(f"{first}{rest}")
