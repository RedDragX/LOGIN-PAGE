import json
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Any
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor
import os
import uuid
import random
import re
import requests as http_requests
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

app = FastAPI(title="pgroom API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "168"))

DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

MSG91_AUTHKEY = os.environ.get("MSG91_AUTHKEY", "")
MSG91_TEMPLATE_ID = os.environ.get("MSG91_TEMPLATE_ID", "")


# ─── DB HELPERS ───────────────────────────────────────────────────────────────

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True,
        charset="utf8mb4",
    )


def db_fetchone(query, params=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.fetchone()
    finally:
        conn.close()


def db_fetchall(query, params=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.fetchall()
    finally:
        conn.close()


def db_execute(query, params=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.rowcount
    finally:
        conn.close()


def _ensure_column(table: str, column: str, definition: str):
    """Add a column to a table if it doesn't already exist."""
    exists = db_fetchone(
        "SELECT 1 FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s",
        (table, column),
    )
    if not exists:
        try:
            db_execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")
        except Exception as e:
            print(f"Migration warning: {e}")


# ─── SERIALIZATION HELPERS ────────────────────────────────────────────────────

def _parse_json(val, default=None):
    if default is None:
        default = []
    if val is None:
        return default
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return default


def _serialize_property(p: dict) -> dict:
    if not p:
        return p
    p = dict(p)
    for field in ["amenities", "images", "nearby_landmarks", "checklist"]:
        p[field] = _parse_json(p.get(field), [])
    for field in ["verified", "flood_free_zone", "water_24_7"]:
        p[field] = bool(p.get(field, False))
    return p


def _serialize_booking(b: dict) -> dict:
    if not b:
        return b
    b = dict(b)
    for field in ["visit_fee_paid"]:
        b[field] = bool(b.get(field, False))
    return b


def _serialize_user(u: dict) -> dict:
    if not u:
        return u
    u = dict(u)
    u.pop("password", None)
    u["kyc_verified"] = bool(u.get("kyc_verified", False))
    return u


# ─── MODELS ───────────────────────────────────────────────────────────────────

class RegisterIn(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    phone: str
    password: str
    role: str = "tenant"


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class OTPRequest(BaseModel):
    phone: str


class OTPVerifyRequest(BaseModel):
    phone: str
    otp: str


class OTPRegisterRequest(BaseModel):
    name: Optional[str] = None
    fullName: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    mobile: Optional[str] = None
    phoneNumber: Optional[str] = None


class OTPRegisterVerifyIn(BaseModel):
    name: str
    email: Optional[str] = None
    phone: str
    otp: str
    role: str = "tenant"


class KYCIn(BaseModel):
    pan: Optional[str] = None
    voter_id: Optional[str] = None
    aadhaar: Optional[str] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_phone: Optional[str] = None
    emergency_contact_relation: Optional[str] = None


class PropertyIn(BaseModel):
    title: str
    description: str
    location: str
    address: str
    area: str
    gender: str
    rent: int
    deposit: int = 5000
    amenities: List[Any] = []
    images: List[Any] = []
    flood_free_zone: bool = False
    water_24_7: bool = False
    total_rooms: int = 1
    available_rooms: int = 1
    nearby_landmarks: List[Any] = []
    checklist: List[Any] = []


class BookingIn(BaseModel):
    property_id: str
    visit_date: str


class WalletRechargeIn(BaseModel):
    amount: int


class RentPayIn(BaseModel):
    property_id: str
    month: str  # "YYYY-MM"


class ReviewIn(BaseModel):
    property_id: str
    rating: int
    comment: Optional[str] = ""


# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────

def normalize_phone(phone: str) -> str:
    return "".join(ch for ch in (phone or "") if ch.isdigit())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.replace("Bearer ", "")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db_fetchone(
        "SELECT id,name,email,phone,role,wallet_balance,kyc_verified FROM users WHERE id=%s",
        (payload["sub"],),
    )
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return _serialize_user(dict(user))


# ─── SMS HELPER ───────────────────────────────────────────────────────────────

def send_msg91_otp(phone: str, name: str, otp: str) -> dict:
    if not MSG91_AUTHKEY or not MSG91_TEMPLATE_ID:
        return {"delivered": False, "error": "MSG91 not configured"}

    try:
        response = http_requests.post(
            "https://control.msg91.com/api/v5/flow",
            json={
                "template_id": MSG91_TEMPLATE_ID,
                "recipients": [{"mobiles": f"91{phone}", "var1": name, "var2": otp}],
            },
            headers={
                "accept": "application/json",
                "authkey": MSG91_AUTHKEY,
                "content-type": "application/json",
            },
            timeout=15,
        )
        try:
            body = response.json()
        except Exception:
            body = response.text
        return {
            "delivered": 200 <= response.status_code < 300,
            "status_code": response.status_code,
            "response": body,
        }
    except Exception as e:
        return {"delivered": False, "error": str(e)}


# ─── OTP TABLE HELPER ─────────────────────────────────────────────────────────

def _store_otp(phone: str, otp: str):
    db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))
    db_execute(
        "INSERT INTO otp_codes (phone, otp, created_at, expires_at) "
        "VALUES (%s,%s,NOW(),DATE_ADD(NOW(), INTERVAL 10 MINUTE))",
        (phone, otp),
    )


def _verify_otp(phone: str, otp: str) -> bool:
    row = db_fetchone(
        "SELECT 1 FROM otp_codes WHERE phone=%s AND otp=%s AND expires_at > NOW()",
        (phone, otp),
    )
    if row:
        db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))
    return bool(row)


# ─── ROOT ─────────────────────────────────────────────────────────────────────

@app.get("/api")
async def root():
    return {"status": "running", "message": "pgroom mysql backend running"}


# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register")
async def register(payload: RegisterIn):
    phone = normalize_phone(payload.phone)
    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Phone must be a 10-digit number")

    if payload.email and db_fetchone("SELECT id FROM users WHERE email=%s", (payload.email,)):
        raise HTTPException(status_code=400, detail="Email already exists")

    if db_fetchone("SELECT id FROM users WHERE phone=%s", (phone,)):
        raise HTTPException(status_code=400, detail="Phone already exists")

    user_id = str(uuid.uuid4())
    db_execute(
        "INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())",
        (user_id, payload.name, payload.email, phone, hash_password(payload.password), payload.role, 0),
    )
    token = create_token(user_id, payload.role)
    return {
        "message": "Registration successful",
        "token": token,
        "user": {"id": user_id, "name": payload.name, "email": payload.email, "phone": phone, "role": payload.role},
    }


@app.post("/api/auth/login")
async def login(payload: LoginIn):
    user = db_fetchone("SELECT * FROM users WHERE email=%s", (payload.email,))
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user["id"], user["role"])
    return {
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
    }


@app.get("/api/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@app.post("/api/auth/kyc")
async def submit_kyc(payload: KYCIn, user=Depends(get_current_user)):
    """Validate KYC documents. PAN must be 10-char alphanumeric, Aadhaar 12 digits."""
    verified = True
    errors = []

    # PAN validation: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F)
    if payload.pan:
        if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", payload.pan.upper()):
            verified = False
            errors.append("Invalid PAN format")
    
    # Aadhaar validation: 12 digits
    if payload.aadhaar:
        if not re.fullmatch(r"\d{12}", payload.aadhaar.replace(" ", "")):
            verified = False
            errors.append("Invalid Aadhaar number")

    if verified:
        kyc_data = json.dumps({
            "pan": payload.pan,
            "voter_id": payload.voter_id,
            "aadhaar": payload.aadhaar,
            "emergency_contact_name": payload.emergency_contact_name,
            "emergency_contact_phone": payload.emergency_contact_phone,
            "emergency_contact_relation": payload.emergency_contact_relation,
        })
        db_execute(
            "UPDATE users SET kyc_verified=1, kyc_data=%s WHERE id=%s",
            (kyc_data, user["id"]),
        )

    return {"verified": verified, "errors": errors}


# ─── OTP — GENERIC (for KYC phone verification, returns OTP for testing) ──────

@app.post("/api/auth/otp/send")
async def otp_send_generic(payload: OTPRequest):
    """Generic OTP send used during KYC flow. Returns OTP in response for dev/testing."""
    phone = normalize_phone(payload.phone)
    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Enter a valid 10-digit mobile")

    otp = str(random.randint(100000, 999999))
    _store_otp(phone, otp)
    delivery = send_msg91_otp(phone, "User", otp)

    return {
        "message": "OTP sent",
        "otp": otp,               # returned for testing/dev
        "delivered": delivery.get("delivered", False),
        "delivery": delivery,
    }


@app.post("/api/auth/otp/verify")
async def otp_verify_generic(payload: OTPVerifyRequest):
    """Generic OTP verify used during KYC flow."""
    phone = normalize_phone(payload.phone)
    if not _verify_otp(phone, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    return {"message": "Phone verified", "phone": phone}


# ─── OTP — LOGIN ──────────────────────────────────────────────────────────────

@app.post("/api/auth/otp/login/send")
async def otp_login_send(payload: OTPRequest):
    phone = normalize_phone(payload.phone)
    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Enter a valid 10-digit mobile")

    user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if not user:
        raise HTTPException(status_code=404, detail="Mobile not registered")

    otp = str(random.randint(100000, 999999))
    _store_otp(phone, otp)
    delivery = send_msg91_otp(phone, user["name"], otp)

    return {"message": "OTP sent successfully", "delivery": delivery}


@app.post("/api/auth/otp/login/verify")
async def otp_login_verify(payload: OTPVerifyRequest):
    phone = normalize_phone(payload.phone)
    if not _verify_otp(phone, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token(user["id"], user["role"])
    return {
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"], "phone": user["phone"]},
    }


# ─── OTP — REGISTER ───────────────────────────────────────────────────────────

@app.post("/api/auth/otp/register/send")
async def otp_register_send(payload: OTPRegisterRequest):
    data = payload.dict()
    name = data.get("name") or data.get("fullName") or data.get("username") or "User"
    phone = data.get("phone") or data.get("mobile") or data.get("phoneNumber")

    if not phone:
        raise HTTPException(status_code=400, detail="Phone required")
    phone = normalize_phone(phone)
    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Invalid mobile number")

    if db_fetchone("SELECT id FROM users WHERE phone=%s", (phone,)):
        raise HTTPException(status_code=400, detail="Mobile already registered")

    otp = str(random.randint(100000, 999999))
    _store_otp(phone, otp)
    delivery = send_msg91_otp(phone, name, otp)

    return {"message": "OTP sent successfully", "phone": phone, "delivery": delivery}


@app.post("/api/auth/otp/register/verify")
async def otp_register_verify(payload: OTPRegisterVerifyIn):
    phone = normalize_phone(payload.phone)

    if not _verify_otp(phone, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    if db_fetchone("SELECT id FROM users WHERE phone=%s", (phone,)):
        raise HTTPException(status_code=400, detail="User already exists")

    user_id = str(uuid.uuid4())
    db_execute(
        "INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())",
        (user_id, payload.name, payload.email, phone, hash_password(str(uuid.uuid4())), payload.role, 0),
    )
    token = create_token(user_id, payload.role)
    return {
        "message": "Registration successful",
        "token": token,
        "user": {"id": user_id, "name": payload.name, "email": payload.email, "phone": phone, "role": payload.role},
    }


# ─── PROPERTIES ───────────────────────────────────────────────────────────────

@app.get("/api/properties")
async def get_properties(
    area: Optional[str] = None,
    gender: Optional[str] = None,
    min_rent: Optional[int] = None,
    max_rent: Optional[int] = None,
    flood_free: Optional[str] = None,
    water_24_7: Optional[str] = None,
    amenity: Optional[str] = None,
    q: Optional[str] = None,
):
    query = "SELECT * FROM properties WHERE 1=1"
    params = []

    if area:
        query += " AND area=%s"
        params.append(area)
    if gender:
        query += " AND gender=%s"
        params.append(gender)
    if min_rent is not None:
        query += " AND rent >= %s"
        params.append(min_rent)
    if max_rent is not None:
        query += " AND rent <= %s"
        params.append(max_rent)
    if flood_free and flood_free.lower() in ("true", "1", "yes"):
        query += " AND flood_free_zone = 1"
    if water_24_7 and water_24_7.lower() in ("true", "1", "yes"):
        query += " AND water_24_7 = 1"
    if q:
        query += " AND (title LIKE %s OR location LIKE %s OR description LIKE %s)"
        like = f"%{q}%"
        params.extend([like, like, like])

    query += " ORDER BY created_at DESC"
    rows = db_fetchall(query, tuple(params))
    return [_serialize_property(dict(r)) for r in rows]


@app.get("/api/properties/{property_id}")
async def property_details(property_id: str):
    p = db_fetchone("SELECT * FROM properties WHERE id=%s", (property_id,))
    if not p:
        raise HTTPException(status_code=404, detail="Property not found")

    result = _serialize_property(dict(p))

    # Attach reviews
    reviews = db_fetchall(
        "SELECT id, user_name, rating, comment, created_at FROM reviews WHERE property_id=%s ORDER BY created_at DESC",
        (property_id,),
    )
    result["reviews"] = [dict(r) for r in reviews]
    return result


@app.post("/api/properties")
async def create_property(payload: PropertyIn, user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")

    property_id = str(uuid.uuid4())
    db_execute(
        """
        INSERT INTO properties
        (id, owner_id, owner_name, title, description, location, address, area, gender,
         rent, deposit, amenities, images, flood_free_zone, water_24_7,
         total_rooms, available_rooms, nearby_landmarks, checklist,
         verified, rating, review_count, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,0,NOW())
        """,
        (
            property_id, user["id"], user["name"],
            payload.title, payload.description, payload.location, payload.address,
            payload.area, payload.gender, payload.rent, payload.deposit,
            json.dumps(payload.amenities), json.dumps(payload.images),
            int(payload.flood_free_zone), int(payload.water_24_7),
            payload.total_rooms, payload.available_rooms,
            json.dumps(payload.nearby_landmarks), json.dumps(payload.checklist),
        ),
    )

    p = db_fetchone("SELECT * FROM properties WHERE id=%s", (property_id,))
    result = _serialize_property(dict(p))
    result["reviews"] = []
    return result


# ─── BOOKINGS ─────────────────────────────────────────────────────────────────

@app.post("/api/bookings")
async def create_booking(payload: BookingIn, user=Depends(get_current_user)):
    if user["role"] != "tenant":
        raise HTTPException(status_code=403, detail="Only tenants can create bookings")

    prop = db_fetchone("SELECT * FROM properties WHERE id=%s", (payload.property_id,))
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")

    booking_id = str(uuid.uuid4())
    db_execute(
        """
        INSERT INTO bookings
        (id, tenant_id, property_id, visit_date, status, visit_fee, visit_fee_paid, advance_paid, created_at)
        VALUES (%s,%s,%s,%s,'pending_payment',500,0,0,NOW())
        """,
        (booking_id, user["id"], payload.property_id, payload.visit_date),
    )

    b = db_fetchone("SELECT * FROM bookings WHERE id=%s", (booking_id,))
    return _serialize_booking(dict(b))


@app.get("/api/bookings/me")
async def my_bookings(user=Depends(get_current_user)):
    rows = db_fetchall(
        """
        SELECT b.*, p.title AS property_title
        FROM bookings b
        JOIN properties p ON b.property_id = p.id
        WHERE b.tenant_id=%s
        ORDER BY b.created_at DESC
        """,
        (user["id"],),
    )
    return [_serialize_booking(dict(r)) for r in rows]


@app.post("/api/bookings/{booking_id}/pay-visit-fee")
async def pay_visit_fee(booking_id: str, user=Depends(get_current_user)):
    b = db_fetchone("SELECT * FROM bookings WHERE id=%s AND tenant_id=%s", (booking_id, user["id"]))
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")

    db_execute(
        "UPDATE bookings SET visit_fee_paid=1, status='scheduled' WHERE id=%s",
        (booking_id,),
    )
    # Record payment
    db_execute(
        "INSERT INTO payments (id, user_id, type, amount, property_id, total, created_at) "
        "VALUES (%s,%s,'visit_fee',500,%s,500,NOW())",
        (str(uuid.uuid4()), user["id"], b["property_id"]),
    )

    b = db_fetchone("SELECT * FROM bookings WHERE id=%s", (booking_id,))
    return _serialize_booking(dict(b))


@app.post("/api/bookings/{booking_id}/move-in")
async def move_in(booking_id: str, user=Depends(get_current_user)):
    b = db_fetchone("SELECT * FROM bookings WHERE id=%s AND tenant_id=%s", (booking_id, user["id"]))
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")

    prop = db_fetchone("SELECT deposit FROM properties WHERE id=%s", (b["property_id"],))
    advance = prop["deposit"] if prop else 5000

    u = db_fetchone("SELECT wallet_balance FROM users WHERE id=%s", (user["id"],))
    if not u or u["wallet_balance"] < advance:
        raise HTTPException(status_code=400, detail=f"Insufficient wallet balance. Need ₹{advance}")

    db_execute("UPDATE users SET wallet_balance=wallet_balance-%s WHERE id=%s", (advance, user["id"]))
    db_execute(
        "UPDATE bookings SET status='moved_in', advance_paid=%s WHERE id=%s",
        (advance, booking_id),
    )
    db_execute(
        "INSERT INTO payments (id, user_id, type, amount, property_id, total, created_at) "
        "VALUES (%s,%s,'advance',%s,%s,%s,NOW())",
        (str(uuid.uuid4()), user["id"], advance, b["property_id"], advance),
    )

    b = db_fetchone("SELECT * FROM bookings WHERE id=%s", (booking_id,))
    return _serialize_booking(dict(b))


@app.post("/api/bookings/{booking_id}/exit")
async def exit_booking(booking_id: str, user=Depends(get_current_user)):
    b = db_fetchone("SELECT * FROM bookings WHERE id=%s AND tenant_id=%s", (booking_id, user["id"]))
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")

    exit_after = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")
    db_execute(
        "UPDATE bookings SET status='exit_notice', exit_after=%s WHERE id=%s",
        (exit_after, booking_id),
    )
    b = db_fetchone("SELECT * FROM bookings WHERE id=%s", (booking_id,))
    return _serialize_booking(dict(b))


# ─── WALLET ───────────────────────────────────────────────────────────────────

@app.post("/api/wallet/recharge")
async def wallet_recharge(payload: WalletRechargeIn, user=Depends(get_current_user)):
    if payload.amount < 100:
        raise HTTPException(status_code=400, detail="Minimum recharge is ₹100")

    db_execute("UPDATE users SET wallet_balance=wallet_balance+%s WHERE id=%s", (payload.amount, user["id"]))
    db_execute(
        "INSERT INTO payments (id, user_id, type, amount, total, created_at) "
        "VALUES (%s,%s,'wallet_recharge',%s,%s,NOW())",
        (str(uuid.uuid4()), user["id"], payload.amount, payload.amount),
    )

    updated = db_fetchone("SELECT wallet_balance FROM users WHERE id=%s", (user["id"],))
    return {"message": "Wallet recharged", "wallet_balance": updated["wallet_balance"]}


@app.get("/api/payments/me")
async def my_payments(user=Depends(get_current_user)):
    rows = db_fetchall(
        "SELECT * FROM payments WHERE user_id=%s ORDER BY created_at DESC",
        (user["id"],),
    )
    return [dict(r) for r in rows]


# ─── RENT ─────────────────────────────────────────────────────────────────────

@app.post("/api/rent/pay")
async def pay_rent(payload: RentPayIn, user=Depends(get_current_user)):
    prop = db_fetchone("SELECT * FROM properties WHERE id=%s", (payload.property_id,))
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")

    rent = prop["rent"]
    today = datetime.now(timezone.utc).day
    penalty = max(0, (today - 8) * 500) if today > 8 else 0
    total = rent + penalty

    u = db_fetchone("SELECT wallet_balance FROM users WHERE id=%s", (user["id"],))
    if not u or u["wallet_balance"] < total:
        raise HTTPException(status_code=400, detail=f"Insufficient wallet balance. Need ₹{total}")

    db_execute("UPDATE users SET wallet_balance=wallet_balance-%s WHERE id=%s", (total, user["id"]))

    invoice_no = f"INV-{uuid.uuid4().hex[:8].upper()}"
    payment_id = str(uuid.uuid4())
    db_execute(
        "INSERT INTO payments (id, user_id, type, amount, property_id, month, invoice_no, penalty, total, created_at) "
        "VALUES (%s,%s,'rent',%s,%s,%s,%s,%s,%s,NOW())",
        (payment_id, user["id"], rent, payload.property_id, payload.month, invoice_no, penalty, total),
    )

    return {
        "message": "Rent paid",
        "invoice_no": invoice_no,
        "rent": rent,
        "penalty": penalty,
        "total": total,
        "month": payload.month,
    }


# ─── REVIEWS ──────────────────────────────────────────────────────────────────

@app.post("/api/reviews")
async def add_review(payload: ReviewIn, user=Depends(get_current_user)):
    if user["role"] != "tenant":
        raise HTTPException(status_code=403, detail="Only tenants can leave reviews")

    if not db_fetchone("SELECT id FROM properties WHERE id=%s", (payload.property_id,)):
        raise HTTPException(status_code=404, detail="Property not found")

    review_id = str(uuid.uuid4())
    db_execute(
        "INSERT INTO reviews (id, tenant_id, property_id, rating, comment, user_name, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,NOW())",
        (review_id, user["id"], payload.property_id, payload.rating, payload.comment, user["name"]),
    )

    # Update property rating and review_count
    agg = db_fetchone(
        "SELECT COUNT(*) AS cnt, AVG(rating) AS avg_rating FROM reviews WHERE property_id=%s",
        (payload.property_id,),
    )
    db_execute(
        "UPDATE properties SET review_count=%s, rating=%s WHERE id=%s",
        (agg["cnt"], round(agg["avg_rating"] or 0, 1), payload.property_id),
    )

    return {"message": "Review submitted", "review_id": review_id}


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    users_count = db_fetchone("SELECT COUNT(*) AS total FROM users")
    props_count = db_fetchone("SELECT COUNT(*) AS total FROM properties")
    bookings_count = db_fetchone("SELECT COUNT(*) AS total FROM bookings")

    # Revenue stats
    revenue_row = db_fetchone("SELECT COALESCE(SUM(total),0) AS total FROM payments")
    payments_count_row = db_fetchone("SELECT COUNT(*) AS cnt FROM payments")

    revenue_by_type_rows = db_fetchall(
        "SELECT type, COALESCE(SUM(total),0) AS total FROM payments GROUP BY type"
    )
    revenue_by_type = {r["type"]: r["total"] for r in revenue_by_type_rows}

    return {
        "users": users_count["total"] if users_count else 0,
        "properties": props_count["total"] if props_count else 0,
        "bookings": bookings_count["total"] if bookings_count else 0,
        "revenue": revenue_row["total"] if revenue_row else 0,
        "revenue_by_type": revenue_by_type,
        "payments_count": payments_count_row["cnt"] if payments_count_row else 0,
    }


@app.put("/api/admin/properties/{property_id}/verify")
async def admin_verify_property(property_id: str, user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    if not db_fetchone("SELECT id FROM properties WHERE id=%s", (property_id,)):
        raise HTTPException(status_code=404, detail="Property not found")

    db_execute("UPDATE properties SET verified=1 WHERE id=%s", (property_id,))
    return {"message": "Property verified", "property_id": property_id}


@app.put("/api/admin/users/{user_id}/kyc-verify")
async def admin_kyc_verify(user_id: str, user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    if not db_fetchone("SELECT id FROM users WHERE id=%s", (user_id,)):
        raise HTTPException(status_code=404, detail="User not found")

    db_execute("UPDATE users SET kyc_verified=1 WHERE id=%s", (user_id,))
    return {"message": "KYC verified", "user_id": user_id}


@app.get("/api/admin/users")
async def admin_list_users(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    rows = db_fetchall(
        "SELECT id, name, email, phone, role, wallet_balance, kyc_verified, created_at FROM users ORDER BY created_at DESC"
    )
    return [dict(r) for r in rows]


# ─── STARTUP / SEED ───────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_seed():
    # ── Create tables ──────────────────────────────────────────────────────
    db_execute("""
        CREATE TABLE IF NOT EXISTS users (
            id           VARCHAR(36)  PRIMARY KEY,
            name         VARCHAR(255) NOT NULL,
            email        VARCHAR(255) UNIQUE,
            phone        VARCHAR(20)  UNIQUE NOT NULL,
            password     VARCHAR(255) NOT NULL,
            role         VARCHAR(20)  DEFAULT 'tenant',
            wallet_balance INT        DEFAULT 0,
            kyc_verified TINYINT(1)  DEFAULT 0,
            kyc_data     TEXT,
            created_at   DATETIME    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    db_execute("""
        CREATE TABLE IF NOT EXISTS properties (
            id               VARCHAR(36)   PRIMARY KEY,
            owner_id         VARCHAR(36),
            owner_name       VARCHAR(255),
            title            VARCHAR(255)  NOT NULL,
            description      TEXT,
            location         VARCHAR(255),
            address          VARCHAR(255),
            area             VARCHAR(100),
            gender           VARCHAR(20),
            rent             INT,
            deposit          INT           DEFAULT 5000,
            verified         TINYINT(1)   DEFAULT 0,
            flood_free_zone  TINYINT(1)   DEFAULT 0,
            water_24_7       TINYINT(1)   DEFAULT 0,
            amenities        TEXT,
            images           TEXT,
            rating           FLOAT         DEFAULT 0,
            review_count     INT           DEFAULT 0,
            available_rooms  INT           DEFAULT 1,
            total_rooms      INT           DEFAULT 1,
            nearby_landmarks TEXT,
            checklist        TEXT,
            created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    db_execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id             VARCHAR(36) PRIMARY KEY,
            tenant_id      VARCHAR(36),
            property_id    VARCHAR(36),
            visit_date     VARCHAR(20),
            status         VARCHAR(50) DEFAULT 'pending_payment',
            visit_fee      INT         DEFAULT 500,
            visit_fee_paid TINYINT(1) DEFAULT 0,
            advance_paid   INT         DEFAULT 0,
            exit_after     VARCHAR(30),
            created_at     DATETIME    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    db_execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id          VARCHAR(36) PRIMARY KEY,
            tenant_id   VARCHAR(36),
            property_id VARCHAR(36),
            rating      INT         NOT NULL,
            comment     TEXT,
            user_name   VARCHAR(255),
            created_at  DATETIME    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    db_execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id          VARCHAR(36) PRIMARY KEY,
            user_id     VARCHAR(36),
            type        VARCHAR(50),
            amount      INT,
            property_id VARCHAR(36),
            month       VARCHAR(20),
            invoice_no  VARCHAR(50),
            penalty     INT         DEFAULT 0,
            total       INT,
            created_at  DATETIME    DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    db_execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            phone      VARCHAR(20) PRIMARY KEY,
            otp        VARCHAR(10) NOT NULL,
            created_at DATETIME    DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME    NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Migrate existing tables (add missing columns) ──────────────────────
    _ensure_column("users", "kyc_verified", "TINYINT(1) DEFAULT 0")
    _ensure_column("users", "kyc_data", "TEXT")
    _ensure_column("properties", "owner_name", "VARCHAR(255)")
    _ensure_column("properties", "verified", "TINYINT(1) DEFAULT 0")
    _ensure_column("properties", "flood_free_zone", "TINYINT(1) DEFAULT 0")
    _ensure_column("properties", "water_24_7", "TINYINT(1) DEFAULT 0")
    _ensure_column("properties", "amenities", "TEXT")
    _ensure_column("properties", "images", "TEXT")
    _ensure_column("properties", "rating", "FLOAT DEFAULT 0")
    _ensure_column("properties", "review_count", "INT DEFAULT 0")
    _ensure_column("properties", "available_rooms", "INT DEFAULT 1")
    _ensure_column("properties", "total_rooms", "INT DEFAULT 1")
    _ensure_column("properties", "nearby_landmarks", "TEXT")
    _ensure_column("properties", "checklist", "TEXT")
    _ensure_column("bookings", "status", "VARCHAR(50) DEFAULT 'pending_payment'")
    _ensure_column("bookings", "visit_fee", "INT DEFAULT 500")
    _ensure_column("bookings", "visit_fee_paid", "TINYINT(1) DEFAULT 0")
    _ensure_column("bookings", "advance_paid", "INT DEFAULT 0")
    _ensure_column("bookings", "exit_after", "VARCHAR(30)")

    # ── Seed users ─────────────────────────────────────────────────────────
    seed_users = [
        ("PGRoom Admin",    "admin@pgroom.in",  "9999999999", "admin123",  "admin"),
        ("PG Owner",        "owner@pgroom.in",  "9888888888", "pass1234",  "owner"),
        ("Test Tenant",     "tenant@pgroom.in", "9777777777", "pass1234",  "tenant"),
    ]
    for name, email, phone, pwd, role in seed_users:
        if not db_fetchone("SELECT id FROM users WHERE email=%s", (email,)):
            db_execute(
                "INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,0,NOW())",
                (str(uuid.uuid4()), name, email, phone, hash_password(pwd), role),
            )

    # ── Seed properties (need >=6 for admin stats test) ────────────────────
    if db_fetchone("SELECT COUNT(*) AS cnt FROM properties", ())["cnt"] < 6:
        owner = db_fetchone("SELECT id, name FROM users WHERE email='owner@pgroom.in'")
        owner_id = owner["id"] if owner else str(uuid.uuid4())
        owner_name = owner["name"] if owner else "PG Owner"

        seed_props = [
            {
                "title": "Sunrise Boys PG",
                "description": "Comfortable boys PG near IIT Guwahati. Flood-free zone with 24/7 water.",
                "location": "Six Mile, Guwahati",
                "address": "Near IIT Gate, Six Mile, Guwahati 781022",
                "area": "six_mile",
                "gender": "boys",
                "rent": 7500,
                "deposit": 5000,
                "flood_free_zone": 1,
                "water_24_7": 1,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "AC", "Food", "Power Backup"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800"]),
                "rating": 4.8,
                "review_count": 32,
                "total_rooms": 20,
                "available_rooms": 5,
                "nearby_landmarks": json.dumps(["IIT Guwahati 500m", "Six Mile Market 200m"]),
                "checklist": json.dumps([{"name": "Bed", "price": 5000}, {"name": "Table", "price": 2000}]),
            },
            {
                "title": "Lakshmi Girls PG",
                "description": "Safe girls PG in Beltola. CCTV, biometric entry, home food available.",
                "location": "Beltola, Guwahati",
                "address": "House No 42, Beltola, Guwahati 781028",
                "area": "beltola",
                "gender": "girls",
                "rent": 8500,
                "deposit": 5000,
                "flood_free_zone": 1,
                "water_24_7": 1,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "Food", "CCTV", "Geyser"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1555854877-bab0e564b8d5?w=800"]),
                "rating": 4.6,
                "review_count": 18,
                "total_rooms": 15,
                "available_rooms": 3,
                "nearby_landmarks": json.dumps(["Beltola Market 300m", "Apollo Hospital 1km"]),
                "checklist": json.dumps([{"name": "Wardrobe", "price": 4000}]),
            },
            {
                "title": "Green Valley Co-Living",
                "description": "Modern co-living space near Gauhati University. Unisex, fully furnished.",
                "location": "Zoo Road, Guwahati",
                "address": "Lane 3, Zoo Road, Guwahati 781005",
                "area": "zoo_road",
                "gender": "unisex",
                "rent": 9000,
                "deposit": 5000,
                "flood_free_zone": 0,
                "water_24_7": 1,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "AC", "Gym", "Laundry"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1502672260266-1c1ef2d93688?w=800"]),
                "rating": 4.5,
                "review_count": 12,
                "total_rooms": 25,
                "available_rooms": 8,
                "nearby_landmarks": json.dumps(["Gauhati University 800m", "Zoo Road Market 400m"]),
                "checklist": json.dumps([{"name": "AC", "price": 15000}]),
            },
            {
                "title": "Jalukbari Boys PG",
                "description": "Budget-friendly boys PG near Cotton University. Good food, calm locality.",
                "location": "Jalukbari, Guwahati",
                "address": "Near Cotton University, Jalukbari, Guwahati 781014",
                "area": "jalukbari",
                "gender": "boys",
                "rent": 6500,
                "deposit": 5000,
                "flood_free_zone": 1,
                "water_24_7": 0,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "Food", "Power Backup"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?w=800"]),
                "rating": 4.2,
                "review_count": 9,
                "total_rooms": 12,
                "available_rooms": 2,
                "nearby_landmarks": json.dumps(["Cotton University 300m", "Jalukbari Flyover 500m"]),
                "checklist": json.dumps([]),
            },
            {
                "title": "Khanapara Girls Hostel",
                "description": "Premium girls hostel near IIMB campus. 24/7 security, mess included.",
                "location": "Khanapara, Guwahati",
                "address": "Near Veterinary College, Khanapara, Guwahati 781022",
                "area": "khanapara",
                "gender": "girls",
                "rent": 8000,
                "deposit": 5000,
                "flood_free_zone": 1,
                "water_24_7": 1,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "Food", "CCTV", "Geyser", "AC"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=800"]),
                "rating": 4.7,
                "review_count": 24,
                "total_rooms": 18,
                "available_rooms": 4,
                "nearby_landmarks": json.dumps(["Veterinary College 200m", "Khanapara Police Point 1km"]),
                "checklist": json.dumps([{"name": "Geyser", "price": 3000}]),
            },
            {
                "title": "Ganeshguri Co-Living Hub",
                "description": "Trendy co-living in Ganeshguri. Best connectivity, near Paltan Bazar.",
                "location": "Ganeshguri, Guwahati",
                "address": "Ganeshguri Chariali, Guwahati 781006",
                "area": "ganeshguri",
                "gender": "unisex",
                "rent": 7000,
                "deposit": 5000,
                "flood_free_zone": 0,
                "water_24_7": 0,
                "verified": 0,
                "amenities": json.dumps(["WiFi", "AC", "Parking"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1598928506311-c55ded91a20c?w=800"]),
                "rating": 4.0,
                "review_count": 6,
                "total_rooms": 10,
                "available_rooms": 3,
                "nearby_landmarks": json.dumps(["Ganeshguri Market 100m", "Paltan Bazar 3km"]),
                "checklist": json.dumps([]),
            },
            {
                "title": "Beltola Premium PG",
                "description": "High-end PG in Beltola with all amenities. Flood-safe location.",
                "location": "Beltola, Guwahati",
                "address": "VIP Road, Beltola, Guwahati 781028",
                "area": "beltola",
                "gender": "boys",
                "rent": 10000,
                "deposit": 5000,
                "flood_free_zone": 1,
                "water_24_7": 1,
                "verified": 1,
                "amenities": json.dumps(["WiFi", "AC", "Food", "Gym", "Laundry", "Parking"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1515263487990-61b07816b324?w=800"]),
                "rating": 4.9,
                "review_count": 41,
                "total_rooms": 30,
                "available_rooms": 7,
                "nearby_landmarks": json.dumps(["Beltola Tiniali 500m", "Apollo Hospital 800m"]),
                "checklist": json.dumps([{"name": "AC", "price": 15000}, {"name": "Fridge", "price": 8000}]),
            },
            {
                "title": "Six Mile Budget PG",
                "description": "Affordable PG near IIT and NEHU. Good for students on a budget.",
                "location": "Six Mile, Guwahati",
                "address": "North Guwahati Road, Six Mile, Guwahati 781022",
                "area": "six_mile",
                "gender": "unisex",
                "rent": 5500,
                "deposit": 5000,
                "flood_free_zone": 0,
                "water_24_7": 1,
                "verified": 0,
                "amenities": json.dumps(["WiFi", "Power Backup"]),
                "images": json.dumps(["https://images.unsplash.com/photo-1484154218962-a197022b5858?w=800"]),
                "rating": 3.8,
                "review_count": 5,
                "total_rooms": 8,
                "available_rooms": 2,
                "nearby_landmarks": json.dumps(["NEHU 1km", "Six Mile Hospital 600m"]),
                "checklist": json.dumps([]),
            },
        ]

        for prop in seed_props:
            db_execute(
                """
                INSERT INTO properties
                (id, owner_id, owner_name, title, description, location, address, area, gender,
                 rent, deposit, flood_free_zone, water_24_7, verified, amenities, images,
                 rating, review_count, total_rooms, available_rooms,
                 nearby_landmarks, checklist, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """,
                (
                    str(uuid.uuid4()), owner_id, owner_name,
                    prop["title"], prop["description"], prop["location"], prop["address"],
                    prop["area"], prop["gender"], prop["rent"], prop["deposit"],
                    prop["flood_free_zone"], prop["water_24_7"], prop["verified"],
                    prop["amenities"], prop["images"],
                    prop["rating"], prop["review_count"],
                    prop["total_rooms"], prop["available_rooms"],
                    prop["nearby_landmarks"], prop["checklist"],
                ),
            )

    print("✅ pgroom MySQL backend started successfully")
