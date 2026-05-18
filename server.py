from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor
import os
import uuid
import random
import requests
import jwt
import bcrypt
from datetime import datetime, timedelta
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


def normalize_phone(phone: str) -> str:
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    return digits


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


# --- NEW: OTP-based registration verify (no password required) ---
class OTPRegisterVerifyIn(BaseModel):
    name: str
    email: Optional[str] = None
    phone: str
    otp: str
    role: str = "tenant"


class PropertyIn(BaseModel):
    title: str
    description: str
    location: str
    address: str
    area: str
    gender: str
    rent: int
    deposit: int = 5000


class BookingIn(BaseModel):
    property_id: str
    visit_date: str


def hash_password(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user_id: str, role: str):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def send_msg91_otp(phone: str, name: str, otp: str):
    if not MSG91_AUTHKEY or not MSG91_TEMPLATE_ID:
        return {
            "delivered": False,
            "error": "MSG91 not configured",
        }

    headers = {
        "accept": "application/json",
        "authkey": MSG91_AUTHKEY,
        "content-type": "application/json",
    }

    data = {
        "template_id": MSG91_TEMPLATE_ID,
        "recipients": [
            {
                "mobiles": f"91{phone}",
                "var1": name,
                "var2": otp,
            }
        ],
    }

    try:
        response = requests.post(
            "https://control.msg91.com/api/v5/flow",
            json=data,
            headers=headers,
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
        return {
            "delivered": False,
            "error": str(e),
        }


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.replace("Bearer ", "")

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db_fetchone(
        "SELECT id,name,email,phone,role,wallet_balance FROM users WHERE id=%s",
        (payload["sub"],),
    )

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


@app.get("/api")
async def root():
    return {"status": "running", "message": "pgroom mysql backend running"}


@app.post("/api/auth/register")
async def register(payload: RegisterIn):
    phone = normalize_phone(payload.phone)

    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Phone must be a 10-digit number")

    existing_email = db_fetchone("SELECT id FROM users WHERE email=%s", (payload.email,))
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    existing_phone = db_fetchone("SELECT id FROM users WHERE phone=%s", (phone,))
    if existing_phone:
        raise HTTPException(status_code=400, detail="Phone already exists")

    user_id = str(uuid.uuid4())

    db_execute(
        """
        INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
        """,
        (user_id, payload.name, payload.email, phone, hash_password(payload.password), payload.role, 0),
    )

    token = create_token(user_id, payload.role)

    return {
        "message": "Registration successful",
        "token": token,
        "user": {
            "id": user_id,
            "name": payload.name,
            "email": payload.email,
            "phone": phone,
            "role": payload.role,
        },
    }


@app.post("/api/auth/login")
async def login(payload: LoginIn):
    user = db_fetchone("SELECT * FROM users WHERE email=%s", (payload.email,))

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user["id"], user["role"])

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
        },
    }


@app.get("/api/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ─── OTP LOGIN ────────────────────────────────────────────────────────────────

@app.post("/api/auth/otp/login/send")
async def otp_login_send(payload: OTPRequest):
    phone = normalize_phone(payload.phone)

    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Enter a valid 10-digit mobile")

    user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if not user:
        raise HTTPException(status_code=404, detail="Mobile not registered")

    otp = str(random.randint(100000, 999999))  # 6-digit OTP

    _ensure_otp_table()

    db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))
    db_execute(
        "INSERT INTO otp_codes (phone, otp, created_at, expires_at) VALUES (%s,%s,NOW(),DATE_ADD(NOW(), INTERVAL 10 MINUTE))",
        (phone, otp),
    )

    delivery = send_msg91_otp(phone, user["name"], otp)

    # NOTE: otp is NOT returned in the response — never expose it to the client
    return {
        "message": "OTP sent successfully",
        "delivery": delivery,
    }


@app.post("/api/auth/otp/login/verify")
async def otp_login_verify(payload: OTPVerifyRequest):
    phone = normalize_phone(payload.phone)

    otp_row = db_fetchone(
        "SELECT * FROM otp_codes WHERE phone=%s AND otp=%s AND expires_at > NOW()",
        (phone, payload.otp),
    )

    if not otp_row:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Consume the OTP so it can't be reused
    db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))

    user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token(user["id"], user["role"])

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "phone": user["phone"],
        },
    }


# ─── OTP REGISTER ─────────────────────────────────────────────────────────────

@app.post("/api/auth/otp/register/send")
async def otp_register_send(payload: OTPRegisterRequest):
    data = payload.dict()

    name = (
        data.get("name")
        or data.get("fullName")
        or data.get("username")
        or "User"
    )

    phone = data.get("phone") or data.get("mobile") or data.get("phoneNumber")

    if not phone:
        raise HTTPException(status_code=400, detail="Phone required")

    phone = normalize_phone(phone)

    if len(phone) != 10:
        raise HTTPException(status_code=400, detail="Invalid mobile number")

    existing_user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if existing_user:
        raise HTTPException(status_code=400, detail="Mobile already registered")

    otp = str(random.randint(100000, 999999))  # 6-digit OTP

    _ensure_otp_table()

    db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))
    db_execute(
        "INSERT INTO otp_codes (phone, otp, created_at, expires_at) VALUES (%s,%s,NOW(),DATE_ADD(NOW(), INTERVAL 10 MINUTE))",
        (phone, otp),
    )

    delivery = send_msg91_otp(phone, name, otp)

    # NOTE: otp is NOT returned in the response — never expose it to the client
    return {
        "message": "OTP sent successfully",
        "phone": phone,
        "delivery": delivery,
    }


@app.post("/api/auth/otp/register/verify")
async def otp_register_verify(payload: OTPRegisterVerifyIn):
    """
    Verify OTP and create the account in one step.
    No password is required — OTP is the credential for this flow.
    A random internal password is set; user can reset it later if needed.
    """
    phone = normalize_phone(payload.phone)

    # Verify OTP value AND expiry
    otp_row = db_fetchone(
        "SELECT * FROM otp_codes WHERE phone=%s AND otp=%s AND expires_at > NOW()",
        (phone, payload.otp),
    )

    if not otp_row:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Consume the OTP so it can't be reused
    db_execute("DELETE FROM otp_codes WHERE phone=%s", (phone,))

    existing_user = db_fetchone("SELECT * FROM users WHERE phone=%s", (phone,))
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    user_id = str(uuid.uuid4())
    # Generate a random internal password — user logged in via OTP, no password needed
    internal_password = hash_password(str(uuid.uuid4()))

    db_execute(
        """
        INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
        """,
        (user_id, payload.name, payload.email, phone, internal_password, payload.role, 0),
    )

    token = create_token(user_id, payload.role)

    return {
        "message": "Registration successful",
        "token": token,
        "user": {
            "id": user_id,
            "name": payload.name,
            "email": payload.email,
            "phone": phone,
            "role": payload.role,
        },
    }


# ─── PROPERTIES ───────────────────────────────────────────────────────────────

@app.get("/api/properties")
async def get_properties(
    area: Optional[str] = None,
    gender: Optional[str] = None,
    min_rent: Optional[int] = None,
    max_rent: Optional[int] = None,
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

    if q:
        query += " AND (title LIKE %s OR location LIKE %s OR description LIKE %s)"
        like = f"%{q}%"
        params.extend([like, like, like])

    query += " ORDER BY created_at DESC"

    return db_fetchall(query, tuple(params))


@app.get("/api/properties/{property_id}")
async def property_details(property_id: str):
    property_data = db_fetchone("SELECT * FROM properties WHERE id=%s", (property_id,))

    if not property_data:
        raise HTTPException(status_code=404, detail="Property not found")

    return property_data


@app.post("/api/properties")
async def create_property(payload: PropertyIn, user=Depends(get_current_user)):
    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")

    property_id = str(uuid.uuid4())

    db_execute(
        """
        INSERT INTO properties
        (id, owner_id, title, description, location, address, area, gender, rent, deposit, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """,
        (
            property_id,
            user["id"],
            payload.title,
            payload.description,
            payload.location,
            payload.address,
            payload.area,
            payload.gender,
            payload.rent,
            payload.deposit,
        ),
    )

    return {"message": "Property created", "property_id": property_id}


# ─── BOOKINGS ─────────────────────────────────────────────────────────────────

@app.post("/api/bookings")
async def create_booking(payload: BookingIn, user=Depends(get_current_user)):
    booking_id = str(uuid.uuid4())

    property_data = db_fetchone("SELECT * FROM properties WHERE id=%s", (payload.property_id,))
    if not property_data:
        raise HTTPException(status_code=404, detail="Property not found")

    db_execute(
        """
        INSERT INTO bookings (id, tenant_id, property_id, visit_date, status, created_at)
        VALUES (%s,%s,%s,%s,%s,NOW())
        """,
        (booking_id, user["id"], payload.property_id, payload.visit_date, "pending"),
    )

    return {"message": "Booking created", "booking_id": booking_id}


@app.get("/api/bookings/me")
async def my_bookings(user=Depends(get_current_user)):
    bookings = db_fetchall(
        """
        SELECT b.*, p.title
        FROM bookings b
        JOIN properties p ON b.property_id = p.id
        WHERE b.tenant_id=%s
        ORDER BY b.created_at DESC
        """,
        (user["id"],),
    )
    return bookings


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    users = db_fetchone("SELECT COUNT(*) as total FROM users")
    properties = db_fetchone("SELECT COUNT(*) as total FROM properties")
    bookings = db_fetchone("SELECT COUNT(*) as total FROM bookings")

    return {
        "users": users["total"] if users else 0,
        "properties": properties["total"] if properties else 0,
        "bookings": bookings["total"] if bookings else 0,
    }


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _ensure_otp_table():
    db_execute(
        """
        CREATE TABLE IF NOT EXISTS otp_codes (
            phone VARCHAR(20) PRIMARY KEY,
            otp VARCHAR(10) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL
        )
        """
    )


@app.on_event("startup")
async def startup_seed():
    _ensure_otp_table()

    admin = db_fetchone("SELECT id FROM users WHERE email=%s", ("admin@pgroom.in",))
    if not admin:
        db_execute(
            """
            INSERT INTO users (id, name, email, phone, password, role, wallet_balance, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
            """,
            (
                str(uuid.uuid4()),
                "PGRoom Admin",
                "admin@pgroom.in",
                "9999999999",
                hash_password("admin123"),
                "admin",
                0,
            ),
        )

    print("MySQL backend started successfully")
