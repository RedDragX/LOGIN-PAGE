
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
load_dotenv(ROOT_DIR / '.env')

app = FastAPI(title="pgroom API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"

conn = pymysql.connect(
    host=os.environ["DB_HOST"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    database=os.environ["DB_NAME"],
    cursorclass=DictCursor,
    autocommit=True
)

class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    role: str = "tenant"

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    phone: str

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
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: str, role: str):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.replace("Bearer ", "")

    try:
        payload = decode_token(token)
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT id,name,email,phone,role,wallet_balance FROM users WHERE id=%s",
            (payload["sub"],)
        )
        user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


@app.get("/api")
async def root():
    return {
        "status": "running",
        "message": "pgroom mysql backend running"
    }


@app.post("/api/auth/register")
async def register(payload: RegisterIn):

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT id FROM users WHERE email=%s",
            (payload.email,)
        )

        existing = cursor.fetchone()

        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")

        user_id = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT INTO users
            (id,name,email,phone,password,role,wallet_balance,created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
            """,
            (
                user_id,
                payload.name,
                payload.email,
                payload.phone,
                hash_password(payload.password),
                payload.role,
                0
            )
        )

    token = create_token(user_id, payload.role)

    return {
        "message": "Registration successful",
        "token": token
    }


@app.post("/api/auth/login")
async def login(payload: LoginIn):

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (payload.email,)
        )

        user = cursor.fetchone()

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
            "role": user["role"]
        }
    }
@app.get("/api/auth/me")
async def me(user=Depends(get_current_user)):
    return user

@app.post("/api/auth/otp/login/send")
async def otp_login_send(payload: OTPRequest):

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM users WHERE phone=%s",
            (payload.phone,)
        )

        user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="Mobile not registered")

    otp = str(random.randint(1000, 9999))

    with conn.cursor() as cursor:

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS otp_codes (
                phone VARCHAR(20),
                otp VARCHAR(10)
            )
            """
        )

        cursor.execute(
            "DELETE FROM otp_codes WHERE phone=%s",
            (payload.phone,)
        )

        cursor.execute(
            "INSERT INTO otp_codes (phone, otp) VALUES (%s,%s)",
            (payload.phone, otp)
        )

    headers = {
        "accept": "application/json",
        "authkey": "502981Axv013Fima69c64a7cP1",
        "content-type": "application/json"
    }

    data = {
        "template_id": "69c611a05aca2199ae0e0dd2",
        "recipients": [
            {
                "mobiles": f"91{payload.phone}",
                "var1": user["name"],
                "var2": otp
            }
        ]
    }

    try:

        response = requests.post(
            "https://control.msg91.com/api/v5/flow",
            json=data,
            headers=headers
        )

        print(response.text)

    except Exception as e:

        print(str(e))

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

    return {
        "message": "OTP sent successfully"
    }

@app.post("/api/auth/otp/login/verify")
async def otp_login_verify(payload: dict):

    phone = payload.get("phone")
    otp = payload.get("otp")

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM otp_codes WHERE phone=%s AND otp=%s",
            (phone, otp)
        )

        otp_data = cursor.fetchone()

    if not otp_data:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM users WHERE phone=%s",
            (phone,)
        )

        user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token(user["id"], user["role"])

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }
@app.get("/api/properties")
async def get_properties():

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM properties ORDER BY created_at DESC"
        )

        properties = cursor.fetchall()

    return properties


@app.get("/api/properties/{property_id}")
async def property_details(property_id: str):

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM properties WHERE id=%s",
            (property_id,)
        )

        property_data = cursor.fetchone()

    if not property_data:
        raise HTTPException(status_code=404, detail="Property not found")

    return property_data


@app.post("/api/properties")
async def create_property(payload: PropertyIn, user=Depends(get_current_user)):

    if user["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")

    property_id = str(uuid.uuid4())

    with conn.cursor() as cursor:

        cursor.execute(
            """
            INSERT INTO properties
            (
                id,
                owner_id,
                title,
                description,
                location,
                address,
                area,
                gender,
                rent,
                deposit,
                created_at
            )
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
                payload.deposit
            )
        )

    return {
        "message": "Property created",
        "property_id": property_id
    }


@app.post("/api/bookings")
async def create_booking(payload: BookingIn, user=Depends(get_current_user)):

    booking_id = str(uuid.uuid4())

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT * FROM properties WHERE id=%s",
            (payload.property_id,)
        )

        property_data = cursor.fetchone()

        if not property_data:
            raise HTTPException(status_code=404, detail="Property not found")

        cursor.execute(
            """
            INSERT INTO bookings
            (
                id,
                tenant_id,
                property_id,
                visit_date,
                status,
                created_at
            )
            VALUES (%s,%s,%s,%s,%s,NOW())
            """,
            (
                booking_id,
                user["id"],
                payload.property_id,
                payload.visit_date,
                "pending"
            )
        )

    return {
        "message": "Booking created",
        "booking_id": booking_id
    }


@app.get("/api/bookings/me")
async def my_bookings(user=Depends(get_current_user)):

    with conn.cursor() as cursor:

        cursor.execute(
            """
            SELECT b.*, p.title
            FROM bookings b
            JOIN properties p ON b.property_id = p.id
            WHERE b.tenant_id=%s
            ORDER BY b.created_at DESC
            """,
            (user["id"],)
        )

        bookings = cursor.fetchall()

    return bookings


@app.get("/api/admin/stats")
async def admin_stats(user=Depends(get_current_user)):

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    with conn.cursor() as cursor:

        cursor.execute("SELECT COUNT(*) as total FROM users")
        users = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM properties")
        properties = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM bookings")
        bookings = cursor.fetchone()["total"]

    return {
        "users": users,
        "properties": properties,
        "bookings": bookings
    }


@app.on_event("startup")
async def startup_seed():

    with conn.cursor() as cursor:

        cursor.execute(
            "SELECT id FROM users WHERE email='admin@pgroom.in'"
        )

        admin = cursor.fetchone()

        if not admin:

            cursor.execute(
                """
                INSERT INTO users
                (
                    id,
                    name,
                    email,
                    phone,
                    password,
                    role,
                    wallet_balance,
                    created_at
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
                """,
                (
                    str(uuid.uuid4()),
                    "PGRoom Admin",
                    "admin@pgroom.in",
                    "9999999999",
                    hash_password("admin123"),
                    "admin",
                    0
                )
            )

    print("MySQL backend started successfully")

