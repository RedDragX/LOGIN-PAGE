from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import random
import re
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timezone, timedelta

import requests
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'change-me')
JWT_ALG = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRE_HOURS = int(os.environ.get('JWT_EXPIRE_HOURS', '168'))

MSG91_AUTHKEY = os.environ.get('MSG91_AUTHKEY', '')
MSG91_TEMPLATE_ID = os.environ.get('MSG91_TEMPLATE_ID', '')

app = FastAPI(title="pgroom API", version="1.0.0")
api = APIRouter(prefix="/api")

# ---------- Helpers ----------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def make_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(*roles):
    async def _checker(user: dict = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")
        return user
    return _checker

# ---------- Models ----------
Role = Literal["admin", "owner", "tenant"]

class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    role: Role = "tenant"

class OTPRegisterSendIn(BaseModel):
    phone: str

class OTPRegisterVerifyIn(BaseModel):
    name: str
    phone: str
    otp: str
    role: Role = "tenant"
    email: Optional[EmailStr] = None

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    phone: str

class OTPVerify(BaseModel):
    phone: str
    otp: str

class OTPLoginVerify(BaseModel):
    phone: str
    otp: str

class KYCIn(BaseModel):
    pan: Optional[str] = None
    voter_id: Optional[str] = None
    aadhaar: Optional[str] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_relation: Optional[str] = None
    emergency_contact_phone: Optional[str] = None

class PropertyIn(BaseModel):
    title: str
    description: str
    location: str
    address: str
    area: str  # six_mile, beltola, zoo_road, jalukbari, other
    gender: Literal["boys", "girls", "unisex"]
    rent: int
    deposit: int = 5000
    amenities: List[str] = []
    images: List[str] = []
    video_url: Optional[str] = None
    image_360: Optional[str] = None
    flood_free_zone: bool = False
    water_24_7: bool = False
    nearby_landmarks: List[str] = []
    total_rooms: int = 1
    available_rooms: int = 1
    owner_status: Literal["in_guwahati", "outside", "nri"] = "in_guwahati"
    allow_sublease: bool = False
    lat: Optional[float] = None
    lng: Optional[float] = None
    electricity_bill_url: Optional[str] = None
    gmc_receipt_url: Optional[str] = None
    checklist: List[dict] = []  # [{name, image, price}]

class BookingIn(BaseModel):
    property_id: str
    visit_date: str  # ISO date

class WalletRecharge(BaseModel):
    amount: int

class RentPayIn(BaseModel):
    property_id: str
    month: str  # YYYY-MM

class ReviewIn(BaseModel):
    property_id: str
    rating: int
    comment: str

# ---------- Mock OTP/Payment helpers ----------
def normalize_mobile(phone: str) -> str:
    """Strip non-digits, ensure 91 country prefix for India."""
    digits = re.sub(r'\D', '', phone or '')
    if len(digits) == 10:
        return f"91{digits}"
    if len(digits) == 12 and digits.startswith("91"):
        return digits
    return digits

def send_msg91_otp(phone: str, otp: str, name: str = "User") -> dict:
    """Send OTP via MSG91 Flow API. Returns dict with status/details."""
    if not MSG91_AUTHKEY or not MSG91_TEMPLATE_ID:
        logger.warning("[MSG91] AUTHKEY/TEMPLATE_ID missing — falling back to mock")
        return {"sent": False, "mocked": True, "error": "MSG91 not configured"}
    mobile = normalize_mobile(phone)
    if len(mobile) < 12:
        return {"sent": False, "error": "Invalid mobile (need 10-digit Indian number)"}
    try:
        resp = requests.post(
            "https://control.msg91.com/api/v5/flow",
            headers={
                "accept": "application/json",
                "authkey": MSG91_AUTHKEY,
                "content-type": "application/json",
            },
            json={
                "template_id": MSG91_TEMPLATE_ID,
                "recipients": [{
                    "mobiles": mobile,
                    "var1": name[:20],   # tenant name
                    "var2": otp,         # OTP code
                }],
            },
            timeout=10,
        )
        ok = 200 <= resp.status_code < 300
        body = {}
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:200]}
        logger.info(f"[MSG91] phone={mobile} status={resp.status_code} body={body}")
        return {"sent": ok, "status": resp.status_code, "response": body}
    except requests.RequestException as e:
        logger.error(f"[MSG91] error: {e}")
        return {"sent": False, "error": str(e)}

async def issue_otp(phone: str, name: str = "User") -> dict:
    code = f"{random.randint(100000, 999999)}"
    await db.otps.update_one(
        {"phone": phone},
        {"$set": {
            "phone": phone,
            "otp": code,
            "created_at": now_iso(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "verified": False,
        }},
        upsert=True,
    )
    delivery = send_msg91_otp(phone, code, name)
    logger.info(f"[OTP] phone={phone} delivery={delivery.get('sent')} (code stored)")
    return {"code": code, "delivery": delivery}

# ---------- Routes: Health ----------
@api.get("/")
async def root():
    return {"message": "pgroom API", "version": "1.0.0"}

# ---------- Routes: Auth ----------
@api.post("/auth/register")
async def register(payload: RegisterIn):
    existing = await db.users.find_one({"email": payload.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    digits = re.sub(r'\D', '', payload.phone or '')
    if len(digits) != 10:
        raise HTTPException(status_code=400, detail="Phone must be a 10-digit Indian mobile")
    phone_exists = await db.users.find_one({"phone": {"$regex": f"{digits}$"}}, {"_id": 0})
    if phone_exists:
        raise HTTPException(status_code=400, detail="Mobile already registered. Please sign in instead.")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = {
        "id": str(uuid.uuid4()),
        "name": payload.name,
        "email": payload.email,
        "phone": digits,
        "password": hash_pw(payload.password),
        "role": payload.role,
        "email_verified": False,
        "phone_verified": False,
        "kyc": {},
        "kyc_verified": False,
        "wallet_balance": 0,
        "registration_method": "password",
        "created_at": now_iso(),
    }
    await db.users.insert_one(user)
    token = make_token(user["id"], user["role"])
    user.pop("_id", None)
    user.pop("password")
    return {"token": token, "user": user}

@api.post("/auth/login")
async def login(payload: LoginIn):
    u = await db.users.find_one({"email": payload.email})
    if not u or not check_pw(payload.password, u["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = make_token(u["id"], u["role"])
    u.pop("_id", None)
    u.pop("password", None)
    return {"token": token, "user": u}

@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user

@api.post("/auth/otp/send")
async def send_otp(p: OTPRequest, user=Depends(get_current_user)):
    name = user.get("name") if user else "User"
    result = await issue_otp(p.phone, name=name)
    payload = {
        "message": "OTP sent" if result["delivery"].get("sent") else "OTP queued (delivery fallback)",
        "delivered": bool(result["delivery"].get("sent")),
    }
    # Only echo the OTP back if MSG91 delivery failed (so dev/staging still works)
    if not result["delivery"].get("sent"):
        payload["otp"] = result["code"]
        payload["delivery_error"] = result["delivery"].get("error") or result["delivery"].get("response")
    return payload

# ---------- Public passwordless OTP login ----------
@api.post("/auth/otp/login/send")
async def otp_login_send(p: OTPRequest):
    digits = re.sub(r'\D', '', p.phone or '')
    if len(digits) != 10:
        raise HTTPException(status_code=400, detail="Enter a valid 10-digit mobile")
    # Match users whose stored phone ends with these 10 digits (handles +91 prefixes)
    u = await db.users.find_one({"phone": {"$regex": f"{digits}$"}}, {"_id": 0, "password": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Mobile not registered. Please sign up first.")
    result = await issue_otp(digits, name=u["name"])
    payload = {
        "message": "OTP sent" if result["delivery"].get("sent") else "OTP queued (delivery fallback)",
        "delivered": bool(result["delivery"].get("sent")),
        "greeting": u["name"].split(" ")[0],
    }
    if not result["delivery"].get("sent"):
        payload["otp"] = result["code"]
    return payload

@api.post("/auth/otp/login/verify")
async def otp_login_verify(p: OTPLoginVerify):
    digits = re.sub(r'\D', '', p.phone or '')
    rec = await db.otps.find_one({"phone": digits}, {"_id": 0})
    if not rec or rec.get("otp") != p.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    try:
        expires = datetime.fromisoformat(rec["expires_at"])
        if datetime.now(timezone.utc) > expires:
            raise HTTPException(status_code=400, detail="OTP expired. Request a new one.")
    except (KeyError, ValueError):
        pass
    u = await db.users.find_one({"phone": {"$regex": f"{digits}$"}})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    await db.otps.update_one({"phone": digits}, {"$set": {"verified": True}})
    await db.users.update_one({"id": u["id"]}, {"$set": {"phone_verified": True}})
    token = make_token(u["id"], u["role"])
    u.pop("_id", None)
    u.pop("password", None)
    return {"token": token, "user": u}

# ---------- Public passwordless OTP register ----------
@api.post("/auth/otp/register/send")
async def otp_register_send(p: OTPRegisterSendIn):
    digits = re.sub(r'\D', '', p.phone or '')
    if len(digits) != 10:
        raise HTTPException(status_code=400, detail="Enter a valid 10-digit mobile")
    existing = await db.users.find_one({"phone": {"$regex": f"{digits}$"}}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Mobile already registered. Please sign in instead.")
    result = await issue_otp(digits, name="there")
    payload = {
        "message": "OTP sent" if result["delivery"].get("sent") else "OTP queued (delivery fallback)",
        "delivered": bool(result["delivery"].get("sent")),
    }
    if not result["delivery"].get("sent"):
        payload["otp"] = result["code"]
    return payload

@api.post("/auth/otp/register/verify")
async def otp_register_verify(p: OTPRegisterVerifyIn):
    digits = re.sub(r'\D', '', p.phone or '')
    rec = await db.otps.find_one({"phone": digits}, {"_id": 0})
    if not rec or rec.get("otp") != p.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    try:
        expires = datetime.fromisoformat(rec["expires_at"])
        if datetime.now(timezone.utc) > expires:
            raise HTTPException(status_code=400, detail="OTP expired. Request a new one.")
    except (KeyError, ValueError):
        pass
    if await db.users.find_one({"phone": {"$regex": f"{digits}$"}}, {"_id": 0}):
        raise HTTPException(status_code=400, detail="Mobile already registered.")
    if p.email and await db.users.find_one({"email": p.email}, {"_id": 0}):
        raise HTTPException(status_code=400, detail="Email already registered.")
    auto_pw = uuid.uuid4().hex  # random unguessable password (user will use OTP login)
    user = {
        "id": str(uuid.uuid4()),
        "name": p.name,
        "email": p.email or f"otp_{digits}@pgroom.in",
        "phone": digits,
        "password": hash_pw(auto_pw),
        "role": p.role,
        "email_verified": False,
        "phone_verified": True,
        "kyc": {}, "kyc_verified": False,
        "wallet_balance": 0,
        "registration_method": "otp",
        "created_at": now_iso(),
    }
    await db.users.insert_one(user)
    await db.otps.update_one({"phone": digits}, {"$set": {"verified": True}})
    token = make_token(user["id"], user["role"])
    user.pop("_id", None)
    user.pop("password", None)
    return {"token": token, "user": user}

@api.post("/auth/otp/verify")
async def verify_otp(p: OTPVerify, user=Depends(get_current_user)):
    rec = await db.otps.find_one({"phone": p.phone}, {"_id": 0})
    if not rec or rec["otp"] != p.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    await db.otps.update_one({"phone": p.phone}, {"$set": {"verified": True}})
    await db.users.update_one({"id": user["id"]}, {"$set": {"phone_verified": True, "phone": p.phone}})
    return {"message": "Phone verified"}

@api.post("/auth/email/verify")
async def email_verify(user=Depends(get_current_user)):
    # Mock: instantly mark verified
    await db.users.update_one({"id": user["id"]}, {"$set": {"email_verified": True}})
    return {"message": "Email verified (mock)"}

@api.post("/auth/kyc")
async def submit_kyc(payload: KYCIn, user=Depends(get_current_user)):
    kyc = {k: v for k, v in payload.model_dump().items() if v is not None}
    # Mock validators
    valid = True
    if payload.pan and not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', payload.pan):
        valid = False
    if payload.aadhaar and not re.match(r'^\d{12}$', payload.aadhaar):
        valid = False
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"kyc": kyc, "kyc_verified": valid}},
    )
    return {"message": "KYC submitted", "verified": valid}

# ---------- Routes: Properties ----------
@api.get("/properties")
async def list_properties(
    area: Optional[str] = None,
    gender: Optional[str] = None,
    min_rent: Optional[int] = None,
    max_rent: Optional[int] = None,
    flood_free: Optional[bool] = None,
    water_24_7: Optional[bool] = None,
    amenity: Optional[str] = None,
    q: Optional[str] = None,
):
    query = {"is_active": True}
    if area: query["area"] = area
    if gender: query["gender"] = gender
    if flood_free is not None: query["flood_free_zone"] = flood_free
    if water_24_7 is not None: query["water_24_7"] = water_24_7
    if amenity: query["amenities"] = amenity
    if min_rent or max_rent:
        rq = {}
        if min_rent: rq["$gte"] = min_rent
        if max_rent: rq["$lte"] = max_rent
        query["rent"] = rq
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"location": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]
    items = await db.properties.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

@api.get("/properties/{pid}")
async def get_property(pid: str):
    p = await db.properties.find_one({"id": pid}, {"_id": 0})
    if not p:
        raise HTTPException(status_code=404, detail="Property not found")
    # Get reviews
    reviews = await db.reviews.find({"property_id": pid}, {"_id": 0}).to_list(50)
    p["reviews"] = reviews
    return p

@api.post("/properties")
async def create_property(payload: PropertyIn, user=Depends(require_role("owner", "admin"))):
    p = payload.model_dump()
    p["id"] = str(uuid.uuid4())
    p["owner_id"] = user["id"]
    p["owner_name"] = user["name"]
    p["is_active"] = True
    p["verified"] = False  # admin verifies
    p["rating"] = 0
    p["review_count"] = 0
    p["created_at"] = now_iso()
    await db.properties.insert_one(p)
    p.pop("_id", None)
    return p

@api.put("/properties/{pid}")
async def update_property(pid: str, payload: PropertyIn, user=Depends(get_current_user)):
    existing = await db.properties.find_one({"id": pid}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Property not found")
    if user["role"] != "admin" and existing["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    update = payload.model_dump()
    await db.properties.update_one({"id": pid}, {"$set": update})
    p = await db.properties.find_one({"id": pid}, {"_id": 0})
    return p

@api.delete("/properties/{pid}")
async def delete_property(pid: str, user=Depends(get_current_user)):
    existing = await db.properties.find_one({"id": pid}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Property not found")
    if user["role"] != "admin" and existing["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    await db.properties.delete_one({"id": pid})
    return {"message": "Deleted"}

@api.get("/owner/properties")
async def my_properties(user=Depends(require_role("owner", "admin"))):
    items = await db.properties.find({"owner_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return items

# ---------- Routes: Bookings ----------
@api.post("/bookings")
async def create_booking(payload: BookingIn, user=Depends(require_role("tenant"))):
    prop = await db.properties.find_one({"id": payload.property_id}, {"_id": 0})
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")
    booking = {
        "id": str(uuid.uuid4()),
        "tenant_id": user["id"],
        "tenant_name": user["name"],
        "property_id": payload.property_id,
        "property_title": prop["title"],
        "owner_id": prop["owner_id"],
        "visit_date": payload.visit_date,
        "status": "pending_payment",  # pending_payment -> scheduled -> visited -> moved_in -> exited -> cancelled
        "visit_fee": 500,
        "visit_fee_paid": False,
        "created_at": now_iso(),
    }
    await db.bookings.insert_one(booking)
    booking.pop("_id", None)
    return booking

@api.post("/bookings/{bid}/pay-visit-fee")
async def pay_visit_fee(bid: str, user=Depends(require_role("tenant"))):
    b = await db.bookings.find_one({"id": bid}, {"_id": 0})
    if not b or b["tenant_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    # Mock razorpay payment success
    payment = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "booking_id": bid,
        "amount": 500,
        "type": "visit_fee",
        "status": "success",
        "razorpay_order_id": f"mock_order_{uuid.uuid4().hex[:10]}",
        "razorpay_payment_id": f"mock_pay_{uuid.uuid4().hex[:10]}",
        "created_at": now_iso(),
    }
    await db.payments.insert_one(payment)
    await db.bookings.update_one({"id": bid}, {"$set": {"visit_fee_paid": True, "status": "scheduled"}})
    return {"message": "Visit fee paid", "payment_id": payment["id"]}

@api.get("/bookings/me")
async def my_bookings(user=Depends(get_current_user)):
    if user["role"] == "tenant":
        items = await db.bookings.find({"tenant_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    elif user["role"] == "owner":
        items = await db.bookings.find({"owner_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    else:
        items = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

@api.post("/bookings/{bid}/move-in")
async def move_in(bid: str, user=Depends(require_role("tenant"))):
    b = await db.bookings.find_one({"id": bid}, {"_id": 0})
    if not b or b["tenant_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    me_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    if me_user["wallet_balance"] < 5000:
        raise HTTPException(status_code=400, detail="Recharge wallet with ₹5000 advance first")
    await db.users.update_one({"id": user["id"]}, {"$inc": {"wallet_balance": -5000}})
    await db.bookings.update_one({"id": bid}, {"$set": {
        "status": "moved_in",
        "moved_in_at": now_iso(),
        "advance_paid": 5000,
        "agreement_signed": True,
    }})
    return {"message": "Move-in confirmed. Digital agreement signed."}

@api.post("/bookings/{bid}/exit")
async def exit_booking(bid: str, user=Depends(require_role("tenant"))):
    b = await db.bookings.find_one({"id": bid}, {"_id": 0})
    if not b or b["tenant_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Booking not found")
    notice_until = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
    await db.bookings.update_one({"id": bid}, {"$set": {
        "status": "exit_notice",
        "exit_notice_at": now_iso(),
        "exit_completion_after": notice_until,
    }})
    return {"message": "2-month exit notice submitted", "exit_after": notice_until}

# ---------- Routes: Wallet & Payments ----------
@api.post("/wallet/recharge")
async def wallet_recharge(payload: WalletRecharge, user=Depends(get_current_user)):
    if payload.amount < 1:
        raise HTTPException(status_code=400, detail="Invalid amount")
    payment = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "amount": payload.amount,
        "type": "wallet_recharge",
        "status": "success",
        "razorpay_order_id": f"mock_order_{uuid.uuid4().hex[:10]}",
        "razorpay_payment_id": f"mock_pay_{uuid.uuid4().hex[:10]}",
        "created_at": now_iso(),
    }
    await db.payments.insert_one(payment)
    await db.users.update_one({"id": user["id"]}, {"$inc": {"wallet_balance": payload.amount}})
    new_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password": 0})
    return {"message": "Recharge success", "wallet_balance": new_user["wallet_balance"]}

@api.post("/auth/registration-fee")
async def pay_registration_fee(user=Depends(require_role("tenant"))):
    existing = await db.payments.find_one({"user_id": user["id"], "type": "registration_fee", "status": "success"}, {"_id": 0})
    if existing:
        return {"message": "Already paid"}
    payment = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "amount": 50,
        "type": "registration_fee",
        "status": "success",
        "razorpay_order_id": f"mock_order_{uuid.uuid4().hex[:10]}",
        "razorpay_payment_id": f"mock_pay_{uuid.uuid4().hex[:10]}",
        "created_at": now_iso(),
    }
    await db.payments.insert_one(payment)
    await db.users.update_one({"id": user["id"]}, {"$set": {"registration_fee_paid": True}})
    return {"message": "Registration fee paid"}

@api.post("/rent/pay")
async def pay_rent(payload: RentPayIn, user=Depends(require_role("tenant"))):
    booking = await db.bookings.find_one({"tenant_id": user["id"], "property_id": payload.property_id, "status": "moved_in"}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=400, detail="Active booking not found")
    prop = await db.properties.find_one({"id": payload.property_id}, {"_id": 0})
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")
    today = datetime.now(timezone.utc).day
    penalty = 0
    if today > 8:
        penalty = (today - 8) * 500
    total = prop["rent"] + penalty

    me_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    if me_user["wallet_balance"] < total:
        raise HTTPException(status_code=400, detail=f"Insufficient wallet. Need ₹{total} (rent ₹{prop['rent']} + penalty ₹{penalty})")
    await db.users.update_one({"id": user["id"]}, {"$inc": {"wallet_balance": -total}})
    payment = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "owner_id": prop["owner_id"],
        "property_id": payload.property_id,
        "month": payload.month,
        "amount": prop["rent"],
        "penalty": penalty,
        "total": total,
        "type": "rent",
        "status": "success",
        "invoice_no": f"INV-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}",
        "created_at": now_iso(),
    }
    await db.payments.insert_one(payment)
    return {"message": "Rent paid", "invoice_no": payment["invoice_no"], "total": total, "penalty": penalty}

@api.get("/payments/me")
async def my_payments(user=Depends(get_current_user)):
    items = await db.payments.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

# ---------- Routes: Reviews ----------
@api.post("/reviews")
async def add_review(payload: ReviewIn, user=Depends(require_role("tenant"))):
    r = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "user_name": user["name"],
        "property_id": payload.property_id,
        "rating": payload.rating,
        "comment": payload.comment,
        "created_at": now_iso(),
    }
    await db.reviews.insert_one(r)
    # Update property rating
    revs = await db.reviews.find({"property_id": payload.property_id}, {"_id": 0}).to_list(1000)
    if revs:
        avg = sum(x["rating"] for x in revs) / len(revs)
        await db.properties.update_one({"id": payload.property_id}, {"$set": {"rating": round(avg, 1), "review_count": len(revs)}})
    r.pop("_id", None)
    return r

# ---------- Routes: Notifications ----------
@api.get("/notifications/me")
async def my_notifications(user=Depends(get_current_user)):
    items = await db.notifications.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return items

# ---------- Routes: Admin ----------
@api.get("/admin/stats")
async def admin_stats(user=Depends(require_role("admin"))):
    users = await db.users.count_documents({})
    properties = await db.properties.count_documents({})
    bookings = await db.bookings.count_documents({})
    payments_cursor = db.payments.find({"status": "success"}, {"_id": 0, "amount": 1, "type": 1, "created_at": 1})
    payments = await payments_cursor.to_list(10000)
    revenue = sum(p["amount"] for p in payments)
    # By type
    by_type = {}
    for p in payments:
        by_type[p["type"]] = by_type.get(p["type"], 0) + p["amount"]
    return {
        "users": users,
        "properties": properties,
        "bookings": bookings,
        "revenue": revenue,
        "revenue_by_type": by_type,
        "payments_count": len(payments),
    }

@api.get("/admin/users")
async def admin_users(user=Depends(require_role("admin"))):
    items = await db.users.find({}, {"_id": 0, "password": 0}).sort("created_at", -1).to_list(500)
    return items

@api.put("/admin/properties/{pid}/verify")
async def admin_verify_property(pid: str, user=Depends(require_role("admin"))):
    await db.properties.update_one({"id": pid}, {"$set": {"verified": True}})
    return {"message": "Verified"}

@api.put("/admin/users/{uid}/kyc-verify")
async def admin_verify_kyc(uid: str, user=Depends(require_role("admin"))):
    await db.users.update_one({"id": uid}, {"$set": {"kyc_verified": True}})
    return {"message": "KYC verified"}

@api.get("/admin/payments")
async def admin_payments(user=Depends(require_role("admin"))):
    items = await db.payments.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items

# ---------- Seed default admin + sample data ----------
SAMPLE_PROPS = [
    {
        "title": "Sunrise Boys PG, Six Mile",
        "description": "Modern 3-storey boys PG with study rooms, mess, and 24/7 security. Walking distance from IIT Guwahati shuttle stop.",
        "location": "Six Mile, near IIT Bus Stop",
        "address": "House No. 42, Lane 3, Six Mile, Guwahati",
        "area": "six_mile", "gender": "boys", "rent": 7500, "deposit": 5000,
        "amenities": ["AC", "WiFi", "Food", "Power Backup", "Laundry", "CCTV"],
        "images": [
            "https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=1200&q=80",
            "https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?w=1200&q=80",
            "https://images.unsplash.com/photo-1505691938895-1758d7feb511?w=1200&q=80",
        ],
        "flood_free_zone": True, "water_24_7": True,
        "nearby_landmarks": ["IIT Guwahati - 2km", "Down Town Hospital - 1.5km", "Big Bazaar - 800m"],
        "total_rooms": 24, "available_rooms": 5, "owner_status": "in_guwahati",
    },
    {
        "title": "Lily Girls Hostel, Beltola",
        "description": "Premium girls-only PG with biometric entry, mess by aunty, and quiet study lounge. Verified safe area.",
        "location": "Beltola Tiniali",
        "address": "Beltola Survey, Near Bypass, Guwahati",
        "area": "beltola", "gender": "girls", "rent": 8200, "deposit": 5000,
        "amenities": ["AC", "WiFi", "Food", "Power Backup", "Geyser", "CCTV", "Biometric"],
        "images": [
            "https://images.unsplash.com/photo-1502672260266-1c1ef2d93688?w=1200&q=80",
            "https://images.unsplash.com/photo-1493809842364-78817add7ffb?w=1200&q=80",
            "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=1200&q=80",
        ],
        "flood_free_zone": True, "water_24_7": True,
        "nearby_landmarks": ["Beltola Market - 500m", "GS Road - 2km", "Cotton University - 6km"],
        "total_rooms": 18, "available_rooms": 3, "owner_status": "in_guwahati",
    },
    {
        "title": "Brahmaputra View Unisex PG, Zoo Road",
        "description": "Co-living style unisex PG with separate floors, rooftop garden, and weekly housekeeping.",
        "location": "Zoo Road Tiniali",
        "address": "Sundarpur, Zoo Road, Guwahati",
        "area": "zoo_road", "gender": "unisex", "rent": 9000, "deposit": 5000,
        "amenities": ["AC", "WiFi", "Food", "Power Backup", "Gym", "Lounge"],
        "images": [
            "https://images.unsplash.com/photo-1522444195799-478538b28823?w=1200&q=80",
            "https://images.unsplash.com/photo-1560185007-cde436f6a4d0?w=1200&q=80",
            "https://images.unsplash.com/photo-1554995207-c18c203602cb?w=1200&q=80",
        ],
        "flood_free_zone": False, "water_24_7": True,
        "nearby_landmarks": ["Assam State Zoo - 1km", "GMCH Hospital - 3km", "Pan Bazaar - 5km"],
        "total_rooms": 20, "available_rooms": 7, "owner_status": "in_guwahati",
    },
    {
        "title": "Riverside Boys PG, Jalukbari",
        "description": "Affordable PG near Gauhati University with mess, study room, and shared kitchen access.",
        "location": "Jalukbari, near GU Gate",
        "address": "GU Road, Jalukbari, Guwahati",
        "area": "jalukbari", "gender": "boys", "rent": 5500, "deposit": 5000,
        "amenities": ["WiFi", "Food", "Power Backup", "Laundry"],
        "images": [
            "https://images.unsplash.com/photo-1494526585095-c41746248156?w=1200&q=80",
            "https://images.unsplash.com/photo-1540518614846-7eded433c457?w=1200&q=80",
            "https://images.unsplash.com/photo-1540518614846-7eded433c457?w=1200&q=80",
        ],
        "flood_free_zone": True, "water_24_7": False,
        "nearby_landmarks": ["Gauhati University - 500m", "Jalukbari Market - 700m"],
        "total_rooms": 16, "available_rooms": 9, "owner_status": "nri", "allow_sublease": True,
    },
    {
        "title": "Greenfield Girls PG, Six Mile",
        "description": "Spacious girls-only PG with private balconies, study desks, and home-cooked Assamese meals.",
        "location": "Six Mile, Behind ABC Mall",
        "address": "Survey, Six Mile, Guwahati",
        "area": "six_mile", "gender": "girls", "rent": 8800, "deposit": 5000,
        "amenities": ["AC", "WiFi", "Food", "Power Backup", "Geyser", "Library"],
        "images": [
            "https://images.unsplash.com/photo-1556228453-efd6c1ff04f6?w=1200&q=80",
            "https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=1200&q=80",
            "https://images.unsplash.com/photo-1567767292278-a4f21aa2d36e?w=1200&q=80",
        ],
        "flood_free_zone": True, "water_24_7": True,
        "nearby_landmarks": ["NIPER Guwahati - 3km", "ABC Mall - 200m"],
        "total_rooms": 22, "available_rooms": 4, "owner_status": "in_guwahati",
    },
    {
        "title": "Skyline Working Pro PG, Beltola",
        "description": "Premium PG for working professionals. AC rooms, work-from-home setup, and gym membership included.",
        "location": "Beltola Bazaar",
        "address": "Beltola Market Road, Guwahati",
        "area": "beltola", "gender": "unisex", "rent": 12000, "deposit": 5000,
        "amenities": ["AC", "WiFi", "Food", "Power Backup", "Gym", "Lounge", "Parking"],
        "images": [
            "https://images.unsplash.com/photo-1560185009-5bf9f2849488?w=1200&q=80",
            "https://images.unsplash.com/photo-1551776235-dde6d482980b?w=1200&q=80",
            "https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=1200&q=80",
        ],
        "flood_free_zone": True, "water_24_7": True,
        "nearby_landmarks": ["Beltola Tiniali - 800m", "Big Bazaar - 1km"],
        "total_rooms": 12, "available_rooms": 2, "owner_status": "in_guwahati",
    },
]

@app.on_event("startup")
async def seed_data():
    # Default admin
    if not await db.users.find_one({"email": "admin@pgroom.in"}):
        admin = {
            "id": str(uuid.uuid4()),
            "name": "PGRoom Admin",
            "email": "admin@pgroom.in",
            "phone": "9999999999",
            "password": hash_pw("admin123"),
            "role": "admin",
            "email_verified": True,
            "phone_verified": True,
            "kyc": {}, "kyc_verified": True,
            "wallet_balance": 0,
            "created_at": now_iso(),
        }
        await db.users.insert_one(admin)
        logger.info("Seeded admin user: admin@pgroom.in / admin123")

    # Sample owner
    owner = await db.users.find_one({"email": "owner@pgroom.in"})
    if not owner:
        owner = {
            "id": str(uuid.uuid4()),
            "name": "Rajeev Sharma",
            "email": "owner@pgroom.in",
            "phone": "9876543210",
            "password": hash_pw("owner123"),
            "role": "owner",
            "email_verified": True,
            "phone_verified": True,
            "kyc": {}, "kyc_verified": True,
            "wallet_balance": 0,
            "created_at": now_iso(),
        }
        await db.users.insert_one(owner)
        logger.info("Seeded owner: owner@pgroom.in / owner123")

    # Sample tenant
    if not await db.users.find_one({"email": "tenant@pgroom.in"}):
        tenant = {
            "id": str(uuid.uuid4()),
            "name": "Priya Das",
            "email": "tenant@pgroom.in",
            "phone": "9123456780",
            "password": hash_pw("tenant123"),
            "role": "tenant",
            "email_verified": True,
            "phone_verified": True,
            "kyc": {}, "kyc_verified": False,
            "wallet_balance": 0,
            "created_at": now_iso(),
        }
        await db.users.insert_one(tenant)
        logger.info("Seeded tenant: tenant@pgroom.in / tenant123")

    # Sample properties
    if await db.properties.count_documents({}) == 0:
        for sp in SAMPLE_PROPS:
            doc = {**sp,
                "id": str(uuid.uuid4()),
                "owner_id": owner["id"],
                "owner_name": owner["name"],
                "is_active": True,
                "verified": True,
                "rating": round(random.uniform(4.2, 4.9), 1),
                "review_count": random.randint(8, 45),
                "video_url": None, "image_360": None,
                "lat": 26.1445 + random.uniform(-0.05, 0.05),
                "lng": 91.7362 + random.uniform(-0.05, 0.05),
                "checklist": [
                    {"name": "Bed Mattress", "image": "", "price": 3000},
                    {"name": "Study Table", "image": "", "price": 2500},
                    {"name": "Wardrobe", "image": "", "price": 4500},
                ],
                "electricity_bill_url": "", "gmc_receipt_url": "",
                "allow_sublease": sp.get("allow_sublease", False),
                "created_at": now_iso(),
            }
            await db.properties.insert_one(doc)
        logger.info(f"Seeded {len(SAMPLE_PROPS)} sample properties")

# ---------- Mount ----------
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("pgroom")

@app.on_event("shutdown")
async def shutdown():
    client.close()
