from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta

# --- Auth imports ---
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

# -----------------------------------------------------------------------------
# ENV / DB
# -----------------------------------------------------------------------------
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# -----------------------------------------------------------------------------
# APP & ROUTER
# -----------------------------------------------------------------------------
app = FastAPI()
api_router = APIRouter(prefix="/api")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    # Lokal geliştirmenin yanında prod Vercel alan adını da kapsayalım:
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://csgo-frontend-0.vercel.app",
    ],
    # Alternatif: tüm vercel.app subdomainlerini açmak istersen:
    # allow_origin_regex=r"https://.*\.vercel\.app$",
    allow_credentials=True,           # cookie/bearer vs. kullanıyorsan true kalabilir
    allow_methods=["*"],              # OPTIONS dahil
    allow_headers=["*"],              # Authorization, Content-Type vs.
)

# -----------------------------------------------------------------------------
# STARTUP: indexes (email unique)
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def ensure_indexes():
    # email alanını unique yap: aynı email ile ikinci kullanıcıyı engeller
    try:
        await db.users.create_index("email", unique=True)
    except Exception as e:
        logging.warning(f"ensure_indexes warning: {e}")

# -----------------------------------------------------------------------------
# MODELS (Status)
# -----------------------------------------------------------------------------
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

# -----------------------------------------------------------------------------
# AUTH / USERS (admin)
# -----------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginInput(BaseModel):
    email: str
    password: str

class UserPublic(BaseModel):
    id: str
    email: str
    balance: float
    role: str

class UserCreate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password: str
    balance: float = 0.0
    role: str = "user"  # "admin" | "user"

class BalanceUpdate(BaseModel):
    balance: float

async def get_current_user(token: str = Depends(oauth2_scheme)):
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise cred_exc
    except JWTError:
        raise cred_exc

    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise cred_exc
    return user

async def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# -----------------------------------------------------------------------------
# ROUTES
# -----------------------------------------------------------------------------
@api_router.get("/")
async def root():
    return {"message": "Hello World"}

# ---- Status endpoints (mevcut) ----
@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_obj = StatusCheck(**input.model_dump())
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    for check in status_checks:
        if isinstance(check.get('timestamp'), str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    return status_checks

# ---- Auth (admin login) ----
@api_router.post("/auth/login", response_model=Token)
async def login(input: LoginInput):
    user = await db.users.find_one({"email": input.email}, {"_id": 0})
    if not user or not verify_password(input.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["id"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

# ---- Admin: list users ----
@api_router.get("/admin/users", response_model=List[UserPublic], dependencies=[Depends(require_admin)])
async def list_users():
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return users

# ---- Admin: update balance (absolute set) ----
@api_router.patch("/admin/users/{user_id}/balance", response_model=UserPublic, dependencies=[Depends(require_admin)])
async def update_user_balance(user_id: str, input: BalanceUpdate):
    doc = await db.users.find_one_and_update(
        {"id": user_id},
        {"$set": {"balance": float(input.balance)}},
        return_document=True,
        projection={"_id": 0, "password_hash": 0}
    )
    if not doc:
        raise HTTPException(404, "User not found")
    return doc

# ---- Admin: delete user ----
@api_router.delete("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def delete_user(user_id: str):
    res = await db.users.delete_one({"id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}

# ---- (Optional) Admin: create user ----
@api_router.post("/admin/users", response_model=UserPublic, dependencies=[Depends(require_admin)])
async def create_user(input: UserCreate):
    exists = await db.users.find_one({"email": input.email})
    if exists:
        raise HTTPException(400, "Email already exists")
    doc = {
        "id": input.id,
        "email": input.email,
        "password_hash": hash_password(input.password),
        "balance": float(input.balance),
        "role": input.role
    }
    await db.users.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "password_hash"}

# -----------------------------------------------------------------------------
# PUBLIC (geçici geliştirme uçları)  ⚠️ Canlıda JWT ile /users/me yapacağız
# -----------------------------------------------------------------------------

# --- Public Register (dev hızlı akış) ---
class UserRegisterInput(BaseModel):
    username: str
    email: str
    password: str
    initial_balance: float = 1000.0  # ilk bakiye (istersen 0 yap)

@api_router.post("/public/register", response_model=UserPublic)
async def public_register(input: UserRegisterInput):
    # email unique index'i startup'ta var; yine de manuel kontrol edelim
    exists = await db.users.find_one({"email": input.email})
    if exists:
        raise HTTPException(status_code=400, detail="Email already exists")

    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": input.email,
        "password_hash": hash_password(input.password),
        "balance": float(input.initial_balance),
        "role": "user",
        # not: username istersen ayrı field olarak da saklayabilirsin
        "username": input.username
    }
    await db.users.insert_one(doc)
    # password_hash'ı döndürmeyelim
    return {k: v for k, v in doc.items() if k != "password_hash"}


class UserBalanceOut(BaseModel):
    id: str
    email: str
    balance: float

@api_router.get("/public/user-by-email", response_model=UserBalanceOut)
async def get_user_by_email(email: str):
    user = await db.users.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(404, "User not found")
    # user: id, email, balance, role (role'u döndürmüyoruz)
    return {"id": user["id"], "email": user["email"], "balance": float(user.get("balance", 0.0))}

class BalanceDelta(BaseModel):
    delta: float  # + / -

@api_router.post("/public/balance/add", response_model=UserPublic)
async def add_balance(email: str, body: BalanceDelta):
    doc = await db.users.find_one_and_update(
        {"email": email},
        {"$inc": {"balance": float(body.delta)}},
        return_document=True,
        projection={"_id": 0, "password_hash": 0}
    )
    if not doc:
        raise HTTPException(404, "User not found")
    return doc

# -----------------------------------------------------------------------------
# INCLUDE ROUTER & MIDDLEWARE
# -----------------------------------------------------------------------------
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# LOGGING & SHUTDOWN
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
