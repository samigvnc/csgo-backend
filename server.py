from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Query
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Any, Literal
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict
from bson import ObjectId
# --- Auth imports ---
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
try:
    from bson.decimal128 import Decimal128
except Exception:
    class Decimal128: pass  # yoksa sorun etme
import random
from fastapi.middleware.cors import CORSMiddleware
# def case_out(doc: Dict) -> Dict:
#     """
#     Mongo doc -> API output
#     _id'yi stringe çevirir; eksik alanları toleranslı doldurur.
#     """
#     if not doc:
#         return {}
#     out = {
#         "_id": str(doc.get("_id")) if doc.get("_id") else None,
#         "name": doc.get("name", ""),
#         "price": float(doc.get("price", 0.0)),
#         "image": doc.get("image", ""),
#         "isPremium": bool(doc.get("isPremium", False)),
#         "isNew": bool(doc.get("isNew", False)),
#         "isEvent": bool(doc.get("isEvent", False)),
#         # contents boş olabilir; UI sayıyı göstermek için contentsCount da destekliyor
#         "contents": doc.get("contents", []) or [],
#         "contentsCount": doc.get("contentsCount", None),
#     }
#     # contentsCount yoksa contents uzunluğunu türet
#     if out["contentsCount"] is None:
#         try:
#             out["contentsCount"] = len(out["contents"])
#         except Exception:
#             out["contentsCount"] = 0
#     return out


# -----------------------------------------------------------------------------
# ENV / DB
# -----------------------------------------------------------------------------
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
db_name   = os.environ['DB_NAME']

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]


# -----------------------------------------------------------------------------
# APP & ROUTER
# -----------------------------------------------------------------------------
app = FastAPI(
    title="CSGO Backend",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://csgo-frontend-0.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
api_router = APIRouter(prefix="/api")


@app.get("/api/ping")
async def ping():
    return {"ok": True}



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

# ---- Public: cases list & detail ----
@api_router.get("/public/cases")
async def list_cases(
    search: str = Query("", description="name üzerinde arama"),
    type: Optional[str] = Query(None, pattern="^(premium|regular)$"),
    limit: int = Query(48, ge=1, le=200),
    page: int = Query(1, ge=1),
):
    """
    GET /api/public/cases?search=&type=premium|regular&limit=48&page=1
    Atlas'taki 'cases' koleksiyonundan döner.
    """
    q: Dict = {}

    # Arama: text index yoksa regex ile case-insensitive
    if search:
        q["name"] = {"$regex": search, "$options": "i"}

    if type == "premium":
        q["isPremium"] = True
    elif type == "regular":
        q["isPremium"] = {"$ne": True}

    skip = (page - 1) * limit

    cursor = db.cases.find(q).skip(skip).limit(limit).sort([("_id", -1)])
    docs = await cursor.to_list(length=limit)
    items = [case_out(d) for d in docs]
    total = await db.cases.count_documents(q)

    return {"items": items, "total": total, "page": page}



@api_router.get("/public/cases/{case_id}")
async def get_case(case_id: str):
    # 1) int id ile ara
    doc = None
    if case_id.isdigit():
        doc = await db.cases.find_one({"id": int(case_id)})
    # 2) değilse ObjectId gibi dene (varsa)
    if doc is None:
        try:
            doc = await db.cases.find_one({"_id": ObjectId(case_id)})
        except Exception:
            pass

    if not doc:
        raise HTTPException(404, "case not found")

    return get_case(doc)


def case_out(doc: Dict) -> Dict:
    return {
        "_id": str(doc.get("_id")) if doc.get("_id") else None, 
        "id": doc.get("id"),
        "name": doc.get("name", ""),
        "price": float(doc.get("price", 0.0)),
        "image": doc.get("image", ""),
        "isPremium": bool(doc.get("isPremium", False)),
        "isNew": bool(doc.get("isNew", False)),
        "isEvent": bool(doc.get("isEvent", False)),
        "contents": doc.get("contents", []) or [],
        "contentsCount": doc.get("contentsCount") if doc.get("contentsCount") is not None else len(doc.get("contents", []) or []),
    }

class CaseCreate(BaseModel):
    name: str
    price: float = 0.0
    image: str = ""
    isPremium: bool = False
    isNew: bool = False
    isEvent: bool = False
    contents: list = []
    contentsCount: Optional[int] = None

@api_router.get("/admin/cases", dependencies=[Depends(require_admin)])
async def admin_list_cases():
    docs = await db.cases.find({}, {"name": 1}).sort([("_id", -1)]).to_list(500)
    return [{"_id": str(d["_id"]), "name": d.get("name", "")} for d in docs]

@api_router.post("/admin/cases", dependencies=[Depends(require_admin)])
async def admin_create_case(input: CaseCreate):
    doc = input.model_dump()
    res = await db.cases.insert_one(doc)
    created = await db.cases.find_one({"_id": res.inserted_id})
    return case_out(created)

@api_router.delete("/admin/cases/{case_id}", dependencies=[Depends(require_admin)])
async def admin_delete_case(case_id: str):
    if not ObjectId.is_valid(case_id):
        raise HTTPException(404, "Case not found")
    res = await db.cases.delete_one({"_id": ObjectId(case_id)})
    if res.deleted_count == 0:
        raise HTTPException(404, "Case not found")
    return {"ok": True}

class BattleCreate(BaseModel):
    creator_email: str
    mode: Literal["1v1", "1v1v1", "1v1v1v1"]
    case_ids: List[str] = Field(default_factory=list)  # Mongo _id string'leri
    entry_price: float = 0.0
    is_private: bool = False

class BattleOut(BaseModel):
    id: str
    mode: str
    cases: List[Dict[str, Any]]
    entry_price: float
    players: List[str]
    maxPlayers: int
    status: Literal["waiting", "running", "finished"]
    totals: Dict[str, float] = {}
    winner: Optional[str] = None
    is_private: bool = False

def _max_players(mode: str) -> int:
    return {"1v1": 2, "1v1v1": 3, "1v1v1v1": 4}[mode]

def _battle_out(doc) -> dict:
    return {
        "id": str(doc["_id"]),
        "mode": doc["mode"],
        "cases": doc.get("cases", []),
        "entry_price": float(doc.get("entry_price", 0.0)),
        "players": doc.get("players", []),
        "maxPlayers": _max_players(doc["mode"]),
        "status": doc.get("status", "waiting"),
        "totals": {k: float(v) for k, v in (doc.get("totals", {}) or {}).items()},
        "winner": doc.get("winner"),
        "is_private": bool(doc.get("is_private", False)),
    }

async def _load_cases(ids: List[str]) -> List[dict]:
    valid = [ObjectId(i) for i in ids if ObjectId.is_valid(i)]
    if not valid:
        return []
    cur = db.cases.find({"_id": {"$in": valid}}, {"name": 1, "price": 1, "image": 1})
    docs = await cur.to_list(200)
    return [{"_id": str(d["_id"]), "name": d.get("name"), "price": float(d.get("price", 0)), "image": d.get("image", "")} for d in docs]

@api_router.get("/public/battles", response_model=List[BattleOut])
async def list_battles(status: Optional[str] = None):
    q = {}
    if status in {"waiting", "running", "finished"}:
        q["status"] = status
    cur = db.battles.find(q).sort([("_id", -1)])
    docs = await cur.to_list(500)
    return [_battle_out(d) for d in docs]

@api_router.post("/public/battles", response_model=BattleOut)
async def create_battle(input: BattleCreate):
    maxP = _max_players(input.mode)
    # Kasaları DB’den getir
    cases = await _load_cases(input.case_ids)
    doc = {
        "mode": input.mode,
        "cases": cases,                         # her case: {_id, name, price, image}
        "entry_price": float(input.entry_price) if input.entry_price else float(sum(c["price"] for c in cases)),
        "players": [input.creator_email],
        "status": "waiting",                    # waiting -> running -> finished
        "totals": {},
        "winner": None,
        "is_private": bool(input.is_private),
    }
    res = await db.battles.insert_one(doc)
    created = await db.battles.find_one({"_id": res.inserted_id})
    return _battle_out(created)

class BattleJoin(BaseModel):
    email: str

@api_router.post("/public/battles/{bid}/join", response_model=BattleOut)
async def join_battle(bid: str, body: BattleJoin):
    if not ObjectId.is_valid(bid):
        raise HTTPException(404, "Battle not found")
    battle = await db.battles.find_one({"_id": ObjectId(bid)})
    if not battle:
        raise HTTPException(404, "Battle not found")

    if battle.get("status") != "waiting":
        raise HTTPException(400, "Battle not joinable")

    players = battle.get("players", [])
    if body.email in players:
      # zaten içerdeyse no-op
      return _battle_out(battle)

    maxP = _max_players(battle["mode"])
    if len(players) >= maxP:
        raise HTTPException(400, "Room is full")

    players.append(body.email)
    await db.battles.update_one({"_id": battle["_id"]}, {"$set": {"players": players}})
    battle["players"] = players
    return _battle_out(battle)

class BattleStart(BaseModel):
    # opsiyonel: başlatan creator mı kontrol edebilirsin; basit MVP’de atlıyoruz
    pass

@api_router.post("/public/battles/{bid}/start", response_model=BattleOut)
async def start_battle(bid: str, _: BattleStart):
    if not ObjectId.is_valid(bid):
        raise HTTPException(404, "Battle not found")
    battle = await db.battles.find_one({"_id": ObjectId(bid)})
    if not battle:
        raise HTTPException(404, "Battle not found")

    if battle.get("status") != "waiting":
        # zaten finished ise içindeki rounds'u döndürmek için dokümanı yükle
        out = _battle_out(battle)
        out["rounds"] = battle.get("rounds", [])
        return out

    players = battle.get("players", [])
    maxP = _max_players(battle["mode"])
    if len(players) < 2:
        raise HTTPException(400, "Need at least 2 players")
    if len(players) > maxP:
        players = players[:maxP]

    cases = battle.get("cases") or []
    totals = {p: 0.0 for p in players}
    rng = random.Random()

    rounds = []  # <- EKLEDİK: [{case: {...}, rolls: [{player, value, label}]}...]
    for c in cases:
        base = float(c.get("price", 0.0))
        mu = max(0.1, base * 0.9)
        sigma = max(0.5, base * 0.6)
        round_rolls = []
        for p in players:
            val = max(0.05, rng.gauss(mu, sigma))
            totals[p] += val
            round_rolls.append({
                "player": p,
                "value": float(val),
                # görsel isim/etiket (gerçek drop yoksa basit)
                "label": f"{c.get('name','Case')} Drop",
                # isteğe bağlı renk/rarity mock
                "rarityColor": "#4B69FF",
                "rarityName": "Mil-Spec"
            })
        rounds.append({
            "case": {"_id": str(c.get("_id", "")), "name": c.get("name"), "price": float(base), "image": c.get("image","")},
            "rolls": round_rolls
        })

    winner = max(totals.items(), key=lambda kv: kv[1])[0] if totals else None

    await db.battles.update_one(
        {"_id": battle["_id"]},
        {"$set": {"status": "finished", "totals": totals, "winner": winner, "rounds": rounds}}
    )
    battle = await db.battles.find_one({"_id": battle["_id"]})

    out = _battle_out(battle)
    out["rounds"] = rounds  # response_model esnek; extra alanı döndürüyoruz
    return out

@api_router.get("/public/battles/{bid}", response_model=BattleOut)
async def get_battle(bid: str):
    if not ObjectId.is_valid(bid):
        raise HTTPException(404, "Battle not found")
    battle = await db.battles.find_one({"_id": ObjectId(bid)})
    if not battle:
        raise HTTPException(404, "Battle not found")
    return _battle_out(battle)

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

def to_float_safe(x):
    try:
        if isinstance(x, Decimal128):
            return float(x.to_decimal())
        return float(x)
    except Exception:
        return 0.0

@api_router.get("/public/user-by-email", response_model=UserBalanceOut)
async def get_user_by_email(email: str = Query(..., min_length=3)):
    try:
        user = await db.users.find_one(
            {"email": email},
            {"_id": 0, "password_hash": 0}
        )
        if not user:
            raise HTTPException(404, "User not found")

        # Eski kayıtlar/şemalar için toleranslı ol:
        user_id = user.get("id") or user.get("uid") or ""
        balance_val = to_float_safe(user.get("balance", 0.0))
        
        # --- ÇÖZÜM BURADA ---
        # user["email"] yerine user.get("email") kullanıyoruz.
        user_email = user.get("email")
        if not user_email:
            # Eğer email yoksa, bu beklenmedik bir durum, loglayıp hata dönelim.
            logging.error(f"User document with id {user_id} is missing an email field.")
            raise HTTPException(500, "User data is inconsistent")

        return {"id": user_id, "email": user_email, "balance": balance_val}
    
    except HTTPException:
        raise
    except Exception as e:
        logging.exception(f"user-by-email crashed for {email}: {e}")
        raise HTTPException(500, "internal error")

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

app.include_router(api_router)
