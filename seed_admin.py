import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from pathlib import Path
import asyncio, uuid
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

pwd = os.environ.get("ADMIN_PASSWORD", "135790Aa_")
email = os.environ.get("ADMIN_EMAIL", "menesdemircan@gmail.com")

pwdctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def main():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    exists = await db.users.find_one({"email": email})
    if exists:
        print("Admin already exists:", email)
        return
    doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "password_hash": pwdctx.hash(pwd),
        "balance": 0.0,
        "role": "admin"
    }
    await db.users.insert_one(doc)
    print("Admin created:", email)

if __name__ == "__main__":
    asyncio.run(main())
