from motor.motor_asyncio import AsyncIOMotorClient
from app.core import config

# Initialize MongoDB client using central config
client = AsyncIOMotorClient(config.MONGO_URL) if config.MONGO_URL else None
db = client.promptguard_db if client else None

threat_logs = db.threat_logs if db else None
