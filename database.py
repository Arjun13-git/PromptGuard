from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

# 1. Load the variables FIRST
load_dotenv()

# 2. Fetch the URL securely
MONGO_URL = os.getenv("MONGO_URL")

if not MONGO_URL:
    print("⚠️ WARNING: MONGO_URL is not set in the .env file!")

# 3. Initialize the client
client = AsyncIOMotorClient(MONGO_URL)
db = client.promptguard_db

# Main collection for logs
threat_logs = db.threat_logs