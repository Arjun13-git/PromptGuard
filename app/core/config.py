from dotenv import load_dotenv
import os

# Load environment variables from root .env
load_dotenv()

# Expose commonly used configuration values
MONGO_URL = os.getenv("MONGO_URL")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not MONGO_URL:
    print("⚠️ WARNING: MONGO_URL is not set in the .env file!")
