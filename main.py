from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import uvicorn
import time
from datetime import datetime
from dotenv import load_dotenv

# Import our custom modules
from engine import evaluate_prompt
from database import threat_logs

# Load environment variables
load_dotenv()

app = FastAPI(
    title="PromptGuard API",
    description="AI Firewall for Generative AI Systems",
    version="1.0.0"
)

# --- Pydantic Models ---
class PromptRequest(BaseModel):
    session_id: str
    prompt: str

class PromptResponse(BaseModel):
    status: str
    verdict: str
    final_score: float
    safe_prompt: str
    latency_ms: int
    rule_triggers: list[str]
    threat_type: str
    reasoning: str
    sentinel_action: str

# --- Database Logging Function ---
async def log_to_mongo(log_data: dict):
    """Background task to log evaluations to MongoDB without blocking the API."""
    try:
        await threat_logs.insert_one(log_data)
        print(f"✅ Logged to DB: {log_data['verdict']} ({log_data['final_score']})")
    except Exception as e:
        print(f"⚠️ DB Logging Error: {e}")

# --- API Endpoints ---
@app.get("/")
async def health_check():
    return {"status": "PromptGuard API Running"}

@app.post("/evaluate", response_model=PromptResponse)
async def evaluate_endpoint(request: PromptRequest, background_tasks: BackgroundTasks):
    start_time = time.time()
    
    # 1. Run the prompt through our AI Engine
    engine_result = await evaluate_prompt(request.prompt)
    
    # Calculate real latency
    latency_ms = int((time.time() - start_time) * 1000)

    # 2. Determine Safe Prompt (Sanitization logic placeholder)
    if engine_result["verdict"] == "MALICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request blocked due to malicious intent."
    elif engine_result["verdict"] == "SUSPICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request flagged. Proceed with caution."
    else:
        safe_prompt = request.prompt

    # 3. Construct the response payload
    # 3. Construct the response payload
    response_data = {
        "status": "success",
        "verdict": engine_result["verdict"],
        "final_score": engine_result["final_score"],
        "safe_prompt": safe_prompt,
        "latency_ms": latency_ms,
        "rule_triggers": engine_result["rule_triggers"],
        "threat_type": engine_result["threat_type"],
        "reasoning": engine_result["reasoning"],
        "sentinel_action": engine_result.get("sentinel_action", "No action required.")
    }
    
    # 4. Construct the Database Log Document
    db_document = {
        "timestamp": datetime.utcnow(),
        "session_id": request.session_id,
        "raw_prompt": request.prompt,
        **response_data # Unpack the response data into the DB document
    }
    
    # 5. Fire off the DB log in the background so the user doesn't wait for it
    background_tasks.add_task(log_to_mongo, db_document)
    
    return response_data

if __name__ == "__main__":
    print("🛡️ Starting PromptGuard API on http://localhost:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)