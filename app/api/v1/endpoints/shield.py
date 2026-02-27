from fastapi import APIRouter, BackgroundTasks
from app.models.request import PromptRequest
from app.models.response import PromptResponse
from app.services.security_service import evaluate_prompt
from app.repositories.log_repository import threat_logs
from datetime import datetime

router = APIRouter()


@router.post("/evaluate", response_model=PromptResponse)
async def evaluate_endpoint(request: PromptRequest, background_tasks: BackgroundTasks):
    start_time = datetime.utcnow()
    engine_result = await evaluate_prompt(request.prompt)

    latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

    if engine_result["verdict"] == "MALICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request blocked due to malicious intent."
    elif engine_result["verdict"] == "SUSPICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request flagged. Proceed with caution."
    else:
        safe_prompt = request.prompt

    response_data = {
        "status": "success",
        "verdict": engine_result["verdict"],
        "final_score": engine_result["final_score"],
        "safe_prompt": safe_prompt,
        "latency_ms": latency_ms,
        "rule_triggers": engine_result.get("rule_triggers", []),
        "threat_type": engine_result.get("threat_type", "UNKNOWN"),
        "reasoning": engine_result.get("reasoning", ""),
        "sentinel_action": engine_result.get("sentinel_action", "No action required.")
    }

    db_document = {
        "timestamp": datetime.utcnow(),
        "session_id": request.session_id,
        "raw_prompt": request.prompt,
        **response_data
    }

    if threat_logs is not None:
        background_tasks.add_task(threat_logs.insert_one, db_document)

    return response_data
