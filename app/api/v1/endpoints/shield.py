from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from app.models.request import PromptRequest
from app.models.response import PromptResponse
from app.services import security_service
from app.repositories.log_repository import LogRepository, get_default_repo
from app.core import config
from datetime import datetime
from typing import Callable

router = APIRouter()


async def get_log_repository(request: Request) -> LogRepository:
    # Prefer an app-level repository if placed on app.state by startup event
    repo = getattr(request.app.state, "log_repository", None)
    if repo is None:
        repo = get_default_repo()
    return repo


@router.post("/evaluate", response_model=PromptResponse)
async def evaluate_endpoint(
    request_body: PromptRequest,
    background_tasks: BackgroundTasks,
    repo: LogRepository = Depends(get_log_repository),
):
    start_time = datetime.utcnow()

    try:
        engine_result = await security_service.evaluate_prompt(request_body.prompt)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

    if engine_result.get("verdict") == "MALICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request blocked due to malicious intent."
    elif engine_result.get("verdict") == "SUSPICIOUS":
        safe_prompt = "🛡️ [PromptGuard]: Request flagged. Proceed with caution."
    else:
        safe_prompt = request_body.prompt

    response_data = {
        "status": "success",
        "verdict": engine_result.get("verdict"),
        "final_score": engine_result.get("final_score", 0.0),
        "safe_prompt": safe_prompt,
        "latency_ms": latency_ms,
        "rule_triggers": engine_result.get("rule_triggers", []),
        "threat_type": engine_result.get("threat_type", "UNKNOWN"),
        "reasoning": engine_result.get("reasoning", ""),
        "sentinel_action": engine_result.get("sentinel_action", "No action required.")
    }

    db_document = {
        "timestamp": datetime.utcnow(),
        "session_id": request_body.session_id,
        "raw_prompt": request_body.prompt,
        **response_data,
    }

    # Save log in background
    try:
        background_tasks.add_task(repo.save_log, db_document)
    except Exception:
        # Best-effort non-blocking logging; do not fail the request if DB insert can't be scheduled
        pass

    return response_data
