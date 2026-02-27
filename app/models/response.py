from pydantic import BaseModel
from typing import List


class PromptResponse(BaseModel):
    status: str
    verdict: str
    final_score: float
    safe_prompt: str
    latency_ms: int
    rule_triggers: List[str]
    threat_type: str
    reasoning: str
    sentinel_action: str
