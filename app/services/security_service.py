import time
import asyncio
import json
from typing import Any

from app.services import rule_engine
from app.core import config

try:
    from groq import AsyncGroq
except Exception:
    AsyncGroq = None  # optional dependency in local dev


# Initialize async client if API key is present
client = None
if config.GROQ_API_KEY and AsyncGroq is not None:
    try:
        client = AsyncGroq(api_key=config.GROQ_API_KEY)
    except Exception:
        client = None


async def get_llm_classification(prompt: str, timeout: float = 4.0) -> Any:
    """Call the cloud LLM for a classification. Returns parsed JSON or None on failure."""
    metaprompt = f"""
You are a strict cybersecurity AI firewall. Analyze the user prompt below and return ONLY valid JSON.

Return exactly: {{"classification": "SAFE"|"SUSPICIOUS"|"MALICIOUS", "confidence": float, "attack_type": str}}

User Prompt: "{prompt}"
"""
    if client is None:
        return None
    try:
        resp = await asyncio.wait_for(
            client.chat.completions.create(
                messages=[{"role": "system", "content": metaprompt}],
                model="llama-3.1-8b-instant",
                temperature=0.0,
                response_format={"type": "json_object"},
            ),
            timeout=timeout,
        )
        # groq client returns a nested object; try to extract JSON safely
        text = None
        try:
            text = resp.choices[0].message.content
        except Exception:
            text = getattr(resp, "content", None)
        if not text:
            return None
        if isinstance(text, (dict, list)):
            return text
        try:
            return json.loads(text)
        except Exception:
            # fallback: try to find JSON substring
            import re

            m = re.search(r"\{.*\}", str(text), re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
            return None
    except Exception:
        return None


async def evaluate_prompt(prompt: str) -> dict:
    start_time = time.time()

    # Fast edge check (semantic similarity)
    max_similarity, edge_attack_type = rule_engine.check_vector_similarity(prompt)
    sentinel_note = "No action."

    if max_similarity > 0.70:
        latency_ms = int((time.time() - start_time) * 1000)
        return {
            "verdict": "MALICIOUS",
            "final_score": 0.99,
            "rule_triggers": ["EDGE_VECTOR_MATCH"],
            "threat_type": edge_attack_type,
            "reasoning": f"Edge model similarity {max_similarity:.3f}",
            "sentinel_action": "Edge cache matched known attack.",
            "latency_ms": latency_ms,
            "raw_prompt": prompt,
        }

    # Deterministic rules
    triggered_tags, raw_rule_sum, tanh_rule_score = rule_engine.evaluate_rules(prompt)

    # Call LLM with fail-safe
    llm_json = await get_llm_classification(prompt)
    llm_failed = llm_json is None
    if llm_failed:
        # Fail-safe: rely solely on deterministic scoring
        final_score = round(0.4 * tanh_rule_score, 3)
        llm_confidence = 0.0
        llm_class = "UNKNOWN"
        llm_attack = "NONE"
    else:
        llm_class = llm_json.get("classification", "SAFE")
        try:
            llm_confidence = float(llm_json.get("confidence", 0.0))
        except Exception:
            llm_confidence = 0.0
        llm_attack = llm_json.get("attack_type", "NONE")
        penalty = 0.0 if llm_class == "SAFE" else (0.5 if llm_class == "SUSPICIOUS" else 1.0)
        final_score = round(0.4 * tanh_rule_score + 0.6 * (llm_confidence * penalty), 3)

    # Decision thresholds
    if final_score >= 0.70:
        verdict = "MALICIOUS"
        threat_type = llm_attack if llm_attack and llm_attack != "NONE" else (triggered_tags[0] if triggered_tags else "UNKNOWN")
        sentinel_note = rule_engine.sentinel_deploy_patch(prompt, threat_type)
    elif final_score >= 0.30:
        verdict = "SUSPICIOUS"
        threat_type = llm_attack if llm_attack and llm_attack != "NONE" else (triggered_tags[0] if triggered_tags else "AMBIGUOUS")
    else:
        verdict = "SAFE"
        threat_type = "NONE"

    latency_ms = int((time.time() - start_time) * 1000)

    # Sanitization for SUSPICIOUS results
    safe_prompt = prompt
    if verdict == "SUSPICIOUS":
        safe_prompt = rule_engine.sanitize_prompt(prompt)

    reasoning_parts = [f"rule_sum={raw_rule_sum:.2f}", f"tanh={tanh_rule_score:.3f}"]
    if not llm_failed:
        reasoning_parts.append(f"llm={llm_class}:{llm_confidence:.2f}")
    else:
        reasoning_parts.append("llm=FAILED")

    return {
        "verdict": verdict,
        "final_score": final_score,
        "rule_triggers": triggered_tags,
        "threat_type": threat_type,
        "reasoning": " | ".join(reasoning_parts),
        "sentinel_action": sentinel_note,
        "latency_ms": latency_ms,
        "raw_prompt": safe_prompt,
    }
