import os
import json
import hmac
import hashlib
import uvicorn
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, Header
from dotenv import load_dotenv
from typing import Optional

from agents import (
    brain_triage, brain_intel, brain_judge,
    check_rate_limit, is_user_blacklisted,
    confirm_block, unblock_user, send_pardon_email,
)
from agents.utils import log_trace

load_dotenv()

app = FastAPI()

# Supabase Webhook Secret for verifying requests
SUPABASE_WEBHOOK_SECRET = os.getenv("SUPABASE_WEBHOOK_SECRET")


def verify_webhook_request(payload: bytes, secret_header: str, signature_header: str, secret: str) -> bool:
    """
    Verify the webhook request came from Supabase.
    Supports two methods:
    1. Simple secret comparison (Supabase Database Webhooks)
    2. HMAC-SHA256 signature verification
    """
    if not secret:
        # Secret not configured - reject all requests
        return False

    # Method 1: Simple secret comparison (Supabase Database Webhooks)
    if secret_header and hmac.compare_digest(secret_header, secret):
        return True

    # Method 2: HMAC-SHA256 signature verification
    if signature_header:
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()

        # Handle 'sha256=<hex>' format
        sig = signature_header[7:] if signature_header.startswith('sha256=') else signature_header

        if hmac.compare_digest(expected_signature, sig):
            return True

    return False



async def process_audit_log(log_entry: dict):
    """
    The Orchestrator function. It runs the 3-Brain Loop in the background.
    """

    event_id = log_entry.get("event_id", "unknown_event")
    user_id = log_entry.get("actor", {}).get("user_id", "unknown")
    print(f"\n [Webhook Recieved] Analyzing {event_id} / {user_id}...")

    if not check_rate_limit(user_id, limit=5, window=60):
        log_trace(event_id, "ENFORCER", "BLOCKED", {"reason": "Rate Limit Exceeded"})
        print(f" RATE LIMITER: Traffic throttled for {user_id}.")
        return

    if is_user_blacklisted(user_id):
        log_trace(event_id, "ENFORCER", "BLOCKED", {"reason": "User Blacklisted"})
        print(f" SHIELD: User {user_id} is blacklisted. Request dropped.")
        return

    log_trace(event_id, "TRIAGE", "THINKING", {"msg": "Analyzing intent..."})

    try:
        plan = brain_triage(log_entry)

        if plan["status"] == "SAFE":
            log_trace(event_id, "TRIAGE", "COMPLETED", {"risk": "LOW", "reason": plan.get("reason")})
            print(f" {user_id} is SAFE. (Architect cleared it)")
            return

 
        log_trace(event_id, "TRIAGE", "COMPLETED", {
            "risk": "HIGH",
            "search_vectors": plan.get("search_terms")
        })

    except Exception as e:
        log_trace(event_id, "TRIAGE", "FAILED", {"error": str(e)})
        print(f" TRAIGE: Failed to analyze intent. Error: {e}")
        return

    log_trace(event_id, "INTEL", "THINKING", {"msg": "Searching Vector DB..."})

    try:
        policies = brain_intel(plan["search_terms"])

        log_trace(event_id, "INTEL", "COMPLETED", {
            "found_docs": len(policies),
            "top_policy": policies[0][:50] + "..."
        })

    except Exception as e:
        log_trace(event_id, "INTEL", "FAILED", {"error": str(e)})
        print(f" INTEL: Failed to search vector DB. Error: {e}")
        return

    log_trace(event_id, "JUDGE", "THINKING", {"msg": "Deliberating..."})

    try:
        decision = brain_judge(log_entry, policies)
    
        model_tag = decision.get("model_used", "Junior Analyst")

        role_label = "CISO" if model_tag == "CISO" else "JUDGE"

        log_trace(event_id, role_label, "COMPLETED", {
            "verdict": decision["decision"],
            "confidence": decision.get("confidence", 100),
            "reason": decision.get("reasoning")
        })

        print(f" FINAL DECISION: {decision['decision']}")
        print(f" REASON: {decision.get('reasoning', 'No Reasoning Provided')}")

    except Exception as e:
        log_trace(event_id, "JUDGE", "FAILED", {"error": str(e)})
        print(f" JUDGE: Failed to deliberate. Error: {e}")
        return

    if decision["decision"] == "BLOCK":
        log_trace(event_id, "ENFORCER", "THINKING", {"msg": "Confirming block — escalating strikes..."})

        success = confirm_block(user_id, decision.get('reasoning', 'Blocked by Sentinel'))

        if success:
            log_trace(event_id, "ENFORCER", "BLOCK_CONFIRMED", {
                "action": "STRIKE_ESCALATED",
                "redis_key": f"blacklist:{user_id}",
                "reasoning": decision.get("reasoning"),
            })
        else:
            log_trace(event_id, "ENFORCER", "FAILED", {"error": "Shared Redis unavailable"})
    else:
        # Check if the original sentinel-ml decision was BLOCK
        # If so, the judge is overriding a BLOCK → false positive pardon
        sentinel_decision = log_entry.get("sentinel_analysis", {}).get("decision")

        if sentinel_decision == "BLOCK":
            log_trace(event_id, "ENFORCER", "FALSE_POSITIVE_PARDONED", {
                "msg": f"Judge overrode sentinel BLOCK → ALLOW for {user_id}",
                "reasoning": decision.get("reasoning"),
            })
            unblock_user(user_id)

            # Attempt pardon email (best-effort, needs user email)
            user_email = log_entry.get("actor", {}).get("email")
            if user_email:
                send_pardon_email(user_email, decision.get("reasoning", "False positive"))

            print(f" PARDONED: User {user_id} unblocked (false positive).")
        else:
            log_trace(event_id, "ENFORCER", "IDLE", {"msg": "User Allowed. No action taken."})
            print(f" ALLOWING User {user_id}. No enforcement needed.")


@app.get("/")
def health_check():
    return {"status": "active", "service": "Sentinel Auditor"}

@app.post("/webhook/audit")
async def recieve_audit_log(
    request: Request, 
    background_tasks: BackgroundTasks,
    x_supabase_signature: Optional[str] = Header(None, alias="x-supabase-signature"),
    x_webhook_secret: Optional[str] = Header(None, alias="x-webhook-secret")
):
    """
    Supabase calls this whenever a new row is inserted into 'audit_logs'.
    Verifies the request came from Supabase using either:
    - x-webhook-secret header (simple secret match)
    - x-supabase-signature header (HMAC-SHA256)
    """

    # Get raw body for signature verification
    body_bytes = await request.body()

    # Verify the request is from Supabase (REQUIRED)
    if not SUPABASE_WEBHOOK_SECRET:
        print(" SECURITY: Webhook request rejected - SUPABASE_WEBHOOK_SECRET not configured")
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    # Check if at least one auth header is present
    if not x_supabase_signature and not x_webhook_secret:
        print(" SECURITY: Webhook request rejected - missing authentication header")
        raise HTTPException(status_code=401, detail="Missing webhook authentication")
    
    if not verify_webhook_request(
        payload=body_bytes, 
        secret_header=x_webhook_secret or "", 
        signature_header=x_supabase_signature or "", 
        secret=SUPABASE_WEBHOOK_SECRET
    ):
        print(f" SECURITY: Webhook request rejected - invalid credentials")
        print(f"   x-webhook-secret: {'present' if x_webhook_secret else 'missing'}")
        print(f"   x-supabase-signature: {'present' if x_supabase_signature else 'missing'}")
        raise HTTPException(status_code=401, detail="Invalid webhook credentials")
    
    print(" SECURITY: Webhook verified ✓")


    try:
        body = json.loads(body_bytes)

        record = body.get('record', {})
        log_content = record.get('payload')

        if not log_content:
            if 'actor' in body:
                log_content = body
            else:
                return {"status": "ignored", "reason": "No log payload found"}

        background_tasks.add_task(process_audit_log, log_content)

        return {"status": "processing", "message": "Sentinel is reviewing the log."}

    except Exception as e:
        print(f" Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
