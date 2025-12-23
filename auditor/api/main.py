import os
import json
import uvicorn
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from dotenv import load_dotenv

from agents import brain_triage, brain_intel, brain_judge

load_dotenv()

app = FastAPI()

async def process_audit_log(log_entry: dict):
    """
    The Orchestrator function. It runs the 3-Brain Loop in the background.
    """

    user_id = log_entry.get("actor", {}).get("user_id", "unknown")
    print(f"\n [Webhook Recieved] Analyzing User: {user_id}...")

    plan = brain_triage(log_entry)
    if plan["status"] == "SAFE":
        print(f" {user_id} is SAFE. (Architect cleared it)")
        return

    policies = brain_intel(plan["search_terms"])

    decision = brain_judge(log_entry, policies)

    if decision["decision"] == "BLOCK":
        print(f" BLOCKING User {user_id}!")
        print(f" Reason: {decision['reasoning']}")

        print(f" [SUPABASE API] Session Terminated for {user_id}")

    else:
        print(f" ALLOWING User {user_id}. False Positive dismissed.")


@app.get("/")
def health_check():
    return {"status": "active", "service": "Sentinel Auditor"}

@app.post("/webhook/audit")
async def recieve_audit_log(request: Request, background_tasks: BackgroundTasks):
    """
    Supabase calls this whenever a new row is inserted into 'audit_logs'.
    """

    try:
        body = await request.json()

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
