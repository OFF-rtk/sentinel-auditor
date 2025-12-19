import os
import json
import time
from dotenv import load_dotenv
from supabase import create_client, Client
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_community.vectorstores import SupabaseVectorStore
from tqdm import tqdm

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not all([SUPABASE_URL, SUPABASE_KEY]):
    print("Error: Missing keys in .env file")
    exit(1)

print(f"Connecting to Supabase: {SUPABASE_URL}...")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

print("Loading Local Embedding Model")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

def ingest_audit_logs():
    try:
        with open("audit_logs.json", "r") as f:
            logs = json.load(f)

        print(f"Found {len(logs)} logs.")

        batch_size = 50
        total_batches = len(logs) // batch_size + 1

        for i in tqdm(range(0, len(logs), batch_size), desc="Uploading Logs"):
            batch = logs[i:i + batch_size]

            data_to_insert = [
                {
                    "event_id": log["event_id"],
                    "payload": log,
                }
                for log in batch
            ]

            response = supabase.table("audit_logs").upsert(data_to_insert).execute()

        print("Audit logs ingested")

    except FileNotFoundError:
        print("Error: audit_logs not found")
    except Exception as e:
        print(f"Error uploading logs: {e}")

def ingest_policies():
    print("Vectorizing Policy Docs")

    policies = [
        Document(
            page_content="Policy EXEC-01: Executive Travel. Executives (Role: 'executive', 'premium_user') are permitted to access banking portals from international locations including China (CN) and Russia (RU), provided they use the corporate VPN. 'Impossible Travel' flags for these users should be treated as warnings, not blocks, if IP reputation matches 'corporate' or 'high_risk_vpn'.",
            metadata={"policy_id": "EXEC-01", "category": "access_control"}
        ),
        Document(
            page_content="Policy TRANSFER-02: High Value Transfers. Any transfer exceeding $10,000 USD requires Step-Up Authentication (MFA). If MFA is 'verified', the transaction is approved regardless of location. If MFA is missing or 'bypassed', BLOCK immediately.",
            metadata={"policy_id": "TRANSFER-02", "category": "transaction"}
        ),
        Document(
            page_content="Policy AML-03: Sanctioned Countries. ALL access from North Korea (KP), Iran (IR), and Syria (SY) must be BLOCKED immediately. No exceptions for any role. Report to Compliance Team.",
            metadata={"policy_id": "AML-03", "category": "compliance"}
        ),
        Document(
            page_content="Policy SESSION-05: Session Hijacking. If 'session_age_seconds' is greater than 8 hours (28800) AND the location changes country, this is a confirmed Session Hijack. Terminate session immediately.",
            metadata={"policy_id": "SESSION-05", "category": "security"}
        ),
        Document(
            page_content="Policy BIO-04: Biometric Anomalies. If Sentinel Core reports biometric failures like 'flight_time_profile_mismatch', 'mouse_path_quantization', or 'bot_like_accuracy_spike', this indicates a non-human actor (Bot) or unauthorized user. BLOCK immediately unless 'mfa_status' is 'verified_biometric'.",
            metadata={"policy_id": "BIO-04", "category": "biometrics"}
        )
    ]

    try:
        vector_store = SupabaseVectorStore.from_documents(
            policies,
            embeddings,
            client=supabase,
            table_name="documents"
        )
        print("Policies Stored")

    except Exception as e:
        print(f"Error vectorizing policies: {e}")

if __name__ == "__main__":
    ingest_audit_logs()

    ingest_policies()

    print("Env setup done!!")
