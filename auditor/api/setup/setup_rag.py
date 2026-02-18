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
        ),
        # ===== Vault-Treasury Specific Policies =====
        Document(
            page_content="Policy TREASURY-06: Payment Approval Limits. Any payment approval where the transaction amount exceeds $50,000 USD requires the 'treasury_admin' role. If a 'treasurer' (standard user) approves a payment exceeding $50,000, BLOCK immediately. Admin approvals of high-value payments should be ALLOWED if MFA is verified.",
            metadata={"policy_id": "TREASURY-06", "category": "transaction"}
        ),
        Document(
            page_content="Policy TREASURY-07: Rapid-Fire Payment Actions. If the same user performs more than 5 payment approval or rejection actions within a 10-minute window, flag as suspicious. CHALLENGE the user if individual payment amounts are under $10,000. BLOCK if any payment amount exceeds $10,000. This pattern indicates potential automated fraud or compromised account.",
            metadata={"policy_id": "TREASURY-07", "category": "transaction"}
        ),
        Document(
            page_content="Policy TREASURY-08: Account Limit Modifications. Only users with the 'treasury_admin' role may directly update account spending limits via the updateLimits endpoint. Standard 'treasurer' users may only submit limit change requests via requestLimitChange, which require admin approval (maker-checker flow). If a non-admin attempts to call updateLimits or approveLimitRequest directly, BLOCK immediately.",
            metadata={"policy_id": "TREASURY-08", "category": "access_control"}
        ),
        Document(
            page_content="Policy TREASURY-09: Balance Direct Update. Direct balance updates via the updateBalance admin endpoint are the highest-risk operation in vault-treasury. These require the 'treasury_admin' role AND MFA status of 'verified_biometric'. If MFA is not biometric-verified, CHALLENGE the user. If the user role is not 'treasury_admin', BLOCK immediately. All balance updates must be logged with full audit trail.",
            metadata={"policy_id": "TREASURY-09", "category": "access_control"}
        ),
        Document(
            page_content="Policy TREASURY-10: Off-Hours Operations. Payment approvals, account limit changes, balance updates, user approvals, or user deactivations performed between 00:00-06:00 UTC on weekdays, or at any time on weekends (Saturday/Sunday), require additional verification. CHALLENGE all off-hours actions unless the actor role is 'treasury_admin'. 'treasurer' users performing sensitive actions during off-hours should be BLOCKED.",
            metadata={"policy_id": "TREASURY-10", "category": "compliance"}
        ),
        Document(
            page_content="Policy TREASURY-11: Behavioral Anomaly Override. If Sentinel ML risk_score exceeds 0.85 AND anomaly_vectors contain biometric failures such as 'flight_time_profile_mismatch', 'mouse_path_quantization', or 'dwell_time_profile_mismatch', this is a confirmed identity compromise. BLOCK the user regardless of MFA status or role — applies equally to 'treasurer' and 'treasury_admin'. No exceptions.",
            metadata={"policy_id": "TREASURY-11", "category": "security"}
        ),
        Document(
            page_content="Policy TREASURY-12: ERP Simulator Operations. The ERP simulator is an admin-only feature that generates automated payment transactions for testing. Actions performed via the erp-simulator service (start, stop, updateConfig) require the 'treasury_admin' role and are system operations. Payments generated BY the ERP simulator should be treated as system-generated and should not trigger biometric or behavioral anomaly policies. However, the admin who starts/stops the simulator IS subject to normal Sentinel evaluation.",
            metadata={"policy_id": "TREASURY-12", "category": "compliance"}
        ),
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
    ingest_policies()

    print("Env setup done!!")
