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

    # =========================================================================
    # POLICIES — field names and values match the actual audit log payload:
    #
    #   actor.role:       "treasurer" | "treasury_admin"
    #   mfa_status:       "verified" | "not_verified"
    #   anomaly_vectors:  "impossible_travel" | "infra_mismatch" | "policy_violation"
    #   action_type:      "Payment Approval" | "Payment Rejection" |
    #                     "Account Limit Update" | "Account Limit Change Request" |
    #                     "Account Balance Update" | "Limit Request Approval" |
    #                     "Limit Request Rejection" | "User Approval" |
    #                     "User Rejection" | "User Deactivation" |
    #                     "ERP Simulator Start" | "ERP Simulator Stop" |
    #                     "ERP Simulator Config Update"
    #   geo_location:     { country, city, asn, lat, lng }
    #   client_fingerprint: { device_id, user_agent }
    # =========================================================================

    policies = [
        # --- General Access Policies ---
        Document(
            page_content="Policy EXEC-01: Executive Travel. Users with roles 'treasury_admin' are permitted to access the platform from international locations, provided their session shows consistent device_id and user_agent. 'impossible_travel' anomaly vectors for these users should be treated as warnings and CHALLENGED, not blocked outright, if the geo_location country changes between consecutive evaluations within the same session.",
            metadata={"policy_id": "EXEC-01", "category": "access_control"}
        ),
        Document(
            page_content="Policy TRANSFER-02: High Value Transfers. Any 'Payment Approval' action where the transaction amount exceeds $10,000 USD requires MFA. If mfa_status is 'verified', the transaction is approved regardless of geo_location. If mfa_status is 'not_verified', BLOCK immediately.",
            metadata={"policy_id": "TRANSFER-02", "category": "transaction"}
        ),
        Document(
            page_content="Policy AML-03: Sanctioned Countries. ALL access from North Korea (KP), Iran (IR), and Syria (SY) as reported by geo_location.country must be BLOCKED immediately. No exceptions for any role. Report to Compliance Team.",
            metadata={"policy_id": "AML-03", "category": "compliance"}
        ),
        Document(
            page_content="Policy SESSION-05: Session Hijacking. If actor.session_age_seconds is greater than 8 hours (28800) AND the geo_location.country changes between evaluations, this is a confirmed Session Hijack. Terminate session immediately and BLOCK the user.",
            metadata={"policy_id": "SESSION-05", "category": "security"}
        ),
        Document(
            page_content="Policy BIO-04: Behavioral Anomalies. If sentinel_analysis.anomaly_vectors contains 'impossible_travel', 'infra_mismatch', or 'policy_violation', this indicates a suspicious actor or compromised session. BLOCK immediately unless mfa_status is 'verified' — in which case CHALLENGE the user for re-verification.",
            metadata={"policy_id": "BIO-04", "category": "biometrics"}
        ),

        # --- Vault-Treasury Specific Policies ---
        Document(
            page_content="Policy TREASURY-06: Payment Approval Limits. Any 'Payment Approval' action where the transaction amount exceeds $50,000 USD requires the actor.role to be 'treasury_admin'. If a 'treasurer' role approves a payment exceeding $50,000, BLOCK immediately. Admin approvals of high-value payments should be ALLOWED if mfa_status is 'verified'.",
            metadata={"policy_id": "TREASURY-06", "category": "transaction"}
        ),
        Document(
            page_content="Policy TREASURY-07: Rapid-Fire Payment Actions. If the same actor.user_id performs more than 5 'Payment Approval' or 'Payment Rejection' actions within a 10-minute window, flag as suspicious. CHALLENGE the user if individual payment amounts are under $10,000. BLOCK if any payment amount exceeds $10,000. This pattern indicates potential automated fraud or compromised account.",
            metadata={"policy_id": "TREASURY-07", "category": "transaction"}
        ),
        Document(
            page_content="Policy TREASURY-08: Account Limit Modifications. Only users with actor.role 'treasury_admin' may perform 'Account Limit Update' or 'Limit Request Approval' actions. Standard 'treasurer' users may only perform 'Account Limit Change Request' actions, which require admin approval (maker-checker flow). If a non-admin performs 'Account Limit Update' or 'Limit Request Approval' directly, BLOCK immediately.",
            metadata={"policy_id": "TREASURY-08", "category": "access_control"}
        ),
        Document(
            page_content="Policy TREASURY-09: Balance Direct Update. 'Account Balance Update' actions are the highest-risk operation in vault-treasury. These require actor.role to be 'treasury_admin' AND mfa_status of 'verified'. If mfa_status is 'not_verified', CHALLENGE the user. If the actor.role is not 'treasury_admin', BLOCK immediately. All balance updates must be logged with full audit trail.",
            metadata={"policy_id": "TREASURY-09", "category": "access_control"}
        ),
        Document(
            page_content="Policy TREASURY-10: Off-Hours Operations. 'Payment Approval', 'Payment Rejection', 'Account Limit Update', 'Account Balance Update', 'User Approval', or 'User Deactivation' actions performed between 00:00-06:00 UTC on weekdays, or at any time on weekends (Saturday/Sunday), require additional verification. CHALLENGE all off-hours actions unless actor.role is 'treasury_admin'. 'treasurer' users performing sensitive actions during off-hours should be BLOCKED.",
            metadata={"policy_id": "TREASURY-10", "category": "compliance"}
        ),
        Document(
            page_content="Policy TREASURY-11: Behavioral Anomaly Override. If sentinel_analysis.risk_score exceeds 0.85 AND sentinel_analysis.anomaly_vectors contains any entries such as 'impossible_travel', 'infra_mismatch', or 'policy_violation', this is a confirmed identity compromise. BLOCK the user regardless of mfa_status or actor.role — applies equally to 'treasurer' and 'treasury_admin'. No exceptions.",
            metadata={"policy_id": "TREASURY-11", "category": "security"}
        ),
        Document(
            page_content="Policy TREASURY-12: ERP Simulator Operations. The ERP simulator is an admin-only feature that generates automated payment transactions for testing. Actions with action_type 'ERP Simulator Start', 'ERP Simulator Stop', or 'ERP Simulator Config Update' require actor.role to be 'treasury_admin' and are system operations. Payments generated BY the ERP simulator are system-generated and should not trigger biometric or behavioral anomaly policies. However, the admin who starts/stops the simulator IS subject to normal Sentinel evaluation.",
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
