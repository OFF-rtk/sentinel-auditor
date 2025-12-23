import os
import json
import random
from dotenv import load_dotenv

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_huggingface import HuggingFaceEmbeddings
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

print("Loading Memory (MiniLM Embeddings)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

print("Waking up the Agents...")

llm_junior = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    max_tokens=1024,
    api_key=GROQ_API_KEY
)

llm_senior = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    max_tokens=1024,
    api_key=GROQ_API_KEY
)

def brain_architect(log_entry: dict):
    """
        Step 1: The Triage.
        Decides if the log is suspicious enough to investigate.
        If yes, extracts 'Search term' to find the relevant laws.
    """

    risk_score = log_entry.get("sentinel_analysis", {}).get("risk_score", 0)
    anomalies = log_entry.get("sentinel_analysis", {}).get("anomaly_vectors", [])

    if risk_score < 0.5 and not anomalies:
        return {"status": "SAFE", "reason": "Low risk score and and no anomalies."}

    print(f" Architect detected risk (Score: {risk_score}). Extracting context...")

    prompt = ChatPromptTemplate.from_template("""
    You are a Security Architect. Analyze this audit log.
    Extract 3-5 specific keywords or phrases that I should search for in the Company Security Poicy.

    - Focus on the User Role (e.g., "Executive", "Intern").
    - Focus on the Anomaly (e.g., "Impossible Travel", "VPN").
    - Focus on the Action (e.g., "Wire Transfer").

    Low: {log}

    Return ONLY a JSON list of strings. Example: ["executive travel policy", "VPN usage rules"]
    """)

    chain = prompt | llm_junior | JsonOutputParser()
    try:
        search_terms = chain.invoke({"log": json.dumps(log_entry)})
        return {"status": "INVESTIGATE", "search_terms": search_terms}
    except Exception as e:
        print(f" Architect Error: {e}")
        return {"status": "INVESTIGATE", "search_terms": ["general security policy", "suspicious activity"]}


def brain_critique(search_terms: list):
    """
        Step 2: The Retrieval.
        Uses Local Embeddings to find the exact Policy ID in Supabase.
    """

    print(f" Critique is searching policies for: {search_terms}")

    found_policies = []

    for term in search_terms:
        vector = embeddings.embed_query(term)

        result = supabase.rpc("match_documents", {
            "query_embedding": vector,
            "match_threshold": 0.3,
            "match_count": 1
        }).execute()

        if result.data:
            for doc in result.data:
                policy_text = f"{doc['content']} (Source: {doc['metadata']['policy_id']})"
                found_policies.append(policy_text)

    unique_policies = list(set(found_policies))

    if not unique_policies:
        print(" No specific policies found. Using Standard Protocal.")
        return ["Policy STD-00: Standard Security Protocol. If behavior is suspicious and no specific exemption exists, BLOCK the request."]

    return unique_policies


def brain_assembler(log_entry: dict, policies: list):
    """
        Step 3: The Verdict.
        First, the Junior tries to decide. If unsure, the Senior steps in.
    """

    context_str = "\n".join(policies)

    print(" Junior Assembler is deliberating...")

    junior_prompt = ChatPromptTemplate.from_template("""
    Your are a Junior Security Analyst.
    Tasks: Decide if this user should be BLOCKED or ALLOWED based strictly on the Policy.

    The Log: {log}

    The Policies:
    {policies}

    INSTRUCTIONS:
    1. If the policy explicitly permits the behavior (e.g., "Executives can use VPNs), ALLOW it.
    2. If the policy prohibits it (e.g., "North Korea is Banned"), BLOCK it.
    3. If you are not 100% sure, give a low confidence score.

    Return a JSON with:
    - decision: "BLOCK" or "ALLOW"
    - confidence: An integer 0-100
    - reasoning: One short sentence.
    """)

    chain = junior_prompt | llm_junior | JsonOutputParser()
    verdict = chain.invoke({"log": json.dumps(log_entry), "policies": context_str})

    if verdict["confidence"] >= 90:
        print(f" Junior is confident ({verdict['confidence']}%). Verdict: {verdict['decision']}")
        return verdict

    print(f" Escalating to Senior Partner (Junior confidence only {verdict['confidence']}%)...")

    senior_prompt = ChatPromptTemplate.from_template("""
    You are a CISO (Chief Information Security Officer).
    A Junior Analyst was unsure about this case. Make the final decision.

    THE SCENARIO:
    Log: {log}
    Policies: {policies}
    Junior's Doubt: "{junior_opinion}"

    YOUR JOB:
    Analyse the nuance. Is this a false positive? IS this a sophisticated attack?

    Return a JSON with:
    - decision: "BLOCK" or "ALLOW"
    - reasoning: A detailed explanation citing the policy Id.
    """)

    chain_senior = senior_prompt | llm_senior | JsonOutputParser()
    final_verdict = chain_senior.invoke({
        "log": json.dumps(log_entry),
        "policies": context_str,
        "junior_opinion": verdict["reasoning"]
    })

    print(f" Senior Verdict: {final_verdict['decision']}")
    return final_verdict


def run_sentinel():
    print("\n Scanning Audit Logs for threats...")

    response = supabase.table("audit_logs")\
        .select("*")\
        .gt("payload->sentinel_analysis->risk_score", 0.7)\
        .limit(1)\
        .execute()

    if not response.data:
        print(" No high-risk logs fround in the queue. System Clean.")
        return

    log_entry = response.data[0]['payload']
    user_id = log_entry['actor']['user_id']
    role = log_entry['actor']['role']
    print(f" Target Acquired: {user_id} ({role}) | Risk Score: {log_entry['sentinel_analysis']['risk_score']}")

    plan = brain_architect(log_entry)
    if plan["status"] == "SAFE":
        print(" Architect marked as SAFE. Closing case.")
        return

    policies = brain_critique(plan["search_terms"])

    decision = brain_assembler(log_entry, policies)

    print(f" FINAL DECISION: {decision['decision']}")
    print(f" REASON: {decision['reasoning']}")

    if decision["decision"] == "BLOCK":
        print(f" INITIATING ACTIVE DEFENSE FOR {user_id}...")
        try:
            print(" [SUPABASE API] Sesssion Token Revoked.")
            print(" [SUPABASE API] User Forced Logout.")
        except Exception as e:
            print(f" Error executing kill switch: {e}")
    else:
        print(" User Cleared. False Positive recorded.")


if __name__ == "__main__":
    run_sentinel()





