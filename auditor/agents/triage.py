import json
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from .utils import llm_junior

def brain_triage(log_entry: dict):
    """
    Step 1: The Triage.
    Decides if the log is suspicious enough to investigate.
    If yes, extracts 'Search term' to find the relevant laws.
    """

    risk_score = log_entry.get("sentinel_analysis", {}).get("risk_score", 0)
    anomalies = log_entry.get("sentinel_analysis", {}).get("anomaly_vectors", [])

    if risk_score < 0.5 and not anomalies:
        return {"status": "SAFE", "reason": "Low risk score and no anomalies."}

    print(f" Triage detected risk (Score: {risk_score}). Extracting context...")

    prompt = ChatPromptTemplate.from_template("""
    You are a Security Triage Officer. Analyze this audit log.
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
        print(f" Triage Error: {e}")
        return {"status": "INVESTIGATE", "search_terms": ["general security policy", "suspicious activity"]}
