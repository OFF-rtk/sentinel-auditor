import json
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from .utils import llm_junior, llm_senior

def brain_judge(log_entry: dict, policies: list):
    """
    Step 3: The Verdict.
    First, the Junior tries to decide. If unsure, the Senior steps in.
    """

    context_str = "\n".join(policies)

    print(" Junior Analyst is deliberating...")

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

    print(f" Escalating to CISO (Junior confidence only {verdict['confidence']}%)...")

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

    print(f" CISO Verdict: {final_verdict['decision']}")
    return final_verdict
