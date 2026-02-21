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
    You are a Junior Security Analyst reviewing Sentinel behavioral biometric logs.
    Task: Decide if this user should be BLOCKED or ALLOWED based strictly on the Policy.

    SENTINEL ANALYSIS CONTEXT:
    - "decision": "CHALLENGE" means Sentinel's ML engine detected suspicious behavioral patterns
      and required additional verification. This is an ELEVATED RISK signal.
    - "decision": "ALLOW" means Sentinel found the behavior acceptable.
    - "decision": "BLOCK" means Sentinel detected definitive bot/attack behavior.
    
    ANOMALY VECTOR TYPES:
    - "keystroke_anomaly_X_confidence_Y": HST model detected typing patterns that deviate
      significantly from the user's learned baseline. X is severity (0-1), Y is confidence.
    - "keystroke_elevated_X_confidence_Y": Moderately elevated typing anomaly.
    - "mouse_teleportation_X": X fraction of clicks had no preceding mouse movement (cursor
      teleported to target). Humans ALWAYS produce micro-movements before clicking.
    - "dwell_time_*_high/low": Individual keystroke timing deviations.
    - "flight_time_*_high/low": Inter-key timing deviations.
    - "unknown_user_agent": Non-standard browser user-agent string detected.

    The Log: {log}

    The Policies:
    {policies}

    INSTRUCTIONS:
    1. If the policy explicitly permits the behavior, ALLOW it.
    2. If the policy prohibits it, BLOCK it.
    3. If sentinel_analysis.decision is "CHALLENGE" with risk_score > 0.7 AND anomaly_vectors
       are present, this is strong evidence of non-human behavior — lean toward BLOCK.
    4. If you are not 100% sure, give a low confidence score.

    Return a JSON with:
    - decision: "BLOCK" or "ALLOW"
    - confidence: An integer 0-100
    - reasoning: One short sentence.

    RESPOND WITH ONLY THE JSON OBJECT. NO text before or after. NO explanations. NO markdown.
    """)

    chain = junior_prompt | llm_junior | JsonOutputParser()
    verdict = chain.invoke({"log": json.dumps(log_entry), "policies": context_str})

    if verdict["confidence"] >= 90:
        print(f" Junior is confident ({verdict['confidence']}%). Verdict: {verdict['decision']}")

        verdict["model_used"] = "Junior Analyst"
        return verdict

    print(f" Escalating to CISO (Junior confidence only {verdict['confidence']}%)...")

    senior_prompt = ChatPromptTemplate.from_template("""
    You are a CISO (Chief Information Security Officer).
    A Junior Analyst was unsure about this case. Make the final decision.

    THE SCENARIO:
    Log: {log}
    Policies: {policies}
    Junior's Doubt: "{junior_opinion}"

    SENTINEL ML CONTEXT:
    - "CHALLENGE" decisions from Sentinel indicate the ML engine detected behavioral anomalies
      during the user's session. The user was forced to re-verify their identity via typing.
    - A high risk_score (>0.7) combined with keystroke_anomaly or mouse_teleportation vectors
      is strong evidence of automated (bot) behavior, even if the exact threshold in policy
      is not reached.
    - "unknown_user_agent" means the browser wasn't recognized — this could be a niche browser
      or a new device, NOT necessarily a bot. Only suspicious when combined with other vectors.
    - keystroke_anomaly vectors indicate the typing pattern is statistically anomalous compared
      to the user's learned baseline — this IS a behavioral biometric failure.
    - mouse_teleportation vectors indicate the cursor appeared at click targets without
      traversing intermediate space — physically impossible with a real mouse.

    CRITICAL — CUMULATIVE EVIDENCE:
    Check the anomaly_vectors as a WHOLE. A single vector alone (e.g. just unknown_user_agent)
    may be benign. But MULTIPLE vectors together (unknown_user_agent + keystroke_anomaly +
    mouse_teleportation) are cumulative evidence of bot behavior. The more vectors present,
    the stronger the case for BLOCK. Do not dismiss a high risk_score just because one
    individual threshold isn't met — look at the combined picture.

    YOUR JOB:
    Analyse the nuance. Is this a false positive? Is this a sophisticated attack?
    Consider ALL anomaly vectors together — multiple weak signals can indicate a bot.

    RESPOND WITH ONLY A JSON OBJECT. NO text before or after. NO explanations. NO markdown.
    The JSON must have EXACTLY these keys:
    {{"decision": "BLOCK" or "ALLOW", "reasoning": "one sentence citing policy", "confidence": 0-100}}
    """)

    chain_senior = senior_prompt | llm_senior | JsonOutputParser()

    try:
        final_verdict = chain_senior.invoke({
            "log": json.dumps(log_entry),
            "policies": context_str,
            "junior_opinion": verdict["reasoning"]
        })
    except Exception as parse_err:
        # Fallback: extract decision from the raw text if JSON parse fails
        import re
        raw = str(parse_err)
        print(f" CISO JSON parse failed — extracting from raw output...")

        decision_match = re.search(r'(?:decision|Decision)[:\s]*"?(BLOCK|ALLOW|CHALLENGE)"?', raw, re.IGNORECASE)
        confidence_match = re.search(r'(?:confidence|Confidence)[:\s]*(\d+)', raw, re.IGNORECASE)
        reasoning_match = re.search(r'(?:reasoning|Reasoning)[:\s]*"([^"]+)"', raw, re.IGNORECASE)

        final_verdict = {
            "decision": decision_match.group(1).upper() if decision_match else "BLOCK",
            "confidence": int(confidence_match.group(1)) if confidence_match else 80,
            "reasoning": reasoning_match.group(1) if reasoning_match else "CISO analysis inconclusive — defaulting to BLOCK based on anomaly evidence",
        }
        print(f" Fallback verdict: {final_verdict}")

    # Normalize keys — LLMs sometimes use alternate names
    if "verdict" in final_verdict and "decision" not in final_verdict:
        final_verdict["decision"] = final_verdict.pop("verdict")
    if "reason" in final_verdict and "reasoning" not in final_verdict:
        final_verdict["reasoning"] = final_verdict.pop("reason")
    if "reasoning" not in final_verdict or not final_verdict["reasoning"]:
        final_verdict["reasoning"] = f"CISO verdict: {final_verdict.get('decision', 'BLOCK')} with confidence {final_verdict.get('confidence', 0)}%"

    final_verdict["model_used"] = "CISO"

    print(f" CISO Verdict: {final_verdict['decision']}")
    return final_verdict
