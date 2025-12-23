#!/usr/bin/env python3
"""
Audit Log Generator Script
Generates 1000 mock audit log entries with weighted scenarios:
- Scenario A (Normal User): 95% probability
- Scenario B (Clueless CEO): 3% probability  
- Scenario C (Hacker): 2% probability
"""

import json
import uuid
import random
from datetime import datetime, timezone
from faker import Faker
from enum import Enum
from typing import Any


# Initialize Faker
fake = Faker()


class Scenario(Enum):
    """Weighted scenarios for log generation"""
    NORMAL_USER = "normal"      # 95% - Standard safe transactions
    CLUELESS_CEO = "ceo"        # 3%  - Valid user, weird location, high risk but safe
    HACKER = "hacker"           # 2%  - High risk, bad IP, block status


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Roles aligned with RAG policy documents
ROLES = {
    Scenario.NORMAL_USER: ["intern", "standard_user", "analyst"],
    Scenario.CLUELESS_CEO: ["premium_user", "admin_viewer", "executive"],
    Scenario.HACKER: ["intern", "standard_user"],  # Hackers often use compromised low-level accounts
}

# IP Reputation mappings per scenario
IP_REPUTATIONS = {
    Scenario.NORMAL_USER: ["clean", "residential", "corporate"],
    Scenario.CLUELESS_CEO: ["high_risk_vpn", "datacenter", "unknown"],  # CEO traveling, using hotel/VPN
    Scenario.HACKER: ["high_risk_vpn", "tor_exit_node", "known_botnet", "blacklisted_proxy"],
}

# Countries per scenario
COUNTRIES = {
    Scenario.NORMAL_USER: ["US", "CA", "GB", "DE", "FR", "AU"],  # Safe western countries
    Scenario.CLUELESS_CEO: ["CN", "RU", "AE", "SG", "JP", "BR"],  # Unusual travel destinations
    Scenario.HACKER: ["RU", "CN", "KP", "IR", "NG", "UA"],  # High-risk countries
}

# --- UPDATED: Anomaly Vectors using "Profile Mismatch" Logic ---
# These align with the Sentinel Core documentation (Typist/Navigator/Context)
ANOMALY_VECTORS = [
    # --- The Typist (Keyboard) ---
    "flight_time_profile_mismatch",   # Typing speed changed
    "dwell_time_profile_mismatch",    # Key press duration changed
    "rhythm_syncopation_fail",        # Robotic rhythm (variance = 0)
    "bot_like_accuracy_spike",        # 0 errors from a messy typist
    
    # --- The Navigator (Mouse) ---
    "mouse_path_quantization",        # Straight lines (Bot)
    "mouse_velocity_drift",           # Too fast/slow
    "human_micro_jitter_absent",      # Too smooth (Bot)
    "robotic_constant_speed",         # No acceleration (Bot)
    
    # --- The Context (Environment) ---
    "impossible_travel",              # Berlin -> Tokyo in 1 hour
    "unusual_access_hours",           # 3 AM login
    "unknown_device_signature",       # New laptop
    "anonymized_network_route"        # VPN/TOR usage
]

# Services and action types
SERVICES = ["transfer_service", "account_service", "payment_service", "card_service", "loan_service"]
ACTION_TYPES = {
    "transfer_service": ["fund_transfer", "wire_transfer", "international_transfer"],
    "account_service": ["balance_inquiry", "statement_download", "account_update"],
    "payment_service": ["bill_payment", "scheduled_payment", "recurring_payment"],
    "card_service": ["card_activation", "limit_change", "pin_reset"],
    "loan_service": ["loan_application", "emi_payment", "loan_prepayment"],
}

# MFA statuses per scenario
MFA_STATUSES = {
    Scenario.NORMAL_USER: ["verified_time_based_otp", "verified_push_notification", "verified_biometric"],
    Scenario.CLUELESS_CEO: ["verified_time_based_otp", "verified_sms_otp"],  # CEO uses basic MFA
    Scenario.HACKER: ["failed_otp_attempt", "mfa_bypassed", "session_token_reuse", "pending_verification"],
}

# Sentinel decisions per scenario
SENTINEL_DECISIONS = {
    Scenario.NORMAL_USER: ["ALLOW", "ALLOW", "ALLOW", "LOG_ONLY"],  # Weighted toward ALLOW
    Scenario.CLUELESS_CEO: ["CHALLENGE_REQUIRED", "ALLOW_WITH_LOGGING", "STEP_UP_AUTH"],
    Scenario.HACKER: ["BLOCK", "CHALLENGE_REQUIRED", "QUARANTINE", "DENY"],
}

# Policies
POLICIES = [
    "POLICY_EXEC_01",
    "POLICY_TRANSFER_02", 
    "POLICY_AML_03",
    "POLICY_GEO_04",
    "POLICY_SESSION_05",
]


# ============================================================================
# GENERATOR FUNCTIONS
# ============================================================================

def choose_scenario() -> Scenario:
    """
    The 'Coin Flip' - Weighted random choice for scenario selection.
    95% Normal, 3% CEO, 2% Hacker
    """
    roll = random.random()
    if roll < 0.95:
        return Scenario.NORMAL_USER
    elif roll < 0.98:
        return Scenario.CLUELESS_CEO
    else:
        return Scenario.HACKER


def generate_ja3_hash() -> str:
    """Generate a mock JA3 hash (32-character MD5-like string)"""
    return uuid.uuid4().hex


def generate_device_id() -> str:
    """Generate a device ID"""
    return f"dev_{uuid.uuid4().hex[:16]}"


def generate_risk_score(scenario: Scenario) -> float:
    """Generate risk score based on scenario"""
    if scenario == Scenario.NORMAL_USER:
        return round(random.uniform(0.0, 0.2), 2)
    elif scenario == Scenario.CLUELESS_CEO:
        return round(random.uniform(0.4, 0.7), 2)  # Medium-high but not extreme
    else:  # HACKER
        return round(random.uniform(0.8, 0.99), 2)


# --- UPDATED: Generator Logic based on "Profile Mismatch" ---
def generate_anomaly_vectors(scenario: Scenario) -> list[str]:
    """Generate anomaly vectors based on scenario"""
    if scenario == Scenario.NORMAL_USER:
        return []
        
    elif scenario == Scenario.CLUELESS_CEO:
        # The CEO is legitimate. Their biometrics MATCH. 
        # Only the Network layer is suspicious (Context).
        # This allows the RAG Critique Brain to say: 
        # "Biometrics are clean, just the location is weird. Check VPN policy."
        return random.sample([
            "impossible_travel", 
            "unusual_access_hours", 
            "anonymized_network_route"
        ], k=random.randint(1, 2))
        
    else:  # HACKER
        # The Hacker is an Impostor.
        # Their biometrics DO NOT match the profile.
        # They will have a mix of Biometric failures (Sentinel Core) AND Network issues.
        
        # 1. Always pick at least one Biometric failure (The Typist/Navigator)
        biometric_fail = random.choice([
            "flight_time_profile_mismatch",
            "dwell_time_profile_mismatch",
            "mouse_path_quantization",
            "bot_like_accuracy_spike"
        ])
        
        # 2. Pick random others (Network or Biometric)
        other_fails = random.sample(ANOMALY_VECTORS, k=random.randint(1, 3))
        
        # Combine and deduplicate
        return list(set([biometric_fail] + other_fails))


def generate_transaction_details(scenario: Scenario) -> dict[str, Any]:
    """Generate transaction details with amounts based on scenario"""
    if scenario == Scenario.NORMAL_USER:
        amount = round(random.uniform(10.0, 5000.0), 2)
        recipient_country = random.choice(["US", "CA", "GB", "DE"])
    elif scenario == Scenario.CLUELESS_CEO:
        amount = round(random.uniform(10000.0, 100000.0), 2)  # CEOs move big money
        recipient_country = random.choice(["CN", "SG", "AE", "CH"])  # International deals
    else:  # HACKER
        amount = round(random.uniform(5000.0, 50000.0), 2)  # Significant but not huge
        recipient_country = random.choice(["RU", "CN", "NG", "IR"])  # Suspicious destinations
    
    return {
        "amount": amount,
        "currency": random.choice(["USD", "EUR", "GBP"]),
        "recipient_country": recipient_country
    }


def generate_audit_log(scenario: Scenario, timestamp: datetime) -> dict[str, Any]:
    """Generate a complete audit log entry for the given scenario"""
    
    # Generate unique IDs
    event_id = f"evt_{uuid.uuid4()}"
    correlation_id = f"corr_{uuid.uuid4().hex[:6]}_request_{random.randint(1, 9999)}"
    user_id = f"usr_{random.randint(10000, 99999)}"
    session_id = f"sess_{random.randint(100000, 999999)}"
    
    # Select scenario-appropriate values
    role = random.choice(ROLES[scenario])
    ip_reputation = random.choice(IP_REPUTATIONS[scenario])
    country = random.choice(COUNTRIES[scenario])
    mfa_status = random.choice(MFA_STATUSES[scenario])
    
    # Service and action
    service = random.choice(SERVICES)
    action_type = random.choice(ACTION_TYPES[service])
    
    # Sentinel analysis
    risk_score = generate_risk_score(scenario)
    anomaly_vectors = generate_anomaly_vectors(scenario)
    decision = random.choice(SENTINEL_DECISIONS[scenario])
    
    # Transaction details
    details = generate_transaction_details(scenario)
    
    return {
        # --- METADATA (System Health & Tracing) ---
        "event_id": event_id,
        "correlation_id": correlation_id,
        "timestamp": timestamp.isoformat(),
        "environment": random.choices(["production", "staging"], weights=[95, 5])[0],
        
        # --- ACTOR CONTEXT (Who did it?) ---
        "actor": {
            "user_id": user_id,
            "role": role,
            "session_id": session_id,
            "session_age_seconds": random.randint(60, 7200)  # 1 min to 2 hours
        },
        
        # --- NETWORK CONTEXT (Where are they?) ---
        "network_context": {
            "ip_address": fake.ipv4(),
            "ip_reputation": ip_reputation,
            "geo_location": {
                "country": country,
                "city": fake.city(),
                "asn": f"AS{random.randint(1000, 99999)} {fake.company()}"
            },
            "client_fingerprint": {
                "user_agent_raw": fake.user_agent(),
                "ja3_hash": generate_ja3_hash(),
                "device_id": generate_device_id()
            }
        },
        
        # --- ACTION CONTEXT (What did they try?) ---
        "action_context": {
            "service": service,
            "action_type": action_type,
            "resource_target": f"account_{random.randint(100, 9999)}",
            "details": details
        },
        
        # --- SENTINEL ANALYSIS (What did the ML think?) ---
        "sentinel_analysis": {
            "engine_version": "v2.1.0",
            "risk_score": risk_score,
            "decision": decision,
            "anomaly_vectors": anomaly_vectors
        },
        
        # --- ENFORCEMENT (What happened immediately?) ---
        "security_enforcement": {
            "mfa_status": mfa_status,
            "policy_applied": random.choice(POLICIES)
        },
        
        # --- INTERNAL METADATA (For debugging/analysis) ---
        "_scenario": scenario.value  # Hidden field to verify distribution
    }


def generate_logs(count: int = 1000) -> list[dict[str, Any]]:
    """Generate the specified number of audit logs"""
    logs = []
    scenario_counts = {s: 0 for s in Scenario}
    
    for _ in range(count):
        # Step 1: Decide the scenario (The Coin Flip)
        scenario = choose_scenario()
        scenario_counts[scenario] += 1
        
        # Step 2: Generate timestamp spread over last 7 days
        timestamp = fake.date_time_between(start_date='-7d', end_date='now', tzinfo=timezone.utc)
        
        # Step 3: Generate the log entry
        log = generate_audit_log(scenario, timestamp)
        logs.append(log)
    
    # Sort by timestamp for easier debugging
    logs.sort(key=lambda x: x["timestamp"])
    
    return logs, scenario_counts


def validate_logs(logs: list[dict], scenario_counts: dict) -> None:
    """Validate the generated logs meet requirements"""
    print("\n" + "=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)
    
    # Check count
    print(f"\n✓ Total entries: {len(logs)}")
    
    # Check scenario distribution
    print(f"\n📊 Scenario Distribution:")
    for scenario, count in scenario_counts.items():
        percentage = (count / len(logs)) * 100
        print(f"   {scenario.name}: {count} ({percentage:.1f}%)")
    
    # Check high risk entries
    high_risk = [l for l in logs if l["sentinel_analysis"]["risk_score"] >= 0.8]
    print(f"\n🚨 High Risk entries (score >= 0.8): {len(high_risk)}")
    
    # Check anomaly vectors populated for high risk
    high_risk_with_anomalies = [l for l in high_risk if l["sentinel_analysis"]["anomaly_vectors"]]
    print(f"   With anomaly_vectors populated: {len(high_risk_with_anomalies)}")
    
    # Check unique IDs
    event_ids = [l["event_id"] for l in logs]
    unique_ids = len(set(event_ids))
    print(f"\n🔑 Unique event_ids: {unique_ids}/{len(logs)}")
    
    # Sample entries
    print("\n" + "=" * 60)
    print("SAMPLE ENTRIES")
    print("=" * 60)
    
    for scenario in Scenario:
        sample = next((l for l in logs if l["_scenario"] == scenario.value), None)
        if sample:
            print(f"\n📋 Sample {scenario.name}:")
            print(f"   Risk Score: {sample['sentinel_analysis']['risk_score']}")
            print(f"   Decision: {sample['sentinel_analysis']['decision']}")
            print(f"   Anomalies: {sample['sentinel_analysis']['anomaly_vectors']}")
            print(f"   Role: {sample['actor']['role']}")
            print(f"   Country: {sample['network_context']['geo_location']['country']}")


def main():
    """Main entry point"""
    print("🏦 Secure Bank Audit Log Generator")
    print("=" * 60)
    print("Generating 1000 audit log entries...")
    print("Scenarios: 95% Normal | 3% CEO | 2% Hacker")
    print("=" * 60)
    
    # Generate logs
    logs, scenario_counts = generate_logs(1000)
    
    # Remove internal metadata before saving
    for log in logs:
        del log["_scenario"]
    
    # Save to file
    output_path = "audit_logs.json"
    with open(output_path, "w") as f:
        json.dump(logs, f, indent=2)
    
    print(f"\n✅ Successfully generated {len(logs)} audit logs")
    print(f"📁 Saved to: {output_path}")
    
    # Re-add scenario for validation display (temporarily)
    # Validate (we can infer scenario from risk scores)
    print("\n" + "=" * 60)
    print("QUICK STATS")
    print("=" * 60)
    
    for scenario, count in scenario_counts.items():
        percentage = (count / len(logs)) * 100
        print(f"   {scenario.name}: {count} ({percentage:.1f}%)")
    
    high_risk = [l for l in logs if l["sentinel_analysis"]["risk_score"] >= 0.8]
    print(f"\n🚨 High Risk entries: {len(high_risk)}")
    print(f"🔑 All IDs unique: {len(set(l['event_id'] for l in logs)) == len(logs)}")


if __name__ == "__main__":
    main()
