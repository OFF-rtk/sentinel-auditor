"""
Sentinel Auditor — Enforcer Module

Single-Redis pattern (Upstash via REDIS_URL):
  Global keys (shared with sentinel-ml, no prefix):
    blacklist:{user_id}       → ban reason string (TTL-based)
    global_strikes:{user_id}  → strike counter (7-day TTL)

  Auditor-local keys (prefixed to avoid collisions):
    auditor:rate_limit:{user_id} → request counter (sliding window)

Strike Escalation:
  Strike 1-2  → 1-hour ban   (TTL 3600s)
  Strike 3+   → 24-hour ban  (TTL 86400s)
"""

import os
import smtplib
from email.mime.text import MIMEText

import redis
from dotenv import load_dotenv

load_dotenv()

# Key prefix — only for auditor-local keys (rate limiting)
LOCAL_PREFIX = "auditor:"

# ---------------------------------------------------------------------------
# Redis Connection (single Upstash instance)
# ---------------------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL")
if REDIS_URL:
    r = redis.from_url(REDIS_URL, decode_responses=True)
else:
    print("⚠ REDIS_URL not set — enforcement and rate limiting disabled")
    r = None

# SMTP config (optional — for pardon emails)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

# Global strikes TTL — 7 days
STRIKES_TTL = 604800


# ---------------------------------------------------------------------------
# Shield — Blacklist Check
# ---------------------------------------------------------------------------

def is_user_blacklisted(user_id: str) -> bool:
    """Check if a user is currently banned."""
    if not r:
        return False
    try:
        return r.exists(f"blacklist:{user_id}") > 0
    except redis.ConnectionError:
        print(" ⚠ Redis offline: Skipping blacklist check.")
        return False


def get_ban_reason(user_id: str) -> str | None:
    """Get the ban reason string for a blacklisted user."""
    if not r:
        return None
    try:
        return r.get(f"blacklist:{user_id}")
    except redis.ConnectionError:
        return None


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

def check_rate_limit(user_id: str, limit: int = 10, window: int = 60) -> bool:
    """
    Sliding-window rate limiter.

    Args:
        user_id: The actor's ID.
        limit:   Max requests allowed (default 10).
        window:  Time window in seconds (default 60s).

    Returns:
        True if allowed, False if limit exceeded.
    """
    if not r:
        return True

    key = f"{LOCAL_PREFIX}rate_limit:{user_id}"

    try:
        current_count = r.incr(key)
        if current_count == 1:
            r.expire(key, window)
        if current_count > limit:
            print(f" RATE LIMIT EXCEEDED: {user_id} hit {current_count}/{limit} reqs.")
            return False
        return True
    except Exception as e:
        print(f" Rate Limit Error: {e}")
        return True


# ---------------------------------------------------------------------------
# Strike System — Escalation
# ---------------------------------------------------------------------------

def get_strike_count(user_id: str) -> int:
    """Get the current global strike count for a user."""
    if not r:
        return 0
    try:
        count = r.get(f"global_strikes:{user_id}")
        return int(count) if count else 0
    except Exception as e:
        print(f" Strike count read error: {e}")
        return 0


def confirm_block(user_id: str, reason: str = "Policy Violation") -> bool:
    """
    Confirm a true positive BLOCK — escalate strikes and set ban.

    1. INCR global_strikes:{user_id}
    2. SETEX blacklist:{user_id} with TTL based on strike count:
       - Strikes 1-2:  1 hour  (3600s)
       - Strikes 3+:   24 hours (86400s)
    """
    if not r:
        print(" ⚠ Redis unavailable — cannot enforce block.")
        return False

    try:
        print(f" ENFORCER: Confirming block for {user_id}...")

        # Increment strikes (persistent counter with 7-day TTL)
        strikes = r.incr(f"global_strikes:{user_id}")
        r.expire(f"global_strikes:{user_id}", STRIKES_TTL)

        # Determine ban duration
        if strikes >= 3:
            ban_ttl = 86400  # 24 hours
            ban_reason = f"auditor_extended_ban|strike_{strikes}|{reason}"
            print(f" ENFORCER: Strike {strikes} — EXTENDED BAN (24h)")
        else:
            ban_ttl = 3600  # 1 hour
            ban_reason = f"auditor_confirmed_ban|strike_{strikes}|{reason}"
            print(f" ENFORCER: Strike {strikes} — STANDARD BAN (1h)")

        # Overwrite any existing ban (provisional or otherwise)
        r.setex(f"blacklist:{user_id}", ban_ttl, ban_reason)

        return True

    except Exception as e:
        print(f" ENFORCER FAILURE: {e}")
        return False


# ---------------------------------------------------------------------------
# Pardon — False Positive Recovery
# ---------------------------------------------------------------------------

def unblock_user(user_id: str) -> bool:
    """
    Remove a blacklist entry (false positive pardon).
    Called when the auditor's judge overrides a BLOCK to ALLOW.
    """
    if not r:
        return False

    try:
        deleted = r.delete(f"blacklist:{user_id}")
        if deleted:
            print(f" ENFORCER: Pardoned {user_id} — blacklist entry removed.")
        else:
            print(f" ENFORCER: No blacklist entry found for {user_id} (already expired).")
        return True
    except Exception as e:
        print(f" ENFORCER: Failed to pardon {user_id}: {e}")
        return False


def send_pardon_email(user_email: str, reason: str) -> bool:
    """
    Send an apology/unblock notification email via SMTP.
    Fails silently if SMTP credentials are not configured.
    """
    if not SMTP_USER or not SMTP_PASS:
        print(" ⚠ SMTP not configured — skipping pardon email.")
        return False

    try:
        subject = "Vault Security — Account Unblocked"
        body = (
            f"Hello,\n\n"
            f"Our security system temporarily restricted your account access "
            f"as a precautionary measure. After a thorough review, we have "
            f"determined this was a false positive and your access has been "
            f"fully restored.\n\n"
            f"Review Details:\n{reason}\n\n"
            f"We apologise for any inconvenience. No further action is required.\n\n"
            f"— Vault Security Team"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = user_email

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, user_email, msg.as_string())

        print(f" ENFORCER: Pardon email sent to {user_email}")
        return True

    except Exception as e:
        print(f" ENFORCER: Failed to send pardon email: {e}")
        return False
