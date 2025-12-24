import redis
import os

r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

def is_user_blacklisted(user_id: str):
    """
    THE SHIELD:
    Checks if a user is already banned in Redis.
    Used at the very start of the pipeline to save 8B/70B tokens.
    """
    try:
        return r.exists(f"blacklist:{user_id}")
    except redis.ConnectionError:
        print(" Redis Offline: Skipping blacklist check.")
        return False

def check_rate_limit(user_id: str, limit: int = 10, window: int = 60):
    """
    THE RATE LIMITER:
    Prevents any single user from flooding the system:

    Args:
        user_id: The actor's ID.
        limit: Max requests allowed (default 10).
        window: Time window in seconds (default 60s)

    Returns:
        True if allowed, False if limit exceeded.
    """
    if not r: return True

    key = f"rate_limit:{user_id}"

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

def block_user_session(user_id: str, reason: str = "Policy Violation"):
    """
    THE SWORD (Kill Switch)
    1. Adds user to Redis Blacklist (24h).
    2. Deletes their active Supabase session token (Simulated key for now).
    """
    if not r:
        return False

    try:
        print(f" ENFORCER: Initiating ban for {user_id}...")

        r.setex(f"blacklist:{user_id}", 86400, "banned")

        session_key = f"session:{user_id}"

        if r.exists(session_key):
            r.delete(session_key)
            print(f" ENFORCER: Session {session_key} TERMINATED.")
        else:
            print(f" ENFORCER: User has no active session key (already offline).")

        return True

    except Exception as e:
        print(f" ENFORCER FAILURE: {e}")
        return False
