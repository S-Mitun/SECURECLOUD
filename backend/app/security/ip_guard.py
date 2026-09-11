"""
SecureCloud - IP Access Guard
Verifies client IP addresses against active whitelist and blacklist rules.
"""

import time
from collections import defaultdict
from datetime import datetime
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.models.models import IPRule

# In-memory sliding window trackers
_failed_login_attempts = defaultdict(list)
_endpoint_rate_limits = defaultdict(list)

def get_client_ip(request: Request) -> str:
    """Extracts client IP address considering proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def check_ip_access(request: Request, db: Session):
    """
    Validates client IP against IP rules in database.
    Raises 403 Forbidden if client IP is blacklisted.
    """
    client_ip = get_client_ip(request)
    
    # Check if there is an active rule for this IP
    rule = db.query(IPRule).filter(IPRule.ip_address == client_ip, IPRule.is_active == True).first()
    
    if rule:
        rule.last_seen = datetime.utcnow()
        db.commit()

        if rule.rule_type.upper() == "BLACKLIST":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Blocked by IP Access Guard: IP {client_ip} is blacklisted."
            )

def record_failed_login(key: str):
    """Records a timestamped failed login attempt for rate limiting / lockout."""
    _failed_login_attempts[key].append(time.time())

def clear_failed_logins(key: str):
    """Clears failed attempts on successful login."""
    if key in _failed_login_attempts:
        del _failed_login_attempts[key]

def check_rate_limit(
    request: Request,
    scope: str = "general",
    max_requests: int = 60,
    window_seconds: int = 60
):
    """Sliding-window request rate limiter per client IP."""
    ip = get_client_ip(request)
    now = time.time()
    key = f"{scope}:{ip}"
    
    # Clean older requests outside window
    _endpoint_rate_limits[key] = [t for t in _endpoint_rate_limits[key] if now - t < window_seconds]
    
    if len(_endpoint_rate_limits[key]) >= max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {scope}. Please try again shortly."
        )
    _endpoint_rate_limits[key].append(now)

def check_login_rate_limit(request: Request, identifier: str = ""):
    """
    Protects login endpoints against brute-force attacks.
    Enforces maximum 5 failed attempts per 5 minutes per IP/identifier.
    """
    ip = get_client_ip(request)
    now = time.time()
    lockout_seconds = 300  # 5 minutes
    
    for target in [ip, identifier.strip().lower()]:
        if not target:
            continue
        # Clean older failures
        _failed_login_attempts[target] = [t for t in _failed_login_attempts[target] if now - t < lockout_seconds]
        if len(_failed_login_attempts[target]) >= 5:
            oldest = _failed_login_attempts[target][0]
            remaining = int(lockout_seconds - (now - oldest))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Account temporarily locked out for security. Try again in {max(1, remaining)} seconds."
            )

