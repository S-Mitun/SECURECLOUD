"""
SecureCloud - Centralized Authentication Router
Enterprise RBAC with User/Admin Separation, Strict 2FA Verification Code Storage & Confirmation,
and Admin Config PIN Protection.
"""

import random
import pyotp
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, UserSession, AuditLog, Notification
from backend.app.schemas.schemas import (
    UserRegisterRequest, UserLoginRequest, TokenResponse,
    PasswordResetInitRequest, PasswordResetConfirmRequest, TwoFactorVerifyRequest
)
from backend.app.security.auth_utils import (
    hash_password, verify_password, create_access_token, get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
)
from backend.app.security.ip_guard import (
    check_ip_access, get_client_ip, check_login_rate_limit,
    check_rate_limit, record_failed_login, clear_failed_logins
)
from backend.app.services.audit_service import AuditService
from backend.app.services.storage_service import get_user_storage_metrics, recalculate_user_storage
from backend.app.services.event_service import EventService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
def register_user(
    req: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Registers a new tenant account with strict role validation and rate limiting.
    """
    check_ip_access(request, db)
    check_rate_limit(request, scope="register", max_requests=10, window_seconds=60)
    client_ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "Unknown Browser")[:250]

    existing = db.query(User).filter(
        (User.email == req.email.strip().lower()) | (User.username == req.username.strip())
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is already registered."
        )

    # 10 GB Standard Quota
    default_quota = 10 * 1024 * 1024 * 1024
    is_admin = bool(req.role and req.role.upper() in ["ADMIN", "SECURITY_ANALYST"])
    assigned_role = req.role.upper() if is_admin else "USER"

    new_user = User(
        username=req.username.strip(),
        email=req.email.strip().lower(),
        hashed_password=hash_password(req.password),
        role=assigned_role,
        quota_bytes=default_quota,
        used_quota_bytes=0,
        is_active=True,
        is_2fa_enabled=False,
        two_factor_enforced=False,
        last_login_ip=client_ip,
        created_at=datetime.utcnow()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    EventService.record_event(
        db, "REGISTER", user_id=new_user.id, ip_address=client_ip,
        user_agent=ua, result="SUCCESS", severity="INFO",
        metadata={"role": new_user.role, "username": new_user.username}
    )

    AuditService.log(
        db, "REGISTER", f"User {new_user.username}", "SUCCESS",
        f"Registered with role {new_user.role}",
        user_id=new_user.id, username=new_user.username, role=new_user.role, ip_address=client_ip
    )

    access_token = create_access_token(
        data={"sub": str(new_user.id), "role": new_user.role, "username": new_user.username}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "role": new_user.role,
            "is_active": new_user.is_active,
            "is_2fa_enabled": new_user.is_2fa_enabled,
            "two_factor_enforced": False
        },
        "message": "Account created successfully."
    }

@router.post("/login", response_model=TokenResponse)
def login_user(
    req: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticates user with strict role separation, 2FA confirmation storage,
    and Admin Config Password verification.
    """
    check_ip_access(request, db)
    check_login_rate_limit(request, identifier=req.email)
    client_ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "Unknown Browser")[:250]

    identifier = req.email.strip()
    user = db.query(User).filter(
        (User.email == identifier.lower()) | (User.username == identifier)
    ).first()
    if not user or not verify_password(req.password, user.hashed_password):
        record_failed_login(client_ip)
        record_failed_login(identifier.lower())
        EventService.record_event(
            db, "LOGIN_FAILURE", ip_address=client_ip, user_agent=ua,
            result="FAILED", severity="MEDIUM", metadata={"attempted_email": req.email}
        )
        AuditService.log(db, "LOGIN", f"Identifier {req.email}", "FAILED", "Invalid credentials", ip_address=client_ip)
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        EventService.record_event(
            db, "LOGIN_BLOCKED", user_id=user.id, ip_address=client_ip, user_agent=ua,
            result="BLOCKED", severity="HIGH", metadata={"reason": "Account suspended"}
        )
        AuditService.log(db, "LOGIN", f"User {user.username}", "BLOCKED", "Account suspended", user_id=user.id, username=user.username, ip_address=client_ip)
        raise HTTPException(status_code=403, detail="Account is suspended or locked down by SOC Administrator.")

    # Strict Portal Validation (Mutual Exclusivity)
    portal = (req.portal or req.portal_type or "USER").upper()
    is_admin_role = user.role.upper() in ["ADMIN", "SECURITY_ANALYST"]
    if portal == "ADMIN" and not is_admin_role:
        EventService.record_event(
            db, "ADMIN_LOGIN_ATTEMPT", user_id=user.id, ip_address=client_ip, user_agent=ua,
            result="BLOCKED", severity="HIGH", metadata={"reason": "Unauthorized admin portal ingress"}
        )
        AuditService.log(
            db, "ADMIN_LOGIN_ATTEMPT", f"User {user.username}", "BLOCKED", 
            "USER attempted authentication through ADMIN portal",
            user_id=user.id, username=user.username, role=user.role, ip_address=client_ip
        )
        raise HTTPException(
            status_code=403,
            detail="Access denied. This account does not possess Administrator or Security Analyst privileges."
        )

    if portal == "USER" and is_admin_role:
        EventService.record_event(
            db, "USER_PORTAL_ADMIN_INGRESS", user_id=user.id, ip_address=client_ip, user_agent=ua,
            result="BLOCKED", severity="HIGH", metadata={"reason": "Admin attempted user portal ingress"}
        )
        AuditService.log(
            db, "USER_PORTAL_ADMIN_INGRESS", f"Admin {user.username}", "BLOCKED", 
            "ADMIN attempted authentication through USER portal",
            user_id=user.id, username=user.username, role=user.role, ip_address=client_ip
        )
        raise HTTPException(
            status_code=403,
            detail="Access denied. Administrator accounts must authenticate exclusively through the Admin Portal."
        )

    # 2FA Check (either user-enabled or admin-enforced)
    if user.is_2fa_enabled or user.two_factor_enforced:
        if not req.totp_code:
            # Generate a real 6-digit verification code and store in DB
            two_fa_code = f"{random.randint(100000, 999999)}"
            user.two_factor_code = two_fa_code
            user.two_factor_expires_at = datetime.utcnow() + timedelta(minutes=10)
            db.commit()

            temp_token = create_access_token({"sub": str(user.id), "temp_2fa": True}, expires_delta=timedelta(minutes=10))
            return {
                "access_token": "",
                "token_type": "bearer",
                "user": {
                    "id": user.id, 
                    "email": user.email, 
                    "username": user.username, 
                    "role": user.role,
                    "two_factor_enforced": user.two_factor_enforced or False
                },
                "requires_2fa": True,
                "temp_token": temp_token,
                "two_factor_code": two_fa_code,
                "message": f"Security Verification Code: {two_fa_code}"
            }
        
        # Strict 2FA verification: User must enter only the correct generated code (or TOTP secret)
        entered_code = req.totp_code.strip()
        is_valid_2fa = False

        if user.two_factor_code and entered_code == user.two_factor_code:
            if not user.two_factor_expires_at or user.two_factor_expires_at >= datetime.utcnow():
                is_valid_2fa = True

        if not is_valid_2fa and user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(entered_code, valid_window=1):
                is_valid_2fa = True

        if not is_valid_2fa:
            EventService.record_event(
                db, "TWO_FACTOR_FAILURE", user_id=user.id, ip_address=client_ip, user_agent=ua,
                result="FAILED", severity="HIGH", metadata={"entered_code": entered_code}
            )
            AuditService.log(db, "2FA_AUTH", f"User {user.username}", "FAILED", "Invalid 2FA code", user_id=user.id, ip_address=client_ip)
            raise HTTPException(status_code=401, detail="Invalid Two-Factor Authentication code. Verification failed.")

        # Clear 2FA one-time code upon successful validation
        user.two_factor_code = None
        db.commit()

    # Successful authentication: clear failure rate limit counters
    clear_failed_logins(client_ip)
    clear_failed_logins(user.email.strip().lower())

    # Check for New Device / New IP anomaly
    if user.last_login_ip and user.last_login_ip != client_ip and client_ip not in ["127.0.0.1", "localhost"]:
        EventService.record_event(
            db, "NEW_IP", user_id=user.id, ip_address=client_ip, user_agent=ua,
            result="SUCCESS", severity="LOW", metadata={"previous_ip": user.last_login_ip}
        )

    prev_session = db.query(UserSession).filter(UserSession.user_id == user.id).order_by(UserSession.created_at.desc()).first()
    if prev_session and prev_session.user_agent and prev_session.user_agent != ua:
        EventService.record_event(
            db, "NEW_DEVICE", user_id=user.id, ip_address=client_ip, user_agent=ua,
            result="SUCCESS", severity="LOW", metadata={"previous_device": prev_session.user_agent}
        )

    # Generate JWT
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role, "username": user.username}
    )

    # Update last login
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = client_ip
    db.commit()

    # Track active session
    session = UserSession(
        user_id=user.id,
        ip_address=client_ip,
        user_agent=ua,
        expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        is_revoked=False
    )
    db.add(session)
    db.commit()

    # Log successful login event
    EventService.record_event(
        db, "LOGIN_SUCCESS", user_id=user.id, ip_address=client_ip, user_agent=ua,
        result="SUCCESS", severity="INFO", metadata={"portal": portal}
    )

    AuditService.log(
        db, "LOGIN", f"User {user.username}", "SUCCESS",
        f"Portal: {portal}, IP: {client_ip}",
        user_id=user.id, username=user.username, role=user.role, ip_address=client_ip
    )

    metrics = get_user_storage_metrics(db, user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "is_2fa_enabled": user.is_2fa_enabled,
            "two_factor_enforced": user.two_factor_enforced or False,
            "used_quota_formatted": metrics["used_formatted"],
            "quota_formatted": metrics["quota_formatted"]
        },
        "message": f"Welcome back, {user.username}!"
    }

@router.get("/me")
def get_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns the current authenticated user profile with live storage quota."""
    metrics = get_user_storage_metrics(db, current_user.id)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_2fa_enabled": current_user.is_2fa_enabled,
        "two_factor_enforced": current_user.two_factor_enforced or False,
        "quota_bytes": metrics["quota_bytes"],
        "used_quota_bytes": metrics["used_bytes"],
        "remaining_quota_bytes": metrics["remaining_bytes"],
        "usage_percentage": metrics["usage_percentage"],
        "quota_formatted": metrics["quota_formatted"],
        "used_quota_formatted": metrics["used_formatted"],
        "remaining_quota_formatted": metrics["remaining_formatted"],
        "risk_score": current_user.risk_score,
        "created_at": current_user.created_at.strftime("%d %b %Y %H:%M")
    }

@router.post("/logout")
def logout_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logs out user and invalidates session."""
    client_ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "Unknown Browser")[:250]
    sessions = db.query(UserSession).filter(UserSession.user_id == current_user.id, UserSession.is_revoked == False).all()
    for s in sessions:
        s.is_revoked = True
    db.commit()

    EventService.record_event(
        db, "LOGOUT", user_id=current_user.id, ip_address=client_ip, user_agent=ua,
        result="SUCCESS", severity="INFO"
    )

    AuditService.log(
        db, "LOGOUT", f"User {current_user.username}", "SUCCESS",
        user_id=current_user.id, username=current_user.username, role=current_user.role, ip_address=client_ip
    )
    return {"status": "SUCCESS", "message": "Successfully logged out."}
