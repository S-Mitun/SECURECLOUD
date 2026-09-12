"""
SecureCloud - Authentication & Role Authorization Security Engine
Strict server-side role validation, bcrypt hashing, JWT tokens, and TOTP 2FA.
"""

import os
import io
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import bcrypt
import jwt
import pyotp
import qrcode
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.app.config import (
    JWT_SECRET, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
    SUPABASE_URL, SUPABASE_KEY, SUPABASE_SERVICE_KEY, SUPABASE_JWT_SECRET
)
from backend.app.database import get_db
from backend.app.models.models import User, UserSession

security_bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Encodes JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates JWT token with support for:
    1. Supabase Auth JWT tokens (verified via SUPABASE_JWT_SECRET HS256)
    2. Supabase Auth API verification (when SUPABASE_URL & API key are set)
    3. Standard SecureCloud HMAC JWT tokens (local fallback)
    """
    # 1. Attempt Supabase JWT decoding if secret is present
    if SUPABASE_JWT_SECRET:
        try:
            return jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False}
            )
        except jwt.InvalidTokenError:
            pass

    # 2. Attempt verification with Supabase Auth API if Supabase URL & Key configured
    if SUPABASE_URL and (SUPABASE_KEY or SUPABASE_SERVICE_KEY):
        try:
            import urllib.request
            import json
            req = urllib.request.Request(
                f"{SUPABASE_URL.rstrip('/')}/auth/v1/user",
                headers={
                    "apikey": SUPABASE_KEY or SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {token}"
                }
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    supa_user = json.loads(resp.read().decode("utf-8"))
                    return {
                        "sub": supa_user.get("id"),
                        "email": supa_user.get("email"),
                        "user_metadata": supa_user.get("user_metadata", {}),
                        "app_metadata": supa_user.get("app_metadata", {}),
                        "aud": supa_user.get("aud", "authenticated"),
                        "role": supa_user.get("app_metadata", {}).get("role") or supa_user.get("user_metadata", {}).get("role", "USER")
                    }
        except Exception:
            pass

    # 3. Fall back to standard application JWT secret
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token.")

def generate_totp_secret() -> str:
    """Generates a random base32 TOTP secret."""
    return pyotp.random_base32()

def generate_totp_qr_base64(username: str, secret: str) -> Dict[str, str]:
    """Generates otpauth URL and base64 QR code image."""
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=username, issuer_name="SecureCloud")

    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_code_base64": f"data:image/png;base64,{qr_b64}"
    }

def verify_totp_code(secret: str, code: str) -> bool:
    """Verifies a 6-digit TOTP code against secret."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)

def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    """FastAPI dependency to extract and verify the current authenticated user."""
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_token(auth.credentials)
    user_id = payload.get("sub")
    email = payload.get("email")

    user = None
    # Lookup by numeric local ID if available
    if user_id and str(user_id).isdigit():
        user = db.query(User).filter(User.id == int(user_id)).first()

    # Lookup by email if ID not matched (e.g. Supabase Auth UUID in sub)
    if not user and email:
        user = db.query(User).filter(User.email == email.strip().lower()).first()

    # Auto-provision local profile record if authenticated via external Supabase Auth
    if not user and email:
        raw_username = payload.get("user_metadata", {}).get("username") or email.split("@")[0]
        username = raw_username.strip()
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{raw_username}_{counter}"
            counter += 1

        role_claim = (payload.get("app_metadata", {}).get("role") or
                      payload.get("user_metadata", {}).get("role", "USER")).upper()
        if role_claim not in ["USER", "ADMIN", "SECURITY_ANALYST"]:
            role_claim = "USER"

        user = User(
            username=username,
            email=email.strip().lower(),
            hashed_password="SUPABASE_MANAGED_AUTH",
            role=role_claim,
            is_active=True,
            quota_bytes=10 * 1024 * 1024 * 1024,
            created_at=datetime.utcnow()
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account not found.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is suspended. Contact administrator.")

    return user

def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """FastAPI dependency ensuring the caller has ADMIN or SECURITY_ANALYST role."""
    if current_user.role.upper() not in ["ADMIN", "SECURITY_ANALYST"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Administrator privileges required."
        )
    return current_user
