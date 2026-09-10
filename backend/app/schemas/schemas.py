"""
SecureCloud - Pydantic Request & Response Schemas
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

# Authentication
class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)
    role: Optional[str] = "USER" # "USER" or "ADMIN"
    admin_security_code: Optional[str] = "994422"

class UserLoginRequest(BaseModel):
    email: str
    password: str
    portal_type: str = "USER" # "USER" or "ADMIN"
    portal: Optional[str] = None
    mock_captcha_verified: Optional[bool] = True
    totp_code: Optional[str] = None
    admin_security_code: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]
    requires_2fa: bool = False
    temp_token: Optional[str] = None
    two_factor_code: Optional[str] = None
    message: Optional[str] = None

class TOTPSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_base64: str

class TOTPVerifyRequest(BaseModel):
    totp_code: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    reset_token: Optional[str] = None
    new_password: str = Field(..., min_length=6)

# Schema aliases for backwards compatibility
PasswordResetInitRequest = ForgotPasswordRequest
PasswordResetConfirmRequest = ResetPasswordRequest
TwoFactorVerifyRequest = TOTPVerifyRequest

# Files
class FileResponse(BaseModel):
    id: str
    filename: str
    original_filename: str
    file_size: int
    file_size_formatted: str
    file_hash: str
    mime_type: str
    extension: str
    is_confidential: bool
    is_in_recycle_bin: bool
    current_version: str
    threat_score: float
    security_status: str
    scan_status: Optional[str] = "COMPLETED"
    created_at: str
    updated_at: str

class FileRenameRequest(BaseModel):
    new_filename: str

# File Versions
class FileVersionResponse(BaseModel):
    id: int
    file_id: str
    version_tag: str
    file_size: int
    file_size_formatted: str
    file_hash: str
    created_at: str

# Shared Links
class CreateSharedLinkRequest(BaseModel):
    file_id: Optional[str] = None
    password: Optional[str] = None
    expires_in_hours: Optional[int] = 24
    view_only: bool = False
    allow_download: bool = True

class SharedLinkResponse(BaseModel):
    id: str
    file_id: str
    filename: str
    file_size: int
    file_size_formatted: str
    mime_type: str
    is_password_protected: bool
    view_only: bool
    allow_download: bool
    expires_at: Optional[str] = None
    time_remaining_seconds: Optional[int] = None
    download_count: int
    view_count: int
    created_at: str

class VerifySharePasswordRequest(BaseModel):
    password: str

# Confidential Vault
class ConfidentialLockRequest(BaseModel):
    file_id: Optional[str] = None
    pin: str = Field(..., min_length=4, max_length=32)
    save_password: Optional[bool] = True

class ConfidentialUnlockRequest(BaseModel):
    file_id: Optional[str] = None
    pin: str

# Recycle Bin
class RecycleBinItemResponse(BaseModel):
    id: int
    file_id: str
    original_name: str
    file_size: int
    file_size_formatted: str
    file_hash: str
    deleted_at: str

# Security Scan & ML
class ThreatScanResponse(BaseModel):
    file_id: Optional[str] = None
    filename: str
    file_hash: str
    threat_score: float
    threat_probability: Optional[float] = None
    final_verdict: str
    security_status: str
    ml_prediction: str
    ml_probabilities: Dict[str, float]
    model_version: str
    model_algorithm: str
    heuristic_score: float
    heuristic_verdict: str
    heuristic_rules: List[Dict[str, Any]]
    explanations: List[str]
    is_quarantined: bool
    scanned_at: str

class ScanJobResponse(BaseModel):
    scan_id: str
    file_id: str
    filename: str
    status: str # QUEUED, SCANNING, COMPLETED, FAILED
    stage_label: str
    progress_percent: int
    final_verdict: str
    threat_score: float
    security_status: str
    ml_model: str

class MLTrainRequest(BaseModel):
    dataset_name: Optional[str] = None

class MLFeedbackRequest(BaseModel):
    file_hash: str
    filename: str
    predicted_verdict: str
    is_correct: bool
    user_comment: Optional[str] = None

# IP Guard
class IPRuleCreateRequest(BaseModel):
    ip_address: str
    rule_type: str = "BLACKLIST" # "WHITELIST" or "BLACKLIST"
    description: Optional[str] = None

# SOC Admin
class UserQuotaUpdateRequest(BaseModel):
    quota_gb: float

class QuarantineActionRequest(BaseModel):
    action: str # "RESTORE" or "DELETE"
