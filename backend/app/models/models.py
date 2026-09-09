"""
SecureCloud 2.0 - SQLAlchemy Database Models
Complete enterprise RBAC, file storage, security scanning, IOC Threat Intelligence, and User Risk Profiling schema.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, BigInteger, DateTime, 
    ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from backend.app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(20), default="USER", nullable=False) # "USER" or "ADMIN"
    is_active = Column(Boolean, default=True)
    is_2fa_enabled = Column(Boolean, default=False)
    two_factor_enforced = Column(Boolean, default=False)
    two_factor_code = Column(String(16), nullable=True) # Persisted 6-digit verification code
    two_factor_expires_at = Column(DateTime, nullable=True)
    totp_secret = Column(String(64), nullable=True)
    reset_token = Column(String(64), nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)
    quota_bytes = Column(BigInteger, default=10 * 1024 * 1024 * 1024) # 10 GB
    admin_security_code = Column(String(32), default="994422") # Unique Admin Security Config PIN
    is_locked_down = Column(Boolean, default=False)
    used_quota_bytes = Column(BigInteger, default=0)
    risk_score = Column(Float, default=0.0) # 0.0 to 100.0
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)

    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    shared_links = relationship("SharedLink", back_populates="user", cascade="all, delete-orphan")
    risk_profile = relationship("UserRiskProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ip_address = Column(String(45), default="127.0.0.1")
    user_agent = Column(String(256), default="Browser")
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)

    user = relationship("User", back_populates="sessions")

class FileRecord(Base):
    __tablename__ = "files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(256), nullable=False)
    original_filename = Column(String(256), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    file_hash = Column(String(64), index=True, nullable=False) # SHA-256
    sha1_hash = Column(String(40), nullable=True)
    md5_hash = Column(String(32), nullable=True)
    mime_type = Column(String(128), default="application/octet-stream")
    extension = Column(String(32), default="")
    is_confidential = Column(Boolean, default=False)
    is_in_recycle_bin = Column(Boolean, default=False)
    current_version = Column(String(16), default="v1.0")
    threat_score = Column(Float, default=0.0)
    security_status = Column(String(32), default="CLEAN") # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    scan_status = Column(String(32), default="COMPLETED") # NOT_SCANNED, QUEUED, SCANNING, COMPLETED, FAILED
    storage_path = Column(String(512), nullable=False)
    last_scanned_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="files")
    versions = relationship("FileVersion", back_populates="file", cascade="all, delete-orphan")
    scans = relationship("SecurityScan", back_populates="file", cascade="all, delete-orphan")
    shared_links = relationship("SharedLink", back_populates="file", cascade="all, delete-orphan")
    confidential_meta = relationship("ConfidentialFile", back_populates="file", uselist=False, cascade="all, delete-orphan")
    recycle_meta = relationship("RecycleBinItem", back_populates="file", uselist=False, cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="file", cascade="all, delete-orphan")

class FileVersion(Base):
    __tablename__ = "file_versions"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), nullable=False)
    version_tag = Column(String(16), nullable=False) # e.g. "v1.0", "v1.1"
    file_size = Column(BigInteger, nullable=False)
    file_hash = Column(String(64), nullable=False) # SHA-256
    storage_path = Column(String(512), nullable=False)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("FileRecord", back_populates="versions")

class SecurityScan(Base):
    __tablename__ = "file_security_scans"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_hash = Column(String(64), index=True, nullable=False)
    threat_score = Column(Float, default=0.0)
    final_verdict = Column(String(64), nullable=False)
    security_status = Column(String(32), nullable=False) # CLEAN, SUSPICIOUS, MALICIOUS
    ml_prediction = Column(String(32), default="CLEAN")
    ml_probabilities = Column(JSON, default=dict)
    model_version = Column(String(64), default="LightGBM / EMBER2024")
    heuristic_score = Column(Float, default=0.0)
    heuristic_verdict = Column(String(32), default="CLEAN")
    triggered_rules = Column(JSON, default=list)
    explanations = Column(JSON, default=list)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("FileRecord", back_populates="scans")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String(36), ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(256), nullable=False)
    status = Column(String(32), default="QUEUED") # QUEUED, SCANNING, COMPLETED, FAILED
    stage_label = Column(String(64), default="Queued in Scanner")
    progress_percent = Column(Integer, default=10)
    final_verdict = Column(String(64), default="PENDING")
    threat_score = Column(Float, default=0.0)
    security_status = Column(String(32), default="UNKNOWN")
    ml_model = Column(String(64), default="LightGBM v1.2 / EMBER2024")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    file = relationship("FileRecord", back_populates="scan_jobs")

class SharedLink(Base):
    __tablename__ = "shared_links"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String(36), ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    is_password_protected = Column(Boolean, default=False)
    password_hash = Column(String(256), nullable=True)
    view_only = Column(Boolean, default=False)
    allow_download = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    download_count = Column(Integer, default=0)
    view_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("FileRecord", back_populates="shared_links")
    user = relationship("User", back_populates="shared_links")

class ConfidentialFile(Base):
    __tablename__ = "confidential_files"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    pin_salt = Column(String(64), nullable=False)
    pin_hash = Column(String(256), nullable=False)
    encrypted_key = Column(Text, nullable=False)
    saved_pin = Column(String(128), nullable=True)
    failed_attempts = Column(Integer, default=0)
    lockout_stage = Column(Integer, default=0) # 0: Normal, 1: 30min lockout, 2: 2hr lockout, 3: Permanent
    locked_until = Column(DateTime, nullable=True)
    is_permanently_locked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("FileRecord", back_populates="confidential_meta")

class RecycleBinItem(Base):
    __tablename__ = "recycle_bin"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_name = Column(String(256), nullable=False)
    deleted_at = Column(DateTime, default=datetime.utcnow)
    restore_path = Column(String(512), nullable=False)

    file = relationship("FileRecord", back_populates="recycle_meta")

class QuarantineFile(Base):
    __tablename__ = "quarantine_files"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), nullable=True)
    user_id = Column(Integer, nullable=True)
    file_hash = Column(String(64), index=True, nullable=False)
    original_filename = Column(String(256), nullable=False)
    quarantine_path = Column(String(512), nullable=False)
    quarantined_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(Text, nullable=False)
    status = Column(String(32), default="QUARANTINED") # QUARANTINED, RESTORED, DELETED

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), default="Anonymous")
    role = Column(String(20), default="USER")
    ip_address = Column(String(45), default="127.0.0.1")
    action = Column(String(64), nullable=False)
    resource = Column(String(256), nullable=False)
    result = Column(String(20), default="SUCCESS") # SUCCESS, FAILED, BLOCKED
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class IPRule(Base):
    __tablename__ = "ip_rules"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    rule_type = Column(String(20), default="BLACKLIST") # WHITELIST or BLACKLIST
    description = Column(String(256), nullable=True)
    location = Column(String(64), default="Local Network")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    threat_status = Column(String(32), default="CLEAN")
    is_active = Column(Boolean, default=True)

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True) # None = Global broadcast
    title = Column(String(128), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="INFO") # INFO, LOW, MEDIUM, HIGH, CRITICAL
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="INFO") # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source = Column(String(64), default="Hybrid Threat Engine")
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class MLFeedback(Base):
    __tablename__ = "ml_feedback"

    id = Column(Integer, primary_key=True, index=True)
    file_hash = Column(String(64), nullable=False)
    filename = Column(String(256), nullable=False)
    predicted_verdict = Column(String(64), nullable=False)
    is_correct = Column(Boolean, default=True)
    user_comment = Column(Text, nullable=True)
    user_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class VerifiedCleanArtifact(Base):
    __tablename__ = "verified_clean_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(String(64), unique=True, index=True, nullable=False)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    file_size = Column(Integer, default=0)
    mime_type = Column(String(128), default="application/octet-stream")
    detected_format = Column(String(64), default="BINARY")
    original_filename = Column(String(256), nullable=False)
    owner_user_id = Column(Integer, nullable=True)
    original_scan_id = Column(String(64), nullable=True)
    original_classification = Column(String(32), default="SUSPICIOUS")
    remediation_status = Column(String(32), default="VERIFIED_BY_ADMIN")
    verification_status = Column(String(32), default="VERIFIED_CLEAN") # VERIFIED_CLEAN, REVOKED
    verified_by_admin_id = Column(Integer, nullable=True)
    verified_by_username = Column(String(64), default="Admin")
    verified_at = Column(DateTime, default=datetime.utcnow)
    verification_reason = Column(Text, default="Admin explicit verified clean approval")
    verification_scope = Column(String(32), default="GLOBAL") # GLOBAL, OWNER_ONLY
    scanner_version = Column(String(64), default="SecureCloud Threat Engine v2.0")
    model_version = Column(String(64), default="securecloud-lgbm-v2")
    feature_version = Column(String(32), default="EMBER2024-v3")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# =========================================================================
# REAL THREAT INTELLIGENCE & EVENT LOG MODELS (ZERO RANDOM DATA)
# =========================================================================

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(64), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_id = Column(String(36), nullable=True)
    session_id = Column(String(36), nullable=True)
    ip_address = Column(String(45), default="127.0.0.1", index=True)
    user_agent = Column(String(256), nullable=True)
    device_id = Column(String(64), nullable=True)
    file_hash = Column(String(64), nullable=True, index=True)
    domain = Column(String(128), nullable=True)
    url = Column(String(256), nullable=True)
    country = Column(String(64), default="India")
    result = Column(String(32), default="SUCCESS") # SUCCESS, FAILED, BLOCKED
    severity = Column(String(20), default="INFO") # INFO, LOW, MEDIUM, HIGH, CRITICAL
    metadata_json = Column(JSON, default=dict)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(256), index=True, nullable=False) # IP, Domain, Hash, URL
    indicator_type = Column(String(32), index=True, nullable=False) # IP_ADDRESS, DOMAIN, URL, SHA256, SHA1, MD5, EMAIL, ASN, CVE, MALWARE_FAMILY
    source = Column(String(64), default="LOCAL_DATABASE") # LOCAL_DATABASE, ADMIN_IOC, ABUSE_IPDB, VIRUSTOTAL, URLHAUS
    threat_type = Column(String(64), default="MALICIOUS_INFRASTRUCTURE") # C2_SERVER, MALWARE_PAYLOAD, PHISHING, BRUTE_FORCE
    malware_family = Column(String(64), nullable=True)
    confidence = Column(Float, default=90.0) # 0 - 100
    severity = Column(String(20), default="HIGH") # LOW, MEDIUM, HIGH, CRITICAL
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    source_url = Column(String(256), nullable=True)
    raw_metadata = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatCorrelation(Base):
    __tablename__ = "threat_correlations"

    id = Column(String(64), primary_key=True) # e.g. "CORR-XXXX"
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(20), default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    score = Column(Float, default=0.0) # 0 - 100
    confidence = Column(Float, default=0.0) # 0 - 100
    primary_event_id = Column(String(36), nullable=True)
    user_id = Column(Integer, nullable=True)
    status = Column(String(32), default="OPEN") # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE, SUPPRESSED
    explanation = Column(Text, nullable=False)
    matched_rules = Column(JSON, default=list)
    matched_indicators = Column(JSON, default=list)
    threat_sources = Column(JSON, default=list)
    recommended_action = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict)

class CorrelationEvent(Base):
    __tablename__ = "correlation_events"

    id = Column(Integer, primary_key=True, index=True)
    correlation_id = Column(String(64), index=True, nullable=False)
    event_id = Column(String(36), index=True, nullable=False)

class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(20), default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    user_id = Column(Integer, nullable=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(64), default="Threat Correlation Engine")
    status = Column(String(32), default="OPEN") # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    assigned_to = Column(String(64), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

# =========================================================================
# REAL USER RISK PROFILING & BASELINE MODELS
# =========================================================================

class UserRiskProfile(Base):
    __tablename__ = "user_risk_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, index=True, nullable=False)
    risk_score = Column(Float, default=0.0) # 0.0 - 100.0
    risk_level = Column(String(20), default="LOW") # LOW, GUARDED, ELEVATED, HIGH, CRITICAL
    baseline_period = Column(String(32), default="30d")
    authentication_score = Column(Float, default=0.0)
    file_activity_score = Column(Float, default=0.0)
    sharing_score = Column(Float, default=0.0)
    session_score = Column(Float, default=0.0)
    threat_intel_score = Column(Float, default=0.0)
    top_factors = Column(JSON, default=list) # [{ signal_type, score, reason }]
    status = Column(String(32), default="NORMAL") # NORMAL, MONITORING, ELEVATED, HIGH_RISK, CRITICAL
    has_sufficient_history = Column(Boolean, default=False)
    calculated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="risk_profile")

class RiskEvent(Base):
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    event_id = Column(String(36), nullable=True)
    signal_type = Column(String(64), nullable=False)
    contribution = Column(Float, default=0.0)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserBaseline(Base):
    __tablename__ = "user_baselines"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    metric_name = Column(String(64), nullable=False)
    metric_value = Column(Float, default=0.0)
    sample_count = Column(Integer, default=0)
    calculated_at = Column(DateTime, default=datetime.utcnow)

class ThreatFeedSync(Base):
    __tablename__ = "threat_feed_syncs"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(64), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="SUCCESS") # RUNNING, SUCCESS, FAILED
    records_added = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    error = Column(Text, nullable=True)
