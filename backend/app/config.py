"""
SecureCloud - Configuration Settings
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
ML_DIR = BASE_DIR / "ml"

# Storage Subdirectories
UPLOADS_DIR = STORAGE_DIR / "uploads"
QUARANTINE_DIR = STORAGE_DIR / "quarantine"
CONFIDENTIAL_DIR = STORAGE_DIR / "confidential"
RECYCLE_BIN_DIR = STORAGE_DIR / "recycle_bin"
TEMP_DIR = STORAGE_DIR / "temp"

for d in [STORAGE_DIR, UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR, TEMP_DIR]:
    os.makedirs(d, exist_ok=True)

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'securecloud.db'}")

# Security & JWT
JWT_SECRET = os.getenv("JWT_SECRET", "SECURECLOUD_PRODUCTION_JWT_SECRET_KEY_992178234891")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

# Storage Quota (10 GB default)
DEFAULT_USER_QUOTA_BYTES = 10 * 1024 * 1024 * 1024 # 10 GB
MAX_UPLOAD_SIZE_BYTES = 200 * 1024 * 1024 # 200 MB per file limit

# Telemetry
PROMETHEUS_METRICS_PATH = "/metrics"

# Supabase Cloud Integration
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", os.getenv("SUPABASE_ANON_KEY", ""))
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
SUPABASE_ENABLED = bool(SUPABASE_URL and (SUPABASE_KEY or SUPABASE_SERVICE_KEY))

# S3-Compatible Object Storage Configuration
S3_ENDPOINT = os.getenv("S3_ENDPOINT", "") # e.g. https://<account_id>.r2.cloudflarestorage.com or https://s3.amazonaws.com
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "")
S3_BUCKET = os.getenv("S3_BUCKET", "")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
S3_ENABLED = bool(S3_ACCESS_KEY and S3_SECRET_KEY and S3_BUCKET)

# Real ClamAV Malware Scanning Engine
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "127.0.0.1")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))

# Network & CORS Configuration
PORT = int(os.getenv("PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "")

