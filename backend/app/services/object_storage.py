"""
SecureCloud - Unified Object Storage Provider Abstraction
Supports S3-compatible cloud object storage (Cloudflare R2, AWS S3, Supabase Storage S3, MinIO)
with transparent local filesystem fallback for offline development.
"""

import os
import io
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

from backend.app.config import (
    S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET, S3_REGION, S3_ENABLED,
    STORAGE_DIR, UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR
)

class BaseStorageProvider(ABC):
    """Abstract interface for SecureCloud file storage providers."""

    @abstractmethod
    def save_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Stores raw bytes under the specified object key and returns storage identifier/path."""
        pass

    @abstractmethod
    def read_bytes(self, key_or_path: str) -> bytes:
        """Reads raw bytes for the specified object key or path."""
        pass

    @abstractmethod
    def delete(self, key_or_path: str) -> bool:
        """Permanently deletes the object."""
        pass

    @abstractmethod
    def exists(self, key_or_path: str) -> bool:
        """Checks if the object exists in storage."""
        pass

    @abstractmethod
    def generate_presigned_url(self, key_or_path: str, expires_in: int = 3600) -> Optional[str]:
        """Generates a temporary signed download URL if supported by the provider."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns human-readable name of the active storage provider."""
        pass

    @abstractmethod
    def check_health(self) -> Tuple[bool, str]:
        """Validates connectivity to storage provider."""
        pass


class S3StorageProvider(BaseStorageProvider):
    """S3-Compatible Object Storage Provider using boto3."""

    def __init__(self):
        import boto3
        from botocore.config import Config

        session = boto3.session.Session()
        client_kwargs = {
            "service_name": "s3",
            "aws_access_key_id": S3_ACCESS_KEY,
            "aws_secret_access_key": S3_SECRET_KEY,
            "config": Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "standard"})
        }
        if S3_ENDPOINT:
            client_kwargs["endpoint_url"] = S3_ENDPOINT
        if S3_REGION:
            client_kwargs["region_name"] = S3_REGION

        self.s3_client = session.client(**client_kwargs)
        self.bucket = S3_BUCKET

    def _normalize_key(self, key_or_path: str) -> str:
        """Strips local filesystem prefixes to guarantee clean S3 object keys."""
        norm = str(key_or_path).replace("\\", "/")
        if "storage/" in norm:
            norm = norm.split("storage/")[-1]
        return norm.lstrip("/")

    def save_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        clean_key = self._normalize_key(key)
        self.s3_client.put_object(
            Bucket=self.bucket,
            Key=clean_key,
            Body=data,
            ContentType=content_type,
            ServerSideEncryption="AES256"
        )
        return f"s3://{self.bucket}/{clean_key}"

    def read_bytes(self, key_or_path: str) -> bytes:
        clean_key = self._normalize_key(key_or_path)
        resp = self.s3_client.get_object(Bucket=self.bucket, Key=clean_key)
        return resp["Body"].read()

    def delete(self, key_or_path: str) -> bool:
        clean_key = self._normalize_key(key_or_path)
        try:
            self.s3_client.delete_object(Bucket=self.bucket, Key=clean_key)
            return True
        except Exception:
            return False

    def exists(self, key_or_path: str) -> bool:
        clean_key = self._normalize_key(key_or_path)
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=clean_key)
            return True
        except Exception:
            return False

    def generate_presigned_url(self, key_or_path: str, expires_in: int = 3600) -> Optional[str]:
        clean_key = self._normalize_key(key_or_path)
        try:
            return self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": clean_key},
                ExpiresIn=expires_in
            )
        except Exception:
            return None

    def get_provider_name(self) -> str:
        endpoint_info = S3_ENDPOINT if S3_ENDPOINT else "AWS S3"
        return f"S3-Compatible Object Storage ({self.bucket} @ {endpoint_info})"

    def check_health(self) -> Tuple[bool, str]:
        try:
            self.s3_client.head_bucket(Bucket=self.bucket)
            return True, f"Connected (Bucket: {self.bucket})"
        except Exception as e:
            return False, f"S3 Connection Error: {str(e)}"


class LocalStorageProvider(BaseStorageProvider):
    """Local Filesystem Storage Provider for offline development."""

    def __init__(self):
        for d in [STORAGE_DIR, UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR]:
            os.makedirs(d, exist_ok=True)

    def _resolve_path(self, key_or_path: str) -> Path:
        p = Path(key_or_path)
        if p.is_absolute() and p.exists():
            return p
        norm = str(key_or_path).replace("\\", "/").lstrip("/")
        if norm.startswith("s3://"):
            norm = "/".join(norm.split("/")[3:]) # Strip s3://bucket/
        
        # Check subdirectories
        for base in [UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR, STORAGE_DIR]:
            cand = base / norm
            if cand.exists():
                return cand
            # Direct filename match
            basename_cand = base / Path(norm).name
            if basename_cand.exists():
                return basename_cand
        
        # Default target under uploads
        return UPLOADS_DIR / norm

    def save_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        target = self._resolve_path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        return str(target)

    def read_bytes(self, key_or_path: str) -> bytes:
        target = self._resolve_path(key_or_path)
        if not target.exists():
            raise FileNotFoundError(f"Storage path not found: {key_or_path}")
        with open(target, "rb") as f:
            return f.read()

    def delete(self, key_or_path: str) -> bool:
        target = self._resolve_path(key_or_path)
        if target.exists():
            try:
                target.unlink()
                return True
            except Exception:
                return False
        return False

    def exists(self, key_or_path: str) -> bool:
        target = self._resolve_path(key_or_path)
        return target.exists()

    def generate_presigned_url(self, key_or_path: str, expires_in: int = 3600) -> Optional[str]:
        # Presigned URLs are not available for local filesystem storage
        return None

    def get_provider_name(self) -> str:
        return "Local Filesystem Storage (S3 Unconfigured)"

    def check_health(self) -> Tuple[bool, str]:
        if os.path.exists(STORAGE_DIR) and os.access(STORAGE_DIR, os.W_OK):
            return True, "Connected (Local Filesystem)"
        return False, "Local storage directory not writable"


# Singleton instance manager
_storage_provider_instance: Optional[BaseStorageProvider] = None

def get_storage_provider() -> BaseStorageProvider:
    """Returns the configured storage provider (S3 if credentials exist, otherwise Local)."""
    global _storage_provider_instance
    if _storage_provider_instance is None:
        if S3_ENABLED:
            try:
                _storage_provider_instance = S3StorageProvider()
            except Exception as e:
                print(f"[Storage Warning] Failed to initialize S3 provider ({e}); falling back to Local.")
                _storage_provider_instance = LocalStorageProvider()
        else:
            _storage_provider_instance = LocalStorageProvider()
    return _storage_provider_instance
