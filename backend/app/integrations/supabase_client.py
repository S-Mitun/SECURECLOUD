"""
SecureCloud - Supabase Integration Client
Provides cloud authentication sync, remote profile replication, and Supabase health inspection.
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from backend.app.config import SUPABASE_URL, SUPABASE_KEY, SUPABASE_SERVICE_KEY, SUPABASE_ENABLED

class SupabaseService:
    @staticmethod
    def is_configured() -> bool:
        return bool(SUPABASE_URL and (SUPABASE_KEY or SUPABASE_SERVICE_KEY))

    @staticmethod
    def get_status() -> Dict[str, Any]:
        configured = SupabaseService.is_configured()
        return {
            "enabled": configured,
            "supabase_url": SUPABASE_URL if configured else "Not configured (Operating in local SQLite mode)",
            "auth_mode": "SUPABASE_CLOUD_SYNC" if configured else "LOCAL_SQLITE_ZERO_KNOWLEDGE",
            "message": "Supabase connection active and synchronized." if configured else "Operating locally with built-in SQLite database. No external Supabase dependency required to register or login."
        }

    @staticmethod
    def register_user(email: str, password: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Registers a user on Supabase Auth if configured."""
        if not SupabaseService.is_configured():
            return {"status": "LOCAL_MODE", "synced": False}

        url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/signup"
        headers = {
            "apikey": SUPABASE_KEY or SUPABASE_SERVICE_KEY,
            "Content-Type": "application/json",
            "Authorization": f"Bearer {SUPABASE_KEY or SUPABASE_SERVICE_KEY}"
        }
        payload = {
            "email": email,
            "password": password,
            "data": metadata or {}
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
                return {"status": "SUCCESS", "synced": True, "supabase_user": data}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return {"status": "SUPABASE_ERROR", "synced": False, "error": err_body}
        except Exception as e:
            return {"status": "NETWORK_ERROR", "synced": False, "error": str(e)}

    @staticmethod
    def authenticate_user(email: str, password: str) -> Dict[str, Any]:
        """Authenticates with Supabase Auth if configured."""
        if not SupabaseService.is_configured():
            return {"status": "LOCAL_MODE", "synced": False}

        url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/token?grant_type=password"
        headers = {
            "apikey": SUPABASE_KEY or SUPABASE_SERVICE_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "email": email,
            "password": password
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
                return {"status": "SUCCESS", "synced": True, "session": data}
        except Exception as e:
            return {"status": "AUTH_FAILED", "synced": False, "error": str(e)}
