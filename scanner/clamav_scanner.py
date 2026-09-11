"""
SecureCloud - Optional ClamAV Antivirus Scanner
Checks local ClamAV daemon on port 3310 or clamscan binary in system PATH.
If unavailable, clearly reports 'ClamAV engine unavailable' without faking scan results.
"""

import os
import socket
import subprocess
from typing import Dict, Any, Optional

from backend.app.config import CLAMAV_HOST, CLAMAV_PORT

class ClamAVScanner:
    """Provides real ClamAV integration when available on the host/network."""

    @staticmethod
    def is_available() -> bool:
        """Checks whether ClamAV daemon is listening on configured host/port or clamscan is in PATH."""
        # 1. Check clamd TCP socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((CLAMAV_HOST, CLAMAV_PORT))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass

        # 2. Check clamscan executable
        try:
            res = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=1)
            if res.returncode == 0:
                return True
        except Exception:
            pass

        return False

    @staticmethod
    def scan_bytes(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Scans raw bytes with ClamAV if available.
        Returns status and virus signature name if infected.
        """
        if not ClamAVScanner.is_available():
            return {
                "available": False,
                "status": "UNAVAILABLE",
                "message": "Signature scanner unavailable; static/ML analysis continued.",
                "threat_found": False,
                "virus_name": None
            }

        # If available, run scan
        try:
            import clamd
            cd = clamd.ClamdNetworkSocket(CLAMAV_HOST, CLAMAV_PORT)
            res = cd.instream(raw_bytes)
            stream_res = res.get("stream", ("OK", None))
            if stream_res[0] == "FOUND":
                return {
                    "available": True,
                    "status": "INFECTED",
                    "message": f"ClamAV detected virus signature: {stream_res[1]}",
                    "threat_found": True,
                    "virus_name": stream_res[1]
                }
            return {
                "available": True,
                "status": "CLEAN",
                "message": "ClamAV scan completed: No virus signature matched.",
                "threat_found": False,
                "virus_name": None
            }
        except Exception as e:
            return {
                "available": False,
                "status": "ERROR",
                "message": f"ClamAV communication exception: {str(e)}",
                "threat_found": False,
                "virus_name": None
            }
