"""
SecureCloud - Security Feature Engineering Engine
Extracts 30+ static security features from raw bytes and files without executing code.
"""

import os
import re
import math
import zipfile
import io
from typing import Dict, Any, Union, Optional
import pandas as pd
import numpy as np

# Known dangerous/suspicious extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", 
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".ps2xml", 
    ".psc1", ".psc2", ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", 
    ".msh2xml", ".reg", ".hta", ".cpl", ".jar", ".msi", ".msp", ".vb", ".sh"
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".ppsm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab"}

# Suspicious keyword regex patterns
SUSPICIOUS_PATTERNS = [
    rb"powershell(\.exe)?", rb"cmd(\.exe)?", rb"wscript(\.exe)?", rb"cscript(\.exe)?",
    rb"invoke-expression", rb"iex\b", rb"downloadstring", rb"downloadfile",
    rb"frombase64string", rb"-enc(odedcommand)?", rb"bypass", rb"unrestricted",
    rb"wscript\.shell", rb"shellexecute", rb"virtualalloc", rb"writeprocessmemory",
    rb"createremotethread", rb"loadlibrary", rb"getprocaddress", rb"regread",
    rb"regwrite", rb"autopen", rb"document_open", rb"workbook_open",
    rb"autoexec", rb"eval\s*\(", rb"base64_decode", rb"exec\s*\(", rb"system\s*\(",
    rb"passthru", rb"shell_exec", rb"socket\.", rb"keylogger", rb"mimikatz",
    rb"bitstransfer", rb"certutil\s+-decode", rb"certutil\s+-urlcache"
]

SUSPICIOUS_URL_REGEX = re.compile(
    rb"(https?|ftp)://[^\s/$.?#].[^\s]*|(\d{1,3}\.){3}\d{1,3}(:\d+)?", re.IGNORECASE
)

SUSPICIOUS_CMD_REGEX = re.compile(
    rb"\b(net\s+user|net\s+localgroup|whoami|tasklist|taskkill|schtasks|vssadmin\s+delete|bcdedit|reg\s+add|reg\s+delete|chmod\s+\+x|wget|curl|nc\s+-e|bash\s+-i)\b", 
    re.IGNORECASE
)

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (range: 0.0 - 8.0)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total_bytes = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_bytes
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def detect_magic_signature(data: bytes) -> Dict[str, Any]:
    """Detects MIME and signature type from initial magic bytes."""
    if len(data) >= 2 and data[:2] == b"MZ":
        return {"magic_type": "EXECUTABLE", "detected_mime": "application/x-dosexec", "is_pe": 1}
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return {"magic_type": "ELF_BINARY", "detected_mime": "application/x-executable", "is_pe": 0}
    if len(data) >= 4 and data[:4] == b"%PDF":
        return {"magic_type": "PDF", "detected_mime": "application/pdf", "is_pe": 0}
    if len(data) >= 4 and data[:4] == b"PK\x03\x04":
        return {"magic_type": "ZIP_CONTAINER", "detected_mime": "application/zip", "is_pe": 0}
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return {"magic_type": "IMAGE_PNG", "detected_mime": "image/png", "is_pe": 0}
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return {"magic_type": "IMAGE_JPEG", "detected_mime": "image/jpeg", "is_pe": 0}
    if len(data) >= 4 and data[:4] == b"RIFF":
        return {"magic_type": "MEDIA_RIFF", "detected_mime": "audio/x-wav", "is_pe": 0}
    if len(data) >= 3 and data[:3] == b"ID3":
        return {"magic_type": "AUDIO_MP3", "detected_mime": "audio/mpeg", "is_pe": 0}
    if len(data) >= 4 and (data[4:8] == b"ftyp" or (len(data) >= 8 and data[4:8] == b"ftyp")):
        return {"magic_type": "VIDEO_MP4", "detected_mime": "video/mp4", "is_pe": 0}
    if len(data) >= 6 and (data[:6] == b"GIF87a" or data[:6] == b"GIF89a"):
        return {"magic_type": "IMAGE_GIF", "detected_mime": "image/gif", "is_pe": 0}
    
    # Check if mostly plain text
    if data:
        printable = sum(1 for b in data[:1024] if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / min(len(data), 1024) > 0.85:
            return {"magic_type": "TEXT_PLAIN", "detected_mime": "text/plain", "is_pe": 0}

    return {"magic_type": "UNKNOWN_BINARY", "detected_mime": "application/octet-stream", "is_pe": 0}

class FeatureExtractor:
    """Extracts ML-ready features from uploaded file bytes or file paths."""

    FEATURE_NAMES = [
        "file_size",
        "file_entropy",
        "mime_mismatch",
        "filename_length",
        "filename_complexity",
        "special_char_count",
        "is_hidden",
        "is_executable_ext",
        "is_script_ext",
        "is_macro_ext",
        "is_archive_ext",
        "has_double_extension",
        "is_dangerous_extension",
        "suspicious_string_count",
        "suspicious_url_count",
        "suspicious_cmd_count",
        "powershell_indicator",
        "javascript_indicator",
        "vba_macro_indicator",
        "obfuscation_score",
        "encoded_content_indicator",
        "eval_indicator",
        "nested_archive_depth",
        "archive_has_executable",
        "archive_has_script",
        "compression_ratio",
        "non_ascii_ratio",
        "magic_entropy",
        "magic_is_pe",
        "extension_category"
    ]

    @classmethod
    def get_extension_category(cls, ext: str) -> str:
        ext = ext.lower()
        if ext in [".exe", ".dll", ".sys", ".scr", ".com"]:
            return "executable"
        if ext in [".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".php"]:
            return "script"
        if ext in [".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".txt", ".csv", ".json", ".xml"]:
            return "document"
        if ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
            return "archive"
        if ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"]:
            return "image"
        if ext in [".mp3", ".wav", ".ogg", ".mp4", ".webm", ".avi", ".mkv"]:
            return "media"
        return "other"

    @classmethod
    def extract_features_from_bytes(cls, data: bytes, filename: str) -> Dict[str, Any]:
        """Extracts complete feature dictionary from file bytes and filename."""
        file_size = len(data)
        file_entropy = calculate_shannon_entropy(data)

        # Name features
        basename = os.path.basename(filename)
        ext = os.path.splitext(basename)[1].lower()
        filename_length = len(basename)
        special_chars = sum(1 for c in basename if not c.isalnum() and c not in "._-")
        complexity = round(special_chars / max(filename_length, 1), 4)
        is_hidden = 1 if basename.startswith(".") else 0

        # Double extension detection (e.g., file.pdf.exe, invoice.docx.ps1)
        name_parts = basename.split(".")
        has_double_ext = 1 if len(name_parts) > 2 and f".{name_parts[-2].lower()}" in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"] and f".{name_parts[-1].lower()}" in DANGEROUS_EXTENSIONS else 0

        # Extension checks
        is_executable_ext = 1 if ext in [".exe", ".dll", ".scr", ".com", ".sys"] else 0
        is_script_ext = 1 if ext in [".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".php", ".hta"] else 0
        is_macro_ext = 1 if ext in MACRO_EXTENSIONS else 0
        is_archive_ext = 1 if ext in ARCHIVE_EXTENSIONS else 0
        is_dangerous_ext = 1 if ext in DANGEROUS_EXTENSIONS else 0
        ext_category = cls.get_extension_category(ext)

        # Magic signature and MIME analysis
        magic_info = detect_magic_signature(data)
        magic_entropy = calculate_shannon_entropy(data[:64]) if data else 0.0
        magic_is_pe = magic_info["is_pe"]

        # MIME Mismatch detection
        mime_mismatch = 0
        if magic_info["magic_type"] == "EXECUTABLE" and ext not in [".exe", ".dll", ".sys", ".scr", ".com"]:
            mime_mismatch = 1
        elif magic_info["magic_type"] == "PDF" and ext != ".pdf":
            mime_mismatch = 1
        elif magic_info["magic_type"] == "IMAGE_PNG" and ext != ".png":
            mime_mismatch = 1

        # Suspicious string scans
        sample_chunk = data[:min(len(data), 512 * 1024)] # First 512 KB
        suspicious_string_count = 0
        for pattern in SUSPICIOUS_PATTERNS:
            matches = len(re.findall(pattern, sample_chunk, re.IGNORECASE))
            suspicious_string_count += matches

        url_matches = len(SUSPICIOUS_URL_REGEX.findall(sample_chunk))
        cmd_matches = len(SUSPICIOUS_CMD_REGEX.findall(sample_chunk))

        powershell_indicator = 1 if re.search(rb"(powershell|invoke-expression|frombase64string|-enc)", sample_chunk, re.IGNORECASE) else 0
        javascript_indicator = 1 if re.search(rb"(wscript\.shell|activexobject|document\.write|unescape\(|eval\()", sample_chunk, re.IGNORECASE) else 0
        vba_indicator = 1 if re.search(rb"(autopen|workbook_open|document_open|vba6\.dll|shell\()", sample_chunk, re.IGNORECASE) else 0
        eval_indicator = 1 if re.search(rb"\b(eval|exec|system|passthru|shell_exec)\s*\(", sample_chunk, re.IGNORECASE) else 0

        # Obfuscation indicator
        encoded_content_indicator = 1 if re.search(rb"([A-Za-z0-9+/]{40,}={0,2})|(\\x[0-9a-fA-F]{2}){8,}|(%[0-9a-fA-F]{2}){8,}", sample_chunk) else 0
        
        # Calculate non-ascii ratio
        non_ascii_count = sum(1 for b in sample_chunk if b < 32 or b > 126)
        non_ascii_ratio = round(non_ascii_count / max(len(sample_chunk), 1), 4)

        obfuscation_score = 0.0
        if encoded_content_indicator:
            obfuscation_score += 0.4
        if file_entropy > 7.2:
            obfuscation_score += 0.3
        if suspicious_string_count > 3:
            obfuscation_score += 0.3
        obfuscation_score = min(1.0, round(obfuscation_score, 2))

        # Archive internal analysis
        nested_archive_depth = 0
        archive_has_executable = 0
        archive_has_script = 0
        compression_ratio = 1.0

        if is_archive_ext and len(data) > 22:
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    namelist = zf.namelist()
                    total_uncompressed = 0
                    for name in namelist:
                        info = zf.getinfo(name)
                        total_uncompressed += info.file_size
                        inner_ext = os.path.splitext(name)[1].lower()
                        if inner_ext in [".exe", ".dll", ".scr", ".com", ".pif"]:
                            archive_has_executable = 1
                        if inner_ext in [".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh"]:
                            archive_has_script = 1
                        if inner_ext in ARCHIVE_EXTENSIONS:
                            nested_archive_depth = max(nested_archive_depth, 1)
                    if file_size > 0:
                        compression_ratio = round(total_uncompressed / file_size, 2)
            except Exception:
                pass

        return {
            "file_size": file_size,
            "file_entropy": file_entropy,
            "mime_mismatch": mime_mismatch,
            "filename_length": filename_length,
            "filename_complexity": complexity,
            "special_char_count": special_chars,
            "is_hidden": is_hidden,
            "is_executable_ext": is_executable_ext,
            "is_script_ext": is_script_ext,
            "is_macro_ext": is_macro_ext,
            "is_archive_ext": is_archive_ext,
            "has_double_extension": has_double_ext,
            "is_dangerous_extension": is_dangerous_ext,
            "suspicious_string_count": suspicious_string_count,
            "suspicious_url_count": url_matches,
            "suspicious_cmd_count": cmd_matches,
            "powershell_indicator": powershell_indicator,
            "javascript_indicator": javascript_indicator,
            "vba_macro_indicator": vba_indicator,
            "obfuscation_score": obfuscation_score,
            "encoded_content_indicator": encoded_content_indicator,
            "eval_indicator": eval_indicator,
            "nested_archive_depth": nested_archive_depth,
            "archive_has_executable": archive_has_executable,
            "archive_has_script": archive_has_script,
            "compression_ratio": compression_ratio,
            "non_ascii_ratio": non_ascii_ratio,
            "magic_entropy": magic_entropy,
            "magic_is_pe": magic_is_pe,
            "extension_category": ext_category
        }

    @classmethod
    def extract_features_from_file(cls, file_path: str) -> Dict[str, Any]:
        """Extracts features given a local file path."""
        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.extract_features_from_bytes(data, filename)

    @classmethod
    def to_dataframe(cls, feature_dict: Dict[str, Any]) -> pd.DataFrame:
        """Converts feature dictionary to a 1-row pandas DataFrame with standard feature names."""
        ordered = {k: [feature_dict.get(k, 0)] for k in cls.FEATURE_NAMES}
        return pd.DataFrame(ordered)
