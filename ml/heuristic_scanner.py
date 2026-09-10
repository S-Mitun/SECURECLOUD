"""
SecureCloud - Heuristic Security Scanner
Fast, deterministic rule-based threat analyzer for uploaded files.
"""

import os
import re
import math
from typing import Dict, Any, List, Tuple
from ml.feature_engineering import calculate_shannon_entropy, detect_magic_signature, DANGEROUS_EXTENSIONS

class HeuristicScanner:
    """Performs deterministic heuristic threat analysis on file bytes and metadata."""

    @classmethod
    def scan(cls, data: bytes, filename: str) -> Dict[str, Any]:
        """
        Scans file bytes and filename.
        Returns:
            - heuristic_score: 0 to 100
            - heuristic_verdict: CLEAN | SUSPICIOUS | MALICIOUS
            - triggered_rules: list of rule triggers with severity
            - reasons: list of human-readable explanation strings
        """
        triggered_rules = []
        reasons = []
        score = 0

        basename = os.path.basename(filename)
        ext = os.path.splitext(basename)[1].lower()
        magic_info = detect_magic_signature(data)
        entropy = calculate_shannon_entropy(data)

        # 1. Check for Double Extension (e.g. report.pdf.exe)
        parts = basename.split(".")
        if len(parts) > 2:
            fake_ext = f".{parts[-2].lower()}"
            real_ext = f".{parts[-1].lower()}"
            if fake_ext in [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".txt", ".jpg", ".png"] and real_ext in DANGEROUS_EXTENSIONS:
                score += 55
                triggered_rules.append({
                    "rule": "DOUBLE_EXTENSION",
                    "severity": "CRITICAL",
                    "description": f"Dangerous double extension detected: disguised as '{fake_ext}' but executes as '{real_ext}'"
                })
                reasons.append(f"Double extension anomaly detected ({fake_ext}{real_ext})")

        # 2. Check for Disguised Executable (MIME/Magic Mismatch)
        if magic_info["magic_type"] == "EXECUTABLE" and ext not in [".exe", ".dll", ".sys", ".scr", ".com"]:
            score += 60
            triggered_rules.append({
                "rule": "DISGUISED_EXECUTABLE",
                "severity": "CRITICAL",
                "description": f"File has extension '{ext}' but contains a Windows PE Executable (MZ) header"
            })
            reasons.append("Disguised executable: PE binary header found in non-executable extension")

        if magic_info["magic_type"] == "ELF_BINARY" and ext not in [".elf", ".bin", ".out", ""]:
            score += 50
            triggered_rules.append({
                "rule": "DISGUISED_ELF_BINARY",
                "severity": "HIGH_RISK",
                "description": f"File has extension '{ext}' but contains a Linux ELF binary header"
            })
            reasons.append("Disguised Linux ELF binary header detected")

        # 3. Encoded PowerShell or Script Obfuscation
        sample = data[:min(len(data), 512 * 1024)]
        if re.search(rb"(powershell.*-enc|frombase64string|invoke-expression\s*\(\s*\[system\.text\.encoding\])", sample, re.IGNORECASE):
            score += 50
            triggered_rules.append({
                "rule": "ENCODED_POWERSHELL_PAYLOAD",
                "severity": "CRITICAL",
                "description": "Base64-encoded PowerShell command or dynamic expression invocation detected"
            })
            reasons.append("Encoded PowerShell payload detected")

        if re.search(rb"(certutil\s+-decode|certutil\s+-urlcache|bitsadmin\s+/transfer)", sample, re.IGNORECASE):
            score += 45
            triggered_rules.append({
                "rule": "LIVING_OFF_THE_LAND_BINARIES",
                "severity": "HIGH_RISK",
                "description": "Use of system utility (certutil/bitsadmin) for remote payload download/decoding"
            })
            reasons.append("Suspicious download/decode utility pattern detected")

        # 4. Dangerous VBA Macro Keywords in Office Documents
        if ext in [".docm", ".xlsm", ".pptm", ".doc", ".xls"] or (ext in [".docx", ".xlsx"] and b"vbaProject.bin" in data):
            if re.search(rb"(autopen|workbook_open|document_open|wscript\.shell|shellexecute|virtualalloc)", sample, re.IGNORECASE):
                score += 40
                triggered_rules.append({
                    "rule": "MALICIOUS_VBA_MACRO",
                    "severity": "HIGH_RISK",
                    "description": "Office document contains auto-executing macro routines with shell execution APIs"
                })
                reasons.append("Auto-executing VBA macro with shell execution APIs detected")

        # 5. Dangerous Script Execution Patterns in web/script files
        if ext in [".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta"]:
            cmd_count = len(re.findall(rb"(cmd\.exe|powershell\.exe|wscript\.shell|regsvr32|rundll32)", sample, re.IGNORECASE))
            if cmd_count >= 2:
                score += 35
                triggered_rules.append({
                    "rule": "SUSPICIOUS_SCRIPT_COMMANDS",
                    "severity": "HIGH_RISK",
                    "description": f"Script contains multiple system execution commands ({cmd_count} occurrences)"
                })
                reasons.append("Script contains multiple command execution invocations")

        # 5b. EICAR Standard Antivirus Test Signature & Known Shellcode
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in sample or re.search(rb"(nc\s+-e|/bin/sh|/bin/bash\s+-i|reverse_tcp|meterpreter)", sample, re.IGNORECASE):
            score += 80
            triggered_rules.append({
                "rule": "KNOWN_MALWARE_OR_EXPLOIT_SIGNATURE",
                "severity": "CRITICAL",
                "description": "Matched known malware signature, reverse shell, or standard antivirus test payload"
            })
            reasons.append("Known malware or shellcode signature detected")

        # 6. High-Entropy Packed / Encrypted Binary
        if ext in [".exe", ".dll", ".bin"] and entropy > 7.4:
            score += 30
            triggered_rules.append({
                "rule": "HIGH_ENTROPY_PACKED_CODE",
                "severity": "MEDIUM",
                "description": f"High Shannon entropy ({entropy:.2f}/8.00) indicates packed, encrypted, or compressed binary sections"
            })
            reasons.append(f"High file entropy ({entropy:.2f}) indicates packed/obfuscated code")

        # Determine heuristic verdict
        score = min(100, score)
        if score >= 50:
            verdict = "MALICIOUS"
        elif score >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        if not reasons:
            reasons.append("No heuristic threat signatures detected")

        return {
            "heuristic_score": score,
            "heuristic_verdict": verdict,
            "triggered_rules": triggered_rules,
            "reasons": reasons,
            "entropy": entropy,
            "magic_type": magic_info["magic_type"],
            "detected_mime": magic_info["detected_mime"]
        }
