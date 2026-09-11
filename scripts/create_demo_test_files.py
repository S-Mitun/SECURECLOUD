"""
SecureCloud - Safe Demonstration Test Files Generator
Generates harmless, non-malicious test fixtures for hackathon evaluation:
1. CLEAN: Standard harmless business report document
2. SUSPICIOUS: Safe file exhibiting double extension and elevated entropy
3. SAFE TEST HIGH-RISK FIXTURE: Explicitly labeled safe test fixture designed to trigger
   static heuristic indicators (high entropy + executable indicator string) for quarantine evaluation.

DO NOT execute or treat as malware. All test files are strictly benign.
"""

import os
import zlib
import random
from pathlib import Path

DEST_DIR = Path(__file__).resolve().parent.parent / "demo_test_files"
os.makedirs(DEST_DIR, exist_ok=True)

def generate_clean_file():
    clean_path = DEST_DIR / "clean_quarterly_report.txt"
    content = """SECURECLOUD BENIGN DEMONSTRATION DOCUMENT
Date: 2026-09-12
Classification: UNCLASSIFIED / PUBLIC
Author: Security Engineering

Summary:
This is a clean, verified document intended to validate the SecureCloud
storage, malware scanning, and ML threat classification pipeline.
All static analysis checks are expected to conclude with a CLEAN verdict.
Entropy is normal and no executable or script indicators exist.
"""
    clean_path.write_text(content, encoding="utf-8")
    print(f"[+] Created Clean File: {clean_path}")

def generate_suspicious_file():
    suspicious_path = DEST_DIR / "suspicious_invoice_receipt.pdf.sh"
    # Harmless shell script snippet with multiple extensions
    content = """#!/bin/sh
# SAFE DEMONSTRATION TEST: Harmless test file with multiple extensions
# Purpose: Validates SecureCloud multi-layer heuristic checks.
echo "Running quarterly cloud accounting ledger backup verification..."
date
"""
    suspicious_path.write_text(content, encoding="utf-8")
    print(f"[+] Created Suspicious File (Double Extension): {suspicious_path}")

def generate_high_risk_fixture():
    fixture_path = DEST_DIR / "safe_high_risk_demo_fixture.pdf"
    # Create safe test payload with MZ header and compressed random bytes (elevates entropy)
    # This triggers the heuristic rule for disguised executable (MZ header in .pdf)
    header = b"MZ\x90\x00" + b"SAFE DEMONSTRATION TEST FIXTURE -- NOT MALWARE\n"
    header += b"SECURECLOUD_DISGUISED_PE_TEST_FIXTURE_ELEVATED_ENTROPY\n"
    random.seed(42)
    high_entropy_bytes = bytes([random.randint(0, 255) for _ in range(32768)])
    data = header + high_entropy_bytes
    fixture_path.write_bytes(data)
    print(f"[+] Created Safe High-Risk Test Fixture (Disguised PE): {fixture_path}")

if __name__ == "__main__":
    print("Generating SecureCloud Safe Demo Test Files...")
    generate_clean_file()
    generate_suspicious_file()
    generate_high_risk_fixture()
    print(f"All demo files written to: {DEST_DIR}")
