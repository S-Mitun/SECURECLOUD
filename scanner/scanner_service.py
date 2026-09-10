"""
SecureCloud - Unified Security Scanner & Decision Engine
Combines PE/EMBER LightGBM model inference, Static Security Analysis, and optional ClamAV.
"""

import os
import sys
from typing import Dict, Any, Optional

from ml.feature_engineering import FeatureExtractor
from ml.heuristic_scanner import HeuristicScanner
from ml.predict import ThreatPredictor
from scanner.pe_analyzer import PEAnalyzer
from scanner.clamav_scanner import ClamAVScanner

class UnifiedScannerService:
    """Master Security Decision Engine for all uploaded and on-demand file scans."""

    def __init__(self):
        self.predictor = ThreatPredictor()

    def scan(self, data: bytes, filename: str) -> Dict[str, Any]:
        """
        Executes full scanning pipeline:
        1. File Identification & MIME validation
        2. PE / EMBER feature extraction if executable binary
        3. Static heuristic security analysis
        4. LightGBM / ML classifier inference
        5. Optional ClamAV inspection
        6. Security Decision Engine synthesis
        """
        is_pe = PEAnalyzer.is_pe_binary(data)
        pe_details = PEAnalyzer.analyze_pe(data, filename) if is_pe else None

        # 1. Base ML & Heuristic Prediction
        base_prediction = self.predictor.predict_file(data, filename)

        # 2. ClamAV Engine Check
        clamav_res = ClamAVScanner.scan_bytes(data, filename)

        # 3. Decision Engine Synthesis
        threat_score = base_prediction["threat_score"]
        explanations = list(base_prediction["explanations"])
        security_status = base_prediction["security_status"]
        final_verdict = base_prediction["final_verdict"]
        is_quarantined = base_prediction["is_quarantined"]

        # If ClamAV found malware -> override with critical verdict
        if clamav_res.get("threat_found", False):
            threat_score = max(threat_score, 99.0)
            security_status = "MALICIOUS"
            final_verdict = f"MALICIOUS (ClamAV: {clamav_res.get('virus_name')})"
            is_quarantined = True
            explanations.insert(0, f"ClamAV Antivirus signature matched: {clamav_res.get('virus_name')}")

        # If PE binary has dangerous executable packed entropy or injected APIs
        if pe_details and pe_details.get("has_executable_high_entropy", False):
            threat_score = max(threat_score, 85.0)
            security_status = "MALICIOUS"
            final_verdict = "MALICIOUS PE (Obfuscated/Packed Executable)"
            is_quarantined = True
            explanations.insert(0, "High entropy executable section detected (PE packing / obfuscation signature)")

        if pe_details and pe_details.get("suspicious_apis"):
            apis = ", ".join(pe_details["suspicious_apis"][:3])
            explanations.append(f"Contains process injection / memory manipulation APIs: {apis}")

        return {
            "threat_score": threat_score,
            "final_verdict": final_verdict,
            "security_status": security_status,
            "is_quarantined": is_quarantined,
            "is_pe_binary": is_pe,
            "pe_details": pe_details,
            "clamav": clamav_res,
            "ml_prediction": base_prediction["ml_prediction"],
            "ml_probabilities": base_prediction["ml_probabilities"],
            "model_version": base_prediction["model_version"],
            "model_algorithm": base_prediction["model_algorithm"],
            "heuristic_score": base_prediction["heuristic_score"],
            "heuristic_verdict": base_prediction["heuristic_verdict"],
            "heuristic_rules": base_prediction["heuristic_rules"],
            "explanations": explanations,
            "detected_mime": base_prediction["detected_mime"]
        }
