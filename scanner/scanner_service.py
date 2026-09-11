"""
SecureCloud - Unified Security Scanner & Decision Engine
Combines PE/EMBER LightGBM model inference, Static Security Analysis, and optional ClamAV.
"""

import os
import sys
from typing import Dict, Any, Optional

from pathlib import Path
from ml.feature_engineering import FeatureExtractor
from ml.heuristic_scanner import HeuristicScanner
from ml.predict import ThreatPredictor
from scanner.pe_analyzer import PEAnalyzer
from scanner.clamav_scanner import ClamAVScanner

class UnifiedScannerService:
    """Master Security Decision Engine for all uploaded and on-demand file scans."""

    def __init__(self):
        self.predictor = ThreatPredictor()
        self.clamav = ClamAVScanner

    def scan(self, data_or_path, filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes full scanning pipeline:
        1. File Identification & MIME validation
        2. PE / EMBER feature extraction if executable binary
        3. Static heuristic security analysis
        4. LightGBM / ML classifier inference
        5. Optional ClamAV inspection
        6. Security Decision Engine synthesis
        """
        if isinstance(data_or_path, (str, Path)):
            p = Path(data_or_path)
            data = p.read_bytes()
            if filename is None:
                filename = p.name
        else:
            data = data_or_path
            filename = filename or "uploaded_file.bin"
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

        # 4. Formatted Risk Classification
        if clamav_res.get("threat_found", False) or threat_score >= 95.0:
            final_risk = "CRITICAL"
        elif threat_score >= 75.0:
            final_risk = "HIGH"
        elif threat_score >= 50.0:
            final_risk = "MEDIUM"
        elif threat_score >= 20.0:
            final_risk = "LOW"
        else:
            final_risk = "CLEAN"

        # 5. Compile Verified Reasons (Derived strictly from actual detected features)
        formatted_reasons = []
        if clamav_res.get("threat_found"):
            formatted_reasons.append(f"✓ ClamAV Antivirus signature detected: {clamav_res.get('virus_name')}")
        if pe_details and pe_details.get("has_executable_high_entropy"):
            formatted_reasons.append("✓ High entropy executable section (PE packing / obfuscation)")
        if pe_details and pe_details.get("suspicious_apis"):
            formatted_reasons.append(f"✓ Suspicious PE process manipulation APIs: {', '.join(pe_details['suspicious_apis'][:3])}")
        
        for rule in base_prediction.get("heuristic_rules", []):
            rule_text = rule.get("description", str(rule)) if isinstance(rule, dict) else str(rule)
            if "Clean" not in rule_text and "clean" not in rule_text.lower():
                formatted_reasons.append(f"✓ {rule_text}")

        for exp in explanations:
            clean_exp = exp.lstrip("✓").strip()
            if not any(clean_exp in r for r in formatted_reasons):
                if "clean" not in clean_exp.lower() and "below 20%" not in clean_exp:
                    formatted_reasons.append(f"✓ {clean_exp}")

        if not formatted_reasons:
            formatted_reasons.append("✓ Standard file structure; threat probability below baseline (Verified Safe)")

        # 6. Structured Detection Layers
        detection_layers = {
            "clamav": {
                "status": clamav_res.get("status", "UNAVAILABLE"),
                "label": "ClamAV Signature Scanner",
                "message": clamav_res.get("message", "Scanner offline"),
                "threat_found": clamav_res.get("threat_found", False),
                "virus_name": clamav_res.get("virus_name")
            },
            "heuristic": {
                "label": "Static Heuristic Analysis",
                "score": base_prediction["heuristic_score"],
                "verdict": base_prediction["heuristic_verdict"],
                "rules": base_prediction["heuristic_rules"]
            },
            "ml": {
                "label": "Lightweight Machine Learning Classifier",
                "algorithm": base_prediction["model_algorithm"],
                "model_version": base_prediction["model_version"],
                "prediction": base_prediction["ml_prediction"],
                "malicious_probability": base_prediction["ml_probabilities"].get("MALICIOUS", 0.0),
                "probabilities": base_prediction["ml_probabilities"]
            },
            "final_risk": final_risk
        }

        return {
            "threat_score": threat_score,
            "final_verdict": final_verdict,
            "security_status": security_status,
            "final_risk": final_risk,
            "is_quarantined": is_quarantined,
            "is_pe_binary": is_pe,
            "pe_details": pe_details,
            "clamav": clamav_res,
            "detection_layers": detection_layers,
            "reasons": formatted_reasons,
            "explanations": explanations,
            "ml_prediction": base_prediction["ml_prediction"],
            "ml_probabilities": base_prediction["ml_probabilities"],
            "model_version": base_prediction["model_version"],
            "model_algorithm": base_prediction["model_algorithm"],
            "heuristic_score": base_prediction["heuristic_score"],
            "heuristic_verdict": base_prediction["heuristic_verdict"],
            "heuristic_rules": base_prediction["heuristic_rules"],
            "detected_mime": base_prediction["detected_mime"]
        }

# Global Unified Scanner Singleton
unified_scanner = UnifiedScannerService()
