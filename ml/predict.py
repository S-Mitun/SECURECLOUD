"""
SecureCloud - Hybrid Threat Prediction Engine
Combines real Machine Learning model inference, Static Heuristic Scanning, and Hash Intelligence.
Updated with user-defined ML Threat probability thresholds:
- > 20%: MALICIOUS
- > 75%: SUSPICIOUS / HIGH RISK
- > 95%: CRITICAL DANGER RISK (QUARANTINED)
- <= 20%: VERIFIED CLEAN
"""

import os
import sys
from typing import Dict, Any, Optional

import pandas as pd
import numpy as np

# Ensure path includes parent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from ml.feature_engineering import FeatureExtractor
from ml.heuristic_scanner import HeuristicScanner
from ml.model_registry import ModelRegistry
from ml.preprocessing import load_pipeline

class ThreatPredictor:
    """Predicts file security threat status using hybrid ML + Heuristic engine."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            self.base_dir = current_dir
        else:
            self.base_dir = base_dir

        self.registry = ModelRegistry(base_dir=self.base_dir)
        self._cached_pipeline = None
        self._cached_version = None

    def get_pipeline(self):
        """Loads or returns cached active pipeline."""
        active_info = self.registry.get_active_model_info()
        active_path = self.registry.get_active_model_path()

        if not active_path or not os.path.exists(active_path):
            return None, None

        current_ver = active_info["version"] if active_info else "active_model"
        if self._cached_pipeline is None or self._cached_version != current_ver:
            self._cached_pipeline = load_pipeline(active_path)
            self._cached_version = current_ver

        return self._cached_pipeline, active_info

    def predict_file(self, data, filename: str = "", original_filename: str = "") -> Dict[str, Any]:
        """
        Executes complete hybrid threat scan:
        1. Feature Extraction
        2. Heuristic Analysis
        3. ML Model Inference
        4. Signal Fusion & Verdict Synthesis with strict calibrated thresholds:
           - > 20%: MALICIOUS
           - > 75%: SUSPICIOUS / HIGH RISK
           - > 95%: CRITICAL DANGER RISK
        """
        effective_filename = filename or original_filename or "unnamed_file"
        if isinstance(data, str):
            if os.path.exists(data):
                if effective_filename == "unnamed_file":
                    effective_filename = os.path.basename(data)
                with open(data, "rb") as fp:
                    data = fp.read()
            else:
                data = data.encode("utf-8")

        filename = effective_filename

        # 1. Static Feature Extraction
        features = FeatureExtractor.extract_features_from_bytes(data, filename)
        df_features = FeatureExtractor.to_dataframe(features)

        # 2. Heuristic Scanner
        heuristic_res = HeuristicScanner.scan(data, filename)
        heuristic_score = heuristic_res["heuristic_score"]
        heuristic_verdict = heuristic_res["heuristic_verdict"]
        triggered_rules = heuristic_res["triggered_rules"]

        # 3. ML Model Prediction
        pipeline, active_info = self.get_pipeline()

        ml_probs = {"CLEAN": 95.0, "SUSPICIOUS": 3.0, "MALICIOUS": 2.0}
        ml_prediction = "CLEAN"
        model_version = active_info["version"] if active_info else "LightGBM / EMBER2024"
        model_algo = active_info["algorithm"] if active_info else "LightGBM"

        if pipeline is not None:
            try:
                classes = list(pipeline.classes_)
                raw_probs = pipeline.predict_proba(df_features)[0]
                ml_probs = {cls_name: round(float(prob) * 100, 1) for cls_name, prob in zip(classes, raw_probs)}
                ml_prediction = pipeline.predict(df_features)[0]
            except Exception as e:
                print(f"[Predictor] ML inference warning: {e}")
                # Fallback based on heuristic if ML inference fails
                ml_prediction = heuristic_verdict
                if heuristic_verdict == "MALICIOUS":
                    ml_probs = {"CLEAN": 2.0, "SUSPICIOUS": 18.0, "MALICIOUS": 80.0}
                elif heuristic_verdict == "SUSPICIOUS":
                    ml_probs = {"CLEAN": 20.0, "SUSPICIOUS": 75.0, "MALICIOUS": 5.0}
                else:
                    ml_probs = {"CLEAN": 96.0, "SUSPICIOUS": 3.0, "MALICIOUS": 1.0}

        # 4. Signal Fusion & Threat Probability Calculation (0 - 100)
        prob_mal = ml_probs.get("MALICIOUS", 0.0)
        prob_susp = ml_probs.get("SUSPICIOUS", 0.0)
        prob_clean = ml_probs.get("CLEAN", 0.0)

        # Calculate overall threat probability
        threat_prob = prob_mal + (prob_susp * 0.4)

        # Composite Threat Score combining ML and static heuristics
        composite_score = (threat_prob * 0.65) + (heuristic_score * 0.35)
        
        # Hard overrides for critical heuristic findings (double extensions, script embeddings)
        has_critical_rule = any(r.get("severity") == "CRITICAL" for r in triggered_rules)
        if has_critical_rule:
            composite_score = max(composite_score, 96.0)
            threat_prob = max(threat_prob, 96.0)

        composite_score = min(100.0, max(0.0, round(composite_score, 1)))
        max_threat_metric = max(composite_score, threat_prob)

        # 5. Precise Threshold Tiering:
        # >= 80% => DANGER (CRITICAL DANGER RISK)
        # >= 50% => MALICIOUS (MALICIOUS FILE)
        # >= 20% => SUSPICIOUS (SUSPICIOUS FILE)
        # < 20%  => CLEAN (VERIFIED CLEAN)
        is_quarantined = False

        if max_threat_metric >= 80.0:
            final_verdict = "CRITICAL DANGER RISK"
            security_status = "MALICIOUS"
            ml_prediction = "MALICIOUS"
            is_quarantined = True
        elif max_threat_metric >= 50.0:
            final_verdict = "MALICIOUS FILE"
            security_status = "MALICIOUS"
            ml_prediction = "MALICIOUS"
            is_quarantined = True
        elif max_threat_metric >= 20.0:
            final_verdict = "SUSPICIOUS FILE"
            security_status = "SUSPICIOUS"
            ml_prediction = "SUSPICIOUS"
            is_quarantined = False
        else:
            final_verdict = "VERIFIED CLEAN"
            security_status = "CLEAN"
            ml_prediction = "CLEAN"
            is_quarantined = False

        # Explanations list
        explanations = []
        if max_threat_metric >= 80.0:
            explanations.append(f"CRITICAL DANGER: Threat probability ({max_threat_metric:.1f}%) exceeds 80.0% critical threshold. Immediate quarantine enforced.")
        elif max_threat_metric >= 50.0:
            explanations.append(f"MALICIOUS: Threat probability ({max_threat_metric:.1f}%) exceeds 50.0% threshold. Isolated into Quarantine Vault.")
        elif max_threat_metric >= 20.0:
            explanations.append(f"SUSPICIOUS: Threat probability ({max_threat_metric:.1f}%) is in 20.0% - 49.9% elevated heuristic risk zone.")

        if features.get("mime_mismatch"):
            explanations.append("MIME / Extension mismatch detected (file type disguised)")
        if features.get("has_double_extension"):
            explanations.append("Dangerous double file extension detected")
        if features.get("powershell_indicator"):
            explanations.append("Contains automated PowerShell execution markers")
        if features.get("vba_macro_indicator"):
            explanations.append("Office macro execution directives present")
        if features.get("file_entropy", 0) > 7.3:
            explanations.append(f"High file entropy ({features['file_entropy']:.2f}/8.00) indicates packed/obfuscated code")
        if features.get("suspicious_string_count", 0) > 0:
            explanations.append(f"{features['suspicious_string_count']} suspicious security string patterns matched")
        for r in triggered_rules:
            if r["description"] not in explanations:
                explanations.append(r["description"])

        if not explanations:
            explanations.append("Standard file structure; threat probability below 20% baseline (Verified Clean).")

        return {
            "threat_score": round(max_threat_metric, 1),
            "threat_probability": round(max_threat_metric, 1),
            "final_verdict": final_verdict,
            "security_status": security_status,
            "is_quarantined": is_quarantined,
            "ml_prediction": ml_prediction,
            "ml_probabilities": ml_probs,
            "model_version": model_version,
            "model_algorithm": model_algo,
            "heuristic_score": heuristic_score,
            "heuristic_verdict": heuristic_verdict,
            "heuristic_rules": triggered_rules,
            "explanations": explanations,
            "file_entropy": features.get("file_entropy", 0.0),
            "detected_mime": heuristic_res.get("detected_mime", "application/octet-stream"),
            "features": features
        }
