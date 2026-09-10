"""
SecureCloud - Model Drift & Monitoring Engine
Tracks incoming feature distribution changes vs training baseline and triggers retraining alerts.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import numpy as np

class DriftDetector:
    """Monitors live inference feature distributions for data drift."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.base_dir = base_dir

        self.logs_dir = os.path.join(self.base_dir, "logs")
        self.stats_file = os.path.join(self.logs_dir, "inference_stats.json")
        self.feedback_file = os.path.join(self.logs_dir, "user_feedback.json")
        os.makedirs(self.logs_dir, exist_ok=True)
        self._ensure_files()

    def _ensure_files(self):
        if not os.path.exists(self.stats_file):
            with open(self.stats_file, "w", encoding="utf-8") as f:
                json.dump({
                    "total_scans": 0,
                    "clean_scans": 0,
                    "suspicious_scans": 0,
                    "malicious_scans": 0,
                    "entropy_history": [],
                    "size_history": [],
                    "recent_scans": []
                }, f, indent=2)

        if not os.path.exists(self.feedback_file):
            with open(self.feedback_file, "w", encoding="utf-8") as f:
                json.dump({"feedback_items": []}, f, indent=2)

    def log_inference(self, features: Dict[str, Any], verdict: str, threat_score: float):
        """Records an inference event for drift analysis."""
        try:
            with open(self.stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
        except Exception:
            stats = {"total_scans": 0, "clean_scans": 0, "suspicious_scans": 0, "malicious_scans": 0, "entropy_history": [], "size_history": [], "recent_scans": []}

        stats["total_scans"] += 1
        if "CLEAN" in verdict:
            stats["clean_scans"] += 1
        elif "SUSPICIOUS" in verdict:
            stats["suspicious_scans"] += 1
        elif "MALICIOUS" in verdict:
            stats["malicious_scans"] += 1

        stats["entropy_history"].append(features.get("file_entropy", 4.0))
        stats["size_history"].append(features.get("file_size", 1024))
        
        # Keep last 500 scans
        stats["entropy_history"] = stats["entropy_history"][-500:]
        stats["size_history"] = stats["size_history"][-500:]

        with open(self.stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

    def log_feedback(self, file_hash: str, filename: str, predicted_verdict: str, is_correct: bool, user_comment: str = ""):
        """Stores user feedback for admin review."""
        try:
            with open(self.feedback_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"feedback_items": []}

        data["feedback_items"].append({
            "timestamp": datetime.now().isoformat(),
            "file_hash": file_hash,
            "filename": filename,
            "predicted_verdict": predicted_verdict,
            "is_correct": is_correct,
            "user_comment": user_comment
        })

        with open(self.feedback_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def evaluate_drift(self) -> Dict[str, Any]:
        """Calculates current drift score and retraining recommendation."""
        try:
            with open(self.stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
            with open(self.feedback_file, "r", encoding="utf-8") as f:
                fb = json.load(f)
        except Exception:
            return {
                "drift_score": 0.0,
                "status": "NORMAL",
                "retraining_recommended": False,
                "reason": "Insufficient live scan telemetry"
            }

        total_scans = stats.get("total_scans", 0)
        feedback_list = fb.get("feedback_items", [])
        incorrect_feedback = sum(1 for x in feedback_list if not x.get("is_correct", True))

        # Baseline expected entropy mean ~ 5.2, variance check
        entropies = stats.get("entropy_history", [])
        drift_score = 0.0

        if len(entropies) >= 10:
            mean_entropy = float(np.mean(entropies))
            std_entropy = float(np.std(entropies))
            # Shift indicator
            if mean_entropy > 6.5 or mean_entropy < 3.5:
                drift_score += 35.0
            if std_entropy > 2.0:
                drift_score += 20.0

        if incorrect_feedback > 3:
            drift_score += min(45.0, incorrect_feedback * 10.0)

        drift_score = min(100.0, round(drift_score, 1))
        retrain_rec = drift_score >= 40.0 or incorrect_feedback >= 5

        status = "CRITICAL_DRIFT" if drift_score >= 70.0 else ("MODERATE_DRIFT" if drift_score >= 40.0 else "NORMAL")

        return {
            "total_scans": total_scans,
            "clean_scans": stats.get("clean_scans", 0),
            "suspicious_scans": stats.get("suspicious_scans", 0),
            "malicious_scans": stats.get("malicious_scans", 0),
            "feedback_count": len(feedback_list),
            "incorrect_feedback_count": incorrect_feedback,
            "drift_score": drift_score,
            "status": status,
            "retraining_recommended": retrain_rec,
            "recommendation_text": "MODEL RETRAINING RECOMMENDED: Significant feature drift or feedback mismatch detected." if retrain_rec else "Model performance stable within baseline parameters."
        }
