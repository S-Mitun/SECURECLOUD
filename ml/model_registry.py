"""
SecureCloud 2.0 - ML Model Registry & Version Management
Maintains model versions, performance metrics, and active production model reference.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional

class ModelRegistry:
    """Manages versioned model artifacts and registry metadata."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.base_dir = base_dir

        self.models_dir = os.path.join(self.base_dir, "models")
        self.registry_file = os.path.join(self.models_dir, "model_registry.json")
        os.makedirs(self.models_dir, exist_ok=True)
        self._ensure_registry_exists()

    def _ensure_registry_exists(self):
        """Initializes empty registry file if not present."""
        if not os.path.exists(self.registry_file):
            initial_data = {
                "active_model_version": None,
                "models": {},
                "last_updated": datetime.now().isoformat()
            }
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(initial_data, f, indent=2)

    def get_registry(self) -> Dict[str, Any]:
        """Reads current registry data."""
        self._ensure_registry_exists()
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"active_model_version": None, "models": {}, "last_updated": datetime.now().isoformat()}

    def _save_registry(self, data: Dict[str, Any]):
        """Saves registry data atomically."""
        data["last_updated"] = datetime.now().isoformat()
        with open(self.registry_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def get_next_version_string(self) -> str:
        """Generates next model version tag (e.g., securecloud-threat-model-v1)."""
        reg = self.get_registry()
        existing_versions = list(reg.get("models", {}).keys())
        highest_v = 0
        for v in existing_versions:
            if "v" in v:
                try:
                    num = int(v.split("-v")[-1])
                    highest_v = max(highest_v, num)
                except ValueError:
                    pass
        return f"securecloud-threat-model-v{highest_v + 1}"

    def register_model(
        self,
        version: str,
        algorithm: str,
        model_path: str,
        metrics: Dict[str, Any],
        dataset_info: Dict[str, Any],
        feature_count: int,
        feature_importances: Optional[List[Dict[str, Any]]] = None,
        is_active: bool = True
    ) -> Dict[str, Any]:
        """Registers a newly trained model in the registry."""
        reg = self.get_registry()
        
        record = {
            "version": version,
            "algorithm": algorithm,
            "model_path": model_path,
            "model_filename": os.path.basename(model_path),
            "registered_at": datetime.now().strftime("%d %b %Y %H:%M:%S"),
            "dataset_name": dataset_info.get("name", "security_dataset.csv"),
            "dataset_hash": dataset_info.get("hash", "N/A"),
            "dataset_rows": dataset_info.get("rows", 0),
            "feature_count": feature_count,
            "accuracy": metrics.get("accuracy", 0.0),
            "precision": metrics.get("precision", 0.0),
            "recall": metrics.get("recall", 0.0),
            "f1_score": metrics.get("f1_score", 0.0),
            "malicious_recall": metrics.get("malicious_recall", 0.0),
            "suspicious_recall": metrics.get("suspicious_recall", 0.0),
            "clean_recall": metrics.get("clean_recall", 0.0),
            "roc_auc": metrics.get("roc_auc", 0.0),
            "confusion_matrix": metrics.get("confusion_matrix", []),
            "feature_importances": feature_importances or [],
            "status": "ACTIVE" if is_active else "ARCHIVED"
        }

        # Update all other models to ARCHIVED if this is active
        if is_active:
            for m_ver in reg.get("models", {}):
                reg["models"][m_ver]["status"] = "ARCHIVED"
            reg["active_model_version"] = version

        reg["models"][version] = record
        self._save_registry(reg)
        return record

    def get_active_model_info(self) -> Optional[Dict[str, Any]]:
        """Returns details for the currently active production model."""
        reg = self.get_registry()
        active_ver = reg.get("active_model_version")
        if not active_ver or active_ver not in reg.get("models", {}):
            return None
        return reg["models"][active_ver]

    def get_active_model_path(self) -> Optional[str]:
        """Returns local absolute path to the active model pipeline."""
        info = self.get_active_model_info()
        if not info:
            # Fallback to active_model.joblib if exists
            fallback = os.path.join(self.models_dir, "active_model.joblib")
            if os.path.exists(fallback):
                return fallback
            return None
        return info.get("model_path")

    def set_active_version(self, version: str) -> bool:
        """Sets a specified version as the active model."""
        reg = self.get_registry()
        if version not in reg.get("models", {}):
            return False
        for m_ver in reg.get("models", {}):
            reg["models"][m_ver]["status"] = "ACTIVE" if m_ver == version else "ARCHIVED"
        reg["active_model_version"] = version
        self._save_registry(reg)
        return True

    def list_all_models(self) -> List[Dict[str, Any]]:
        """Returns list of all models sorted by registered_at desc."""
        reg = self.get_registry()
        models = list(reg.get("models", {}).values())
        return sorted(models, key=lambda x: x.get("registered_at", ""), reverse=True)
