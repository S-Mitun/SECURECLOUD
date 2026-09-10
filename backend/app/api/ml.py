"""
SecureCloud - Machine Learning & AI Threat Training API
Provides training triggers, real-time training progress, model registry, metrics, feature importance, and drift detection.
"""

import os
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, MLFeedback
from backend.app.schemas.schemas import MLTrainRequest, MLFeedbackRequest
from backend.app.security.auth_utils import get_current_admin, get_current_user
from backend.app.services.audit_service import AuditService
from ml.dataset_manager import DatasetManager
from ml.model_registry import ModelRegistry
from ml.train_model import train_threat_models
from ml.drift_detector import DriftDetector

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

# Global training state tracker for live progress sequence
TRAINING_STATE = {
    "is_training": False,
    "current_step": 0,
    "total_steps": 10,
    "current_stage": "IDLE",
    "last_result": None,
    "error": None
}

def run_background_training(dataset_name: Optional[str] = None):
    """Executes training in background and updates live training state."""
    global TRAINING_STATE
    TRAINING_STATE["is_training"] = True
    TRAINING_STATE["error"] = None
    
    stages = [
        "Dataset Discovery", "Dataset Validation", "Data Cleaning", "Preprocessing",
        "Feature Engineering", "Dataset Splitting", "Model Training", "Model Evaluation",
        "Model Selection", "Model Deployment"
    ]

    def callback(step: int, msg: str, data: Optional[Dict[str, Any]] = None):
        TRAINING_STATE["current_step"] = step
        TRAINING_STATE["current_stage"] = f"[{step}/10] {stages[step-1]}: {msg}"

    try:
        result = train_threat_models(dataset_name=dataset_name, progress_callback=callback)
        TRAINING_STATE["last_result"] = result
        TRAINING_STATE["is_training"] = False
        TRAINING_STATE["current_stage"] = "COMPLETED"
    except Exception as e:
        TRAINING_STATE["error"] = str(e)
        TRAINING_STATE["is_training"] = False
        TRAINING_STATE["current_stage"] = f"FAILED: {str(e)}"

@router.post("/train")
@router.post("/retrain")
def trigger_model_training(
    background_tasks: BackgroundTasks,
    req: Optional[MLTrainRequest] = None,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Admin endpoint: Triggers the 10-stage automated training pipeline."""
    global TRAINING_STATE
    if TRAINING_STATE["is_training"]:
        return {
            "status": "RUNNING",
            "message": "Model training is already currently in progress.",
            "state": TRAINING_STATE
        }

    dataset_name = req.dataset_name if req else None
    background_tasks.add_task(run_background_training, dataset_name)

    AuditService.log(
        db, "TRAIN_ML_MODEL", "ML Pipeline", "SUCCESS",
        f"Initiated automated training on dataset: {dataset_name or 'Auto-discovered'}",
        user_id=current_admin.id, username=current_admin.username, role="ADMIN"
    )

    return {
        "status": "STARTED",
        "message": "Automated ML training pipeline initiated.",
        "state": TRAINING_STATE
    }

@router.get("/status")
def get_ml_status():
    """Returns active model status, live training stage, and key security performance metrics."""
    global TRAINING_STATE
    registry = ModelRegistry()
    active_info = registry.get_active_model_info()
    dm = DatasetManager()
    datasets = dm.discover_datasets()

    dataset_summary = {"name": "None", "rows": 0, "features": 0}
    if datasets:
        try:
            df, fname = dm.load_raw_dataset()
            dataset_summary = {
                "name": fname,
                "rows": len(df),
                "features": len(df.columns) - 1, # minus label
                "format": datasets[0]["format"],
                "quality_score": dm.analyze_dataset(df)["quality_score"]
            }
        except Exception:
            pass

    return {
        "training_state": TRAINING_STATE,
        "dataset_status": dataset_summary,
        "active_model": {
            "version": active_info.get("version") if active_info else "No Active Model",
            "algorithm": active_info.get("algorithm") if active_info else "N/A",
            "registered_at": active_info.get("registered_at") if active_info else "N/A",
            "accuracy": active_info.get("accuracy", 0.0) if active_info else 0.0,
            "malicious_recall": active_info.get("malicious_recall", 0.0) if active_info else 0.0,
            "f1_score": active_info.get("f1_score", 0.0) if active_info else 0.0,
            "roc_auc": active_info.get("roc_auc", 0.0) if active_info else 0.0,
            "feature_count": active_info.get("feature_count", 30) if active_info else 30
        }
    }

@router.get("/models")
def list_registered_models():
    """Returns leaderboard and historical registered model artifacts."""
    registry = ModelRegistry()
    models = registry.list_all_models()
    return {
        "total_models": len(models),
        "active_model_version": registry.get_registry().get("active_model_version"),
        "models": models
    }

@router.post("/models/{version}/activate")
def activate_model_version(
    version: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Sets a previously trained model version as the active production model."""
    registry = ModelRegistry()
    success = registry.set_active_version(version)
    if not success:
        raise HTTPException(status_code=404, detail=f"Model version '{version}' not found in registry.")

    AuditService.log(
        db, "ACTIVATE_MODEL_VERSION", f"Version {version}", "SUCCESS",
        "Switched active production model pointer",
        user_id=current_admin.id, username=current_admin.username, role="ADMIN"
    )

    return {"status": "SUCCESS", "message": f"Model version '{version}' is now active."}

@router.get("/metrics")
def get_active_model_metrics():
    """Returns confusion matrix, per-class metrics, and ROC parameters for active model."""
    registry = ModelRegistry()
    active_info = registry.get_active_model_info()
    if not active_info:
        raise HTTPException(status_code=404, detail="No active model registered.")

    return {
        "version": active_info.get("version"),
        "algorithm": active_info.get("algorithm"),
        "accuracy": active_info.get("accuracy"),
        "precision": active_info.get("precision"),
        "recall": active_info.get("recall"),
        "f1_score": active_info.get("f1_score"),
        "malicious_recall": active_info.get("malicious_recall"),
        "suspicious_recall": active_info.get("suspicious_recall"),
        "clean_recall": active_info.get("clean_recall"),
        "roc_auc": active_info.get("roc_auc"),
        "confusion_matrix": active_info.get("confusion_matrix", []),
        "classes": ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    }

@router.get("/feature-importance")
def get_active_feature_importance():
    """Returns top contributing static security indicators."""
    registry = ModelRegistry()
    active_info = registry.get_active_model_info()
    if not active_info:
        return []
    return active_info.get("feature_importances", [])

@router.get("/datasets")
def list_available_datasets():
    """Returns metadata and statistics for all raw datasets."""
    dm = DatasetManager()
    datasets = dm.discover_datasets()
    enriched = []
    for d in datasets:
        try:
            df, _ = dm.load_raw_dataset(d["filename"])
            analysis = dm.analyze_dataset(df)
            d["analysis"] = analysis
        except Exception as e:
            d["analysis"] = {"error": str(e)}
        enriched.append(d)
    return enriched

@router.get("/drift")
def get_drift_metrics():
    """Returns model drift score and retraining recommendations."""
    detector = DriftDetector()
    return detector.evaluate_drift()

@router.post("/feedback")
def submit_ml_feedback(
    req: MLFeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Records user detection feedback for drift monitoring and future retraining reviews."""
    detector = DriftDetector()
    detector.log_feedback(
        file_hash=req.file_hash,
        filename=req.filename,
        predicted_verdict=req.predicted_verdict,
        is_correct=req.is_correct,
        user_comment=req.user_comment or ""
    )

    fb_entry = MLFeedback(
        file_hash=req.file_hash,
        filename=req.filename,
        predicted_verdict=req.predicted_verdict,
        is_correct=req.is_correct,
        user_comment=req.user_comment,
        user_id=current_user.id
    )
    db.add(fb_entry)
    db.commit()

    return {"status": "SUCCESS", "message": "Feedback recorded for security review."}
