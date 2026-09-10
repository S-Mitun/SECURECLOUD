"""
SecureCloud - Security, ML, and Audit Reports API
Exports comprehensive threat analytics and SOC audit documents in PDF, CSV, and JSON.
"""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
import io
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, SecurityScan, AuditLog, FileRecord
from backend.app.security.auth_utils import get_current_user
from backend.app.services.report_service import ReportService
from ml.model_registry import ModelRegistry

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/threat-report")
def export_threat_report(
    format: str = Query("json", pattern="^(pdf|csv|json)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generates and downloads Threat Intelligence & Scan Report in requested format."""
    report_data = ReportService.generate_threat_report_data(db)

    if format == "json":
        return report_data

    if format == "csv":
        csv_str = ReportService.export_csv(report_data)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="securecloud_threat_report.csv"'}
        )

    if format == "pdf":
        pdf_bytes = ReportService.export_pdf(report_data)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="securecloud_threat_report.pdf"'}
        )

@router.get("/ml-training-report")
def export_ml_training_report(
    current_user: User = Depends(get_current_user)
):
    """Returns active ML model training report and leaderboard metadata."""
    registry = ModelRegistry()
    active_info = registry.get_active_model_info()
    if not active_info:
        raise HTTPException(status_code=404, detail="No active model report available.")

    return {
        "title": "SecureCloud - ML Threat Classification Training Report",
        "active_model_version": active_info.get("version"),
        "algorithm": active_info.get("algorithm"),
        "training_dataset": active_info.get("dataset_name"),
        "dataset_rows": active_info.get("dataset_rows"),
        "feature_count": active_info.get("feature_count"),
        "accuracy": f"{active_info.get('accuracy', 0)}%",
        "precision": f"{active_info.get('precision', 0)}%",
        "recall": f"{active_info.get('recall', 0)}%",
        "f1_score": f"{active_info.get('f1_score', 0)}%",
        "malicious_recall": f"{active_info.get('malicious_recall', 0)}%",
        "roc_auc": f"{active_info.get('roc_auc', 0)}%",
        "confusion_matrix": active_info.get("confusion_matrix", []),
        "feature_importance": active_info.get("feature_importances", [])
    }
