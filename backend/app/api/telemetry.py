"""
SecureCloud 2.0 - Telemetry & Prometheus Router
"""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.services.telemetry_service import TelemetryService

router = APIRouter(tags=["Telemetry & Monitoring"])

@router.get("/metrics")
def get_prometheus_metrics(db: Session = Depends(get_db)):
    """Exposes real application and VM metrics in Prometheus openmetrics format."""
    metrics_str = TelemetryService.get_prometheus_metrics(db)
    return Response(content=metrics_str, media_type="text/plain; version=0.0.4")

@router.get("/api/telemetry/live")
def get_live_telemetry(db: Session = Depends(get_db)):
    """Returns genuine real-time system and application performance metrics for frontend graphs."""
    return TelemetryService.get_live_metrics(db)

@router.get("/api/telemetry/grafana-config")
def get_grafana_dashboard_json():
    """Provides pre-configured Grafana dashboard JSON schema."""
    return {
        "title": "SecureCloud 2.0 - SOC Threat & VM Infrastructure Dashboard",
        "timezone": "browser",
        "panels": [
            {"title": "CPU Utilization (%)", "type": "gauge", "targets": [{"expr": "securecloud_cpu_utilization_percent"}]},
            {"title": "RAM Utilization (%)", "type": "gauge", "targets": [{"expr": "securecloud_memory_utilization_percent"}]},
            {"title": "Disk Storage (%)", "type": "gauge", "targets": [{"expr": "securecloud_disk_utilization_percent"}]},
            {"title": "Threat Scans Rate", "type": "timeseries", "targets": [{"expr": "rate(securecloud_threat_scans_total[5m])"}]},
            {"title": "Malicious Detections", "type": "stat", "targets": [{"expr": "securecloud_threats_malicious_total"}]},
            {"title": "Active Users", "type": "stat", "targets": [{"expr": "securecloud_active_users"}]}
        ]
    }
