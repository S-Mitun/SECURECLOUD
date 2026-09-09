"""
SecureCloud 2.0 - Centralized Security Event Telemetry Service
Normalizes and logs all operational, authentication, file lifecycle, and admin events.
Feeds directly into the Threat Intelligence Correlation Engine and User Risk Profiling Engine.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from backend.app.models.models import SecurityEvent, User

class EventService:
    @staticmethod
    def record_event(
        db: Session,
        event_type: str,
        user_id: Optional[int] = None,
        file_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        user_agent: Optional[str] = None,
        device_id: Optional[str] = None,
        file_hash: Optional[str] = None,
        domain: Optional[str] = None,
        url: Optional[str] = None,
        country: str = "India",
        result: str = "SUCCESS",
        severity: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """
        Persists an authoritative security event and triggers live correlation and risk evaluation.
        """
        event_id = str(uuid.uuid4())
        event = SecurityEvent(
            id=event_id,
            timestamp=datetime.utcnow(),
            event_type=event_type,
            user_id=user_id,
            file_id=file_id,
            session_id=session_id,
            ip_address=ip_address or "127.0.0.1",
            user_agent=user_agent[:250] if user_agent else "Browser",
            device_id=device_id,
            file_hash=file_hash,
            domain=domain,
            url=url,
            country=country or "India",
            result=result,
            severity=severity,
            metadata_json=metadata or {}
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        # Trigger User Risk Profiling Evaluation if user is identified
        if user_id:
            try:
                from backend.app.services.risk_engine_service import RiskEngineService
                RiskEngineService.evaluate_and_update_user_risk(db, user_id, latest_event=event)
            except Exception as r_err:
                print(f"[EventService] Risk engine update notice: {r_err}")

        # Trigger Threat Intelligence Correlation Check
        try:
            from backend.app.services.threat_intel_service import ThreatIntelService
            ThreatIntelService.process_incoming_event(db, event)
        except Exception as t_err:
            print(f"[EventService] Threat correlation notice: {t_err}")

        return event
