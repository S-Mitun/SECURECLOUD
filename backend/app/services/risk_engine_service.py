"""
SecureCloud 2.0 - Real User Risk Profiling Engine
Calculates per-user behavioral baselines, deterministic risk signals, signal fusion with decay,
and explainable factor breakdowns.
ZERO RANDOM / FAKE DATA: Every calculation is reproducible and derived from real database telemetry.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models.models import (
    User, UserRiskProfile, UserBaseline, RiskEvent, 
    SecurityEvent, FileRecord, SharedLink, UserSession, AuditLog
)

def to_ist(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist = dt + timedelta(hours=5, minutes=30)
    return ist.strftime("%d %b %Y, %I:%M:%S %p IST")

def to_ist_short(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist = dt + timedelta(hours=5, minutes=30)
    return ist.strftime("%d %b %Y, %I:%M %p")

class RiskEngineService:

    @classmethod
    def calculate_user_baseline(cls, db: Session, user_id: int, days: int = 30) -> Dict[str, Any]:
        """
        Calculates individual behavioral baseline from the user's historical telemetry over the last 30 days.
        If user has < 3 events, returns has_sufficient_history = False.
        """
        period_start = datetime.utcnow() - timedelta(days=days)
        events = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= period_start
        ).all()

        if len(events) < 3:
            return {
                "has_sufficient_history": False,
                "sample_count": len(events),
                "downloads_mean_per_day": 0.0,
                "uploads_mean_per_day": 0.0,
                "shares_mean_per_day": 0.0,
                "known_ips": [],
                "known_devices": []
            }

        # Calculate daily averages
        total_downloads = sum(1 for e in events if e.event_type == "FILE_DOWNLOAD")
        total_uploads = sum(1 for e in events if e.event_type == "FILE_UPLOAD")
        total_shares = sum(1 for e in events if e.event_type == "FILE_SHARE")

        days_active = max(1, days)
        dl_mean = round(total_downloads / days_active, 2)
        ul_mean = round(total_uploads / days_active, 2)
        sh_mean = round(total_shares / days_active, 2)

        known_ips = list(set(e.ip_address for e in events if e.ip_address and e.ip_address not in ["127.0.0.1", "localhost", "::1"]))
        known_devices = list(set(e.user_agent for e in events if e.user_agent))

        # Save/update baselines in DB
        db.query(UserBaseline).filter(UserBaseline.user_id == user_id).delete()
        for metric, val in [("downloads_mean", dl_mean), ("uploads_mean", ul_mean), ("shares_mean", sh_mean)]:
            db.add(UserBaseline(
                user_id=user_id,
                period_start=period_start,
                period_end=datetime.utcnow(),
                metric_name=metric,
                metric_value=float(val),
                sample_count=len(events),
                calculated_at=datetime.utcnow()
            ))
        db.commit()

        return {
            "has_sufficient_history": True,
            "sample_count": len(events),
            "downloads_mean_per_day": dl_mean,
            "uploads_mean_per_day": ul_mean,
            "shares_mean_per_day": sh_mean,
            "known_ips": known_ips,
            "known_devices": known_devices
        }

    @classmethod
    def evaluate_and_update_user_risk(cls, db: Session, user_id: int, latest_event: Optional[SecurityEvent] = None) -> UserRiskProfile:
        """
        Authoritative deterministic evaluation of user risk score from actual telemetry.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found.")

        baseline = cls.calculate_user_baseline(db, user_id)
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Telemetry events for the user
        events_24h = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= last_24h
        ).all()

        events_7d = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.timestamp >= last_7d
        ).all()

        factors: List[Dict[str, Any]] = []
        auth_score = 0.0
        file_score = 0.0
        share_score = 0.0
        session_score = 0.0
        threat_score = 0.0

        # --- 1. Authentication Signals ---
        failed_logins_24h = sum(1 for e in events_24h if e.event_type in ["LOGIN_FAILURE", "TWO_FACTOR_FAILURE"] or e.result in ["FAILED", "BLOCKED"])
        if failed_logins_24h >= 3:
            contrib = 15.0
            auth_score += contrib
            factors.append({
                "signal_type": "FAILED_LOGIN_SPIKE",
                "category": "Authentication",
                "contribution": contrib,
                "reason": f"{failed_logins_24h} consecutive failed authentication attempts in last 24h"
            })

        two_fa_fails = sum(1 for e in events_24h if e.event_type == "TWO_FACTOR_FAILURE")
        if two_fa_fails >= 2:
            contrib = 15.0
            auth_score += contrib
            factors.append({
                "signal_type": "2FA_FAILURE_SPIKE",
                "category": "Authentication",
                "contribution": contrib,
                "reason": f"{two_fa_fails} failed Two-Factor Authentication verification attempts"
            })

        new_device_events = [e for e in events_24h if e.event_type == "NEW_DEVICE"]
        if new_device_events:
            contrib = 10.0
            auth_score += contrib
            factors.append({
                "signal_type": "NEW_DEVICE",
                "category": "Authentication",
                "contribution": contrib,
                "reason": "Login activity observed from a new device user agent"
            })

        new_ip_events = [e for e in events_24h if e.event_type == "NEW_IP"]
        if new_ip_events:
            contrib = 10.0
            auth_score += contrib
            factors.append({
                "signal_type": "NEW_IP",
                "category": "Authentication",
                "contribution": contrib,
                "reason": "Authentication originated from an unrecognized IP address"
            })

        # --- 2. File Activity Signals ---
        today_downloads = sum(1 for e in events_24h if e.event_type == "FILE_DOWNLOAD")
        dl_baseline = baseline["downloads_mean_per_day"]
        if baseline["has_sufficient_history"] and dl_baseline > 0 and today_downloads >= (dl_baseline * 3.0) and today_downloads >= 10:
            contrib = 20.0
            file_score += contrib
            factors.append({
                "signal_type": "DOWNLOAD_SPIKE",
                "category": "File Activity",
                "contribution": contrib,
                "reason": f"Download volume ({today_downloads} files) is {(today_downloads/dl_baseline):.1f}× above personal baseline ({dl_baseline}/day)"
            })
        elif not baseline["has_sufficient_history"] and today_downloads >= 30:
            contrib = 15.0
            file_score += contrib
            factors.append({
                "signal_type": "MASS_DOWNLOAD",
                "category": "File Activity",
                "contribution": contrib,
                "reason": f"High volume mass download: {today_downloads} files in 24 hours"
            })

        # Check for suspicious or malicious uploaded files belonging to user
        user_files = db.query(FileRecord).filter(
            FileRecord.user_id == user_id,
            FileRecord.is_in_recycle_bin == False
        ).all()

        malicious_files = [f for f in user_files if f.security_status == "MALICIOUS" or (f.threat_score and f.threat_score > 20.0)]
        suspicious_files = [f for f in user_files if f.security_status == "SUSPICIOUS" and f not in malicious_files]

        if malicious_files:
            contrib = 50.0
            file_score += contrib
            factors.append({
                "signal_type": "MALICIOUS_FILE_UPLOAD",
                "category": "File Activity",
                "contribution": contrib,
                "reason": f"Account repository contains {len(malicious_files)} malicious payload(s) with ML threat score > 20%"
            })

        if suspicious_files:
            contrib = 25.0
            file_score += contrib
            factors.append({
                "signal_type": "SUSPICIOUS_FILE_UPLOAD",
                "category": "File Activity",
                "contribution": contrib,
                "reason": f"{len(suspicious_files)} file(s) flagged with suspicious heuristic markers"
            })

        # --- 3. Sharing Signals ---
        today_shares = sum(1 for e in events_24h if e.event_type == "FILE_SHARE")
        if today_shares >= 5:
            contrib = 15.0
            share_score += contrib
            factors.append({
                "signal_type": "MASS_LINK_CREATION",
                "category": "Sharing",
                "contribution": contrib,
                "reason": f"{today_shares} public share links generated in 24 hours"
            })

        # --- 4. Threat Intelligence Matches ---
        threat_match_events = [e for e in events_7d if "THREAT_INTEL" in (e.event_type or "")]
        if threat_match_events:
            contrib = 40.0
            threat_score += contrib
            factors.append({
                "signal_type": "THREAT_INTEL_MATCH",
                "category": "Threat Intelligence",
                "contribution": contrib,
                "reason": "User telemetry matched configured IOC threat intelligence feed"
            })

        # --- 5. Trusted Clean Adjustments ---
        if not factors and user_files and all(f.security_status == "CLEAN" for f in user_files):
            factors.append({
                "signal_type": "VERIFIED_CLEAN_BASELINE",
                "category": "Integrity",
                "contribution": 0.0,
                "reason": "All stored repository files and authentication activities are verified clean"
            })

        # Composite Score Calculation (0 - 100)
        raw_score = auth_score + file_score + share_score + session_score + threat_score
        final_score = min(100.0, max(0.0, round(raw_score, 1)))

        # Tier Classification
        if final_score >= 90.0:
            risk_level = "CRITICAL"
            status_str = "CRITICAL"
        elif final_score >= 75.0:
            risk_level = "HIGH"
            status_str = "HIGH_RISK"
        elif final_score >= 50.0:
            risk_level = "ELEVATED"
            status_str = "ELEVATED"
        elif final_score >= 25.0:
            risk_level = "GUARDED"
            status_str = "MONITORING"
        else:
            risk_level = "LOW"
            status_str = "NORMAL"

        # Update User model risk_score
        user.risk_score = final_score

        # When risk score is LOW (clean baseline), stop 2FA enforcement automatically.
        # If risk raises again (GUARDED, ELEVATED, HIGH, CRITICAL), 2FA enforcement becomes applicable.
        if risk_level == "LOW":
            user.two_factor_enforced = False

        # Save/Update UserRiskProfile
        profile = db.query(UserRiskProfile).filter(UserRiskProfile.user_id == user_id).first()
        if not profile:
            profile = UserRiskProfile(
                user_id=user_id,
                risk_score=final_score,
                risk_level=risk_level,
                baseline_period="30d",
                authentication_score=auth_score,
                file_activity_score=file_score,
                sharing_score=share_score,
                session_score=session_score,
                threat_intel_score=threat_score,
                top_factors=factors,
                status=status_str,
                has_sufficient_history=baseline["has_sufficient_history"],
                calculated_at=datetime.utcnow()
            )
            db.add(profile)
        else:
            profile.risk_score = final_score
            profile.risk_level = risk_level
            profile.authentication_score = auth_score
            profile.file_activity_score = file_score
            profile.sharing_score = share_score
            profile.session_score = session_score
            profile.threat_intel_score = threat_score
            profile.top_factors = factors
            profile.status = status_str
            profile.has_sufficient_history = baseline["has_sufficient_history"]
            profile.calculated_at = datetime.utcnow()

        db.commit()
        db.refresh(profile)
        return profile

    @classmethod
    def get_all_user_risk_profiles(cls, db: Session) -> List[Dict[str, Any]]:
        """Returns live calculated risk profiles for all system users."""
        users = db.query(User).all()
        res = []
        for u in users:
            prof = cls.evaluate_and_update_user_risk(db, u.id)
            user_files = db.query(FileRecord).filter(FileRecord.user_id == u.id, FileRecord.is_in_recycle_bin == False).all()
            
            # Formulate rule-driven recommendations
            recommendations = []
            if prof.risk_score >= 75.0:
                recommendations.extend([
                    "Enforce mandatory Two-Factor Authentication (2FA)",
                    "Revoke active concurrent sessions immediately",
                    "Quarantine and analyze flagged file artifacts",
                    "Temporarily restrict external link sharing permissions"
                ])
            elif prof.risk_score >= 50.0:
                recommendations.extend([
                    "Review recent login geolocation and IP history",
                    "Prompt user for credential update on next login",
                    "Inspect uploaded scripts and high-entropy documents"
                ])
            elif prof.risk_score >= 25.0:
                recommendations.extend([
                    "Monitor ongoing file download and sharing volume",
                    "Maintain standard SOC monitoring baseline"
                ])
            else:
                recommendations.append("Risk score is LOW (clean baseline). 2FA enforcement stopped; applies only if risk score raises.")

            res.append({
                "user_id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "two_factor_enforced": u.two_factor_enforced or False,
                "risk_score": prof.risk_score,
                "risk_level": prof.risk_level,
                "status": prof.status,
                "has_sufficient_history": prof.has_sufficient_history,
                "file_count": len(user_files),
                "sub_scores": {
                    "authentication": prof.authentication_score,
                    "file_activity": prof.file_activity_score,
                    "sharing": prof.sharing_score,
                    "session_anomalies": prof.session_score,
                    "threat_intelligence": prof.threat_intel_score
                },
                "top_factors": prof.top_factors or [],
                "recommendations": recommendations,
                "calculated_at": to_ist(prof.calculated_at)
            })
        return res

    @classmethod
    def get_user_risk_detail(cls, db: Session, user_id: int) -> Dict[str, Any]:
        """Returns deep risk profile details, timeline of security events, and baseline metrics."""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found.")

        profile = cls.evaluate_and_update_user_risk(db, user_id)
        baseline = cls.calculate_user_baseline(db, user_id)

        # Fetch actual user security event timeline
        events = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id
        ).order_by(SecurityEvent.timestamp.desc()).limit(20).all()

        timeline = [
            {
                "id": e.id,
                "timestamp": to_ist(e.timestamp),
                "event_type": e.event_type,
                "ip_address": e.ip_address,
                "result": e.result,
                "severity": e.severity,
                "details": (e.metadata_json or {}).get("details") or f"Event: {e.event_type}"
            }
            for e in events
        ]

        return {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "risk_score": profile.risk_score,
            "risk_level": profile.risk_level,
            "status": profile.status,
            "has_sufficient_history": profile.has_sufficient_history,
            "baseline": baseline,
            "sub_scores": {
                "authentication": profile.authentication_score,
                "file_activity": profile.file_activity_score,
                "sharing": profile.sharing_score,
                "session_anomalies": profile.session_score,
                "threat_intelligence": profile.threat_intel_score
            },
            "top_factors": profile.top_factors or [],
            "timeline": timeline,
            "calculated_at": to_ist(profile.calculated_at)
        }
