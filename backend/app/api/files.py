"""
SecureCloud - File Management & Format-Preserving Viewer API
Preserves byte-level integrity, supports real-time ML scanning, multi-format rendering, versioning, and quota controls.
"""

import os
import io
import json
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request, Response
from fastapi.responses import FileResponse as FastAPIFileResponse, StreamingResponse
from sqlalchemy.orm import Session

import docx
import openpyxl
import pptx
import mammoth

from backend.app.database import get_db
from backend.app.models.models import User, FileRecord, FileVersion, SecurityScan, RecycleBinItem, QuarantineFile, VerifiedCleanArtifact
from backend.app.schemas.schemas import FileResponse, FileRenameRequest, ThreatScanResponse
from backend.app.security.auth_utils import get_current_user
from backend.app.security.ip_guard import get_client_ip
from backend.app.services.storage_service import (
    compute_hashes, format_size, sanitize_filename, generate_storage_path, resolve_storage_path,
    recalculate_user_storage, get_user_storage_metrics, ensure_physical_file,
    save_file_bytes, read_file_bytes, generate_file_presigned_url
)
from backend.app.services.quarantine_service import QuarantineService
from backend.app.services.audit_service import AuditService
from backend.app.services.alert_service import AlertService
from backend.app.services.telemetry_service import increment_upload_count, increment_threat_count
from backend.app.services.presentation_service import PresentationService
from backend.app.services.event_service import EventService
from ml.predict import ThreatPredictor
from scanner.scanner_service import UnifiedScannerService

router = APIRouter(prefix="/api/files", tags=["Files"])
predictor = ThreatPredictor()
unified_scanner = UnifiedScannerService()

def to_ist(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    return (dt + timedelta(hours=5, minutes=30)).strftime("%d %b %Y %H:%M:%S")

def to_ist_short(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    return (dt + timedelta(hours=5, minutes=30)).strftime("%d %b %Y %H:%M")

@router.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Uploads file, computes SHA-256, extracts static features, runs real ML prediction,
    and quarantines if malicious. Original file bytes are NEVER modified.
    """
    client_ip = get_client_ip(request)
    raw_bytes = await file.read()
    file_size = len(raw_bytes)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Cannot upload empty file.")

    # Live Quota Check
    recalculate_user_storage(db, current_user.id)
    if current_user.used_quota_bytes + file_size > current_user.quota_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"Storage quota exceeded. Available: {format_size(current_user.quota_bytes - current_user.used_quota_bytes)}"
        )

    # Hashes
    hashes = compute_hashes(raw_bytes)
    sha256 = hashes["sha256"]

    # Duplicate file detection across user's active vault
    existing_dup = db.query(FileRecord).filter(
        FileRecord.user_id == current_user.id,
        FileRecord.file_hash == sha256,
        FileRecord.is_in_recycle_bin == False
    ).first()

    # Sanitize and prepare storage path
    original_filename = file.filename or "uploaded_file"
    clean_filename = sanitize_filename(original_filename)
    ext = os.path.splitext(clean_filename)[1].lower()
    file_id, storage_path = generate_storage_path(ext)

    # 1. Check Server Trust Registry for Exact SHA-256 or Filename in Verified Clean Registry
    trusted_artifact = db.query(VerifiedCleanArtifact).filter(
        (VerifiedCleanArtifact.sha256 == sha256) | (VerifiedCleanArtifact.original_filename == clean_filename),
        VerifiedCleanArtifact.verification_status == "VERIFIED_CLEAN"
    ).first()

    if trusted_artifact:
        # Trust recognized! Do not flag as threat.
        scan_result = {
            "threat_score": 0.0,
            "security_status": "CLEAN",
            "final_verdict": "✓ VERIFIED CLEAN FILE",
            "is_quarantined": False,
            "ml_prediction": "CLEAN",
            "probabilities": {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},
            "ml_probabilities": {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},
            "model_version": "Trust Registry Override",
            "heuristic_score": 0.0,
            "heuristic_rules": ["Approved in Verified Clean Trust Registry"],
            "detected_mime": trusted_artifact.mime_type or "application/octet-stream",
            "explanations": [f"Exact cryptographic artifact previously approved as VERIFIED_CLEAN by {trusted_artifact.verified_by_username}."],
            "is_trusted_artifact": True
        }
        threat_score = 0.0
        security_status = "CLEAN"
        final_verdict = scan_result["final_verdict"]
    else:
        # Real Multi-Layer Security Pipeline (ClamAV + Static PE Heuristics + LightGBM ML)
        scan_result = unified_scanner.scan(raw_bytes, clean_filename)
        threat_score = scan_result["threat_score"]
        security_status = scan_result["security_status"]
        final_verdict = scan_result["final_verdict"]

    # If Malicious -> Isolate into Quarantine Vault
    if scan_result.get("is_quarantined", False):
        increment_threat_count()
        quarantine_entry = QuarantineService.quarantine_file(
            db=db,
            user_id=current_user.id,
            original_filename=clean_filename,
            file_hash=sha256,
            raw_bytes=raw_bytes,
            reason=f"{final_verdict} (Threat Score: {threat_score}%)"
        )
        
        # Save Security Alert
        AlertService.create_alert(
            db=db,
            title=f"🚨 CRITICAL SECURITY THREAT: {final_verdict}",
            description=f"File '{clean_filename}' classified as malicious (Threat Score: {threat_score}%). Isolated into Quarantine.",
            severity="CRITICAL",
            user_id=current_user.id
        )

        AuditService.log(
            db, "QUARANTINE_FILE", f"File {clean_filename}", "BLOCKED",
            f"Verdict: {final_verdict}, SHA-256: {sha256[:16]}",
            user_id=current_user.id, username=current_user.username, role=current_user.role, ip_address=client_ip
        )

        # Still persist non-executable metadata record with MALICIOUS status
        new_file = FileRecord(
            id=file_id,
            user_id=current_user.id,
            filename=clean_filename,
            original_filename=clean_filename,
            file_size=file_size,
            file_hash=sha256,
            sha1_hash=hashes["sha1"],
            md5_hash=hashes["md5"],
            mime_type=scan_result["detected_mime"],
            extension=ext,
            is_confidential=False,
            is_in_recycle_bin=False,
            current_version="v1.0",
            threat_score=threat_score,
            security_status=security_status,
            storage_path=quarantine_entry.quarantine_path,
            created_at=datetime.utcnow()
        )
        db.add(new_file)

        # Persist SecurityScan record
        sec_scan = SecurityScan(
            file_id=new_file.id,
            user_id=current_user.id,
            file_hash=sha256,
            threat_score=threat_score,
            final_verdict=final_verdict,
            security_status=security_status,
            ml_prediction=scan_result.get("ml_prediction", "MALICIOUS"),
            ml_probabilities=scan_result.get("ml_probabilities", {}),
            model_version=scan_result.get("model_version", "LightGBM v2.0"),
            heuristic_score=scan_result.get("heuristic_score", 0.0),
            heuristic_verdict=scan_result.get("heuristic_verdict", "MALICIOUS"),
            triggered_rules=scan_result.get("heuristic_rules", []),
            explanations=scan_result.get("reasons") or scan_result.get("explanations", []),
            scanned_at=datetime.utcnow()
        )
        db.add(sec_scan)
        db.commit()

        EventService.record_event(
            db, "FILE_MALICIOUS", user_id=current_user.id, file_id=new_file.id,
            file_hash=sha256, ip_address=client_ip, result="BLOCKED", severity="CRITICAL",
            metadata={"filename": clean_filename, "threat_score": threat_score}
        )
        EventService.record_event(
            db, "FILE_QUARANTINED", user_id=current_user.id, file_id=new_file.id,
            file_hash=sha256, ip_address=client_ip, result="SUCCESS", severity="HIGH",
            metadata={"filename": clean_filename}
        )

        # Update live quota
        recalculate_user_storage(db, current_user.id)
        storage_metrics = get_user_storage_metrics(db, current_user.id)

        return {
            "status": "QUARANTINED",
            "is_critical_threat": True,
            "message": f"Security Threat Detected: '{clean_filename}' was classified as MALICIOUS ({threat_score}%) and isolated into the Quarantine Vault.",
            "file": {
                "id": new_file.id,
                "filename": new_file.filename,
                "file_size": new_file.file_size,
                "file_size_formatted": format_size(new_file.file_size),
                "file_hash": new_file.file_hash,
                "mime_type": new_file.mime_type,
                "extension": new_file.extension,
                "current_version": new_file.current_version,
                "threat_score": new_file.threat_score,
                "security_status": new_file.security_status,
                "created_at": new_file.created_at.strftime("%d %b %Y %H:%M")
            },
            "scan": {
                "threat_score": threat_score,
                "final_verdict": final_verdict,
                "security_status": security_status,
                "final_risk": scan_result.get("final_risk", "CRITICAL"),
                "detection_layers": scan_result.get("detection_layers", {}),
                "reasons": scan_result.get("reasons", []),
                "ml_prediction": scan_result.get("ml_prediction", "MALICIOUS"),
                "ml_probabilities": scan_result.get("ml_probabilities", {}),
                "model_version": scan_result.get("model_version", "v2.0"),
                "heuristic_score": scan_result.get("heuristic_score", 0.0),
                "heuristic_rules": scan_result.get("heuristic_rules", []),
                "explanations": scan_result.get("explanations", [])
            },
            "storage": storage_metrics
        }

    # If Safe or Suspicious -> Write Original Raw Bytes through Object Storage Provider
    storage_key = f"users/{current_user.id}/uploads/{file_id}_{clean_filename}"
    saved_storage_path = save_file_bytes(storage_key, raw_bytes, content_type=scan_result.get("detected_mime", "application/octet-stream"))

    # Create Database Records
    new_file = FileRecord(
        id=file_id,
        user_id=current_user.id,
        filename=clean_filename,
        original_filename=clean_filename,
        file_size=file_size,
        file_hash=sha256,
        sha1_hash=hashes["sha1"],
        md5_hash=hashes["md5"],
        mime_type=scan_result.get("detected_mime") or scan_result.get("mime_type") or "application/octet-stream",
        extension=ext,
        is_confidential=False,
        is_in_recycle_bin=False,
        current_version="v1.0",
        threat_score=threat_score,
        security_status=security_status,
        storage_path=saved_storage_path,
        created_at=datetime.utcnow()
    )
    db.add(new_file)

    # Create Version v1.0
    v1 = FileVersion(
        file_id=file_id,
        version_tag="v1.0",
        file_size=file_size,
        file_hash=sha256,
        storage_path=saved_storage_path,
        uploader_id=current_user.id,
        created_at=datetime.utcnow()
    )
    db.add(v1)

    # Persist SecurityScan record
    sec_scan = SecurityScan(
        file_id=new_file.id,
        user_id=current_user.id,
        file_hash=sha256,
        threat_score=threat_score,
        final_verdict=final_verdict,
        security_status=security_status,
        ml_prediction=scan_result.get("ml_prediction", "CLEAN"),
        ml_probabilities=scan_result.get("ml_probabilities", {}),
        model_version=scan_result.get("model_version", "LightGBM v2.0"),
        heuristic_score=scan_result.get("heuristic_score", 0.0),
        heuristic_verdict=scan_result.get("heuristic_verdict", "CLEAN"),
        triggered_rules=scan_result.get("heuristic_rules", []),
        explanations=scan_result.get("reasons") or scan_result.get("explanations", []),
        scanned_at=datetime.utcnow()
    )
    db.add(sec_scan)

    increment_upload_count()
    db.commit()

    # Authoritative quota recalculation
    recalculate_user_storage(db, current_user.id)
    storage_metrics = get_user_storage_metrics(db, current_user.id)

    if security_status == "SUSPICIOUS":
        AlertService.create_alert(
            db=db,
            title="⚠️ SUSPICIOUS SCRIPT/FILE DETECTED",
            description=f"File '{clean_filename}' flagged with suspicious indicators (Threat Score: {threat_score}%).",
            severity="MEDIUM",
            user_id=current_user.id
        )
        EventService.record_event(
            db, "FILE_SUSPICIOUS", user_id=current_user.id, file_id=new_file.id,
            file_hash=sha256, ip_address=client_ip, result="SUCCESS", severity="MEDIUM",
            metadata={"filename": clean_filename, "threat_score": threat_score}
        )

    EventService.record_event(
        db, "FILE_UPLOAD", user_id=current_user.id, file_id=new_file.id,
        file_hash=sha256, ip_address=client_ip, result="SUCCESS", severity="INFO",
        metadata={"filename": clean_filename, "security_status": security_status, "threat_score": threat_score}
    )

    AuditService.log(
        db, "UPLOAD_FILE", f"File {clean_filename}", "SUCCESS",
        f"Size: {format_size(file_size)}, SHA256: {sha256[:16]}, Verdict: {final_verdict}",
        user_id=current_user.id, username=current_user.username, role=current_user.role, ip_address=client_ip
    )

    return {
        "status": "SUCCESS",
        "message": "File uploaded and scanned successfully." if not existing_dup else "File uploaded (Notice: identical file hash exists).",
        "file": {
            "id": new_file.id,
            "filename": new_file.filename,
            "file_size": new_file.file_size,
            "file_size_formatted": format_size(new_file.file_size),
            "file_hash": new_file.file_hash,
            "mime_type": new_file.mime_type,
            "extension": new_file.extension,
            "current_version": new_file.current_version,
            "threat_score": new_file.threat_score,
            "security_status": new_file.security_status,
            "created_at": new_file.created_at.strftime("%d %b %Y %H:%M")
        },
        "scan": {
            "threat_score": threat_score,
            "final_verdict": final_verdict,
            "security_status": security_status,
            "ml_prediction": scan_result["ml_prediction"],
            "ml_probabilities": scan_result["ml_probabilities"],
            "model_version": scan_result["model_version"],
            "heuristic_score": scan_result["heuristic_score"],
            "heuristic_rules": scan_result["heuristic_rules"],
            "explanations": scan_result["explanations"]
        },
        "storage": storage_metrics
    }

@router.get("/list")
def list_user_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists active non-recycled files for the current user with direct security status badges."""
    recalculate_user_storage(db, current_user.id)
    files = db.query(FileRecord).filter(
        FileRecord.user_id == current_user.id,
        FileRecord.is_in_recycle_bin == False,
        FileRecord.is_confidential == False
    ).order_by(FileRecord.created_at.desc()).all()

    return [
        {
            "id": f.id,
            "filename": f.filename,
            "original_filename": f.original_filename,
            "file_size": f.file_size,
            "file_size_formatted": format_size(f.file_size),
            "file_hash": f.file_hash,
            "mime_type": f.mime_type,
            "extension": f.extension,
            "is_confidential": f.is_confidential,
            "current_version": f.current_version,
            "threat_score": f.threat_score,
            "security_status": f.security_status,
            "is_shared": len([s for s in f.shared_links if s.is_active]) > 0,
            "created_at": to_ist_short(f.created_at),
            "updated_at": to_ist_short(f.updated_at)
        }
        for f in files
    ]

@router.get("/all")
def list_all_files_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Admin view: lists all non-confidential files across all users."""
    if current_user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin privileges required.")

    files = db.query(FileRecord).filter(
        FileRecord.is_in_recycle_bin == False
    ).order_by(FileRecord.created_at.desc()).all()

    results = []
    for f in files:
        owner = db.query(User).filter(User.id == f.user_id).first()
        results.append({
            "id": f.id,
            "filename": f.filename,
            "file_size": f.file_size,
            "file_size_formatted": format_size(f.file_size),
            "file_hash": f.file_hash,
            "owner": owner.username if owner else "Unknown",
            "owner_email": owner.email if owner else "Unknown",
            "is_confidential": f.is_confidential,
            "threat_score": f.threat_score,
            "security_status": f.security_status,
            "created_at": to_ist_short(f.created_at)
        })
    return results

@router.put("/{file_id}/rename")
def rename_file(
    file_id: str,
    req: FileRenameRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Renames an existing file."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id, FileRecord.user_id == current_user.id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    clean_name = sanitize_filename(req.new_filename)
    old_name = f.filename
    f.filename = clean_name
    f.original_filename = clean_name
    _, ext = os.path.splitext(clean_name)
    if ext:
        f.extension = ext
    f.updated_at = datetime.utcnow()
    db.commit()

    AuditService.log(db, "RENAME_FILE", f"File {file_id}", "SUCCESS", f"From '{old_name}' to '{clean_name}'", user_id=current_user.id, username=current_user.username)
    return {"message": "File renamed successfully.", "filename": clean_name}

@router.delete("/{file_id}")
def delete_file_to_recycle_bin(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Moves a file to Recycle Bin."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id, FileRecord.user_id == current_user.id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    f.is_in_recycle_bin = True

    # Record in RecycleBin
    bin_item = RecycleBinItem(
        file_id=f.id,
        user_id=current_user.id,
        original_name=f.filename,
        restore_path=f.storage_path,
        deleted_at=datetime.utcnow()
    )
    db.add(bin_item)
    db.commit()

    # Recalculate storage quota
    recalculate_user_storage(db, current_user.id)
    storage_metrics = get_user_storage_metrics(db, current_user.id)

    AuditService.log(db, "DELETE_FILE", f"File {f.filename}", "SUCCESS", "Moved to Recycle Bin", user_id=current_user.id, username=current_user.username)
    return {
        "message": "File moved to Recycle Bin.",
        "storage": storage_metrics
    }

@router.get("/{file_id}/versions")
def get_file_versions(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists all versions for a file with uploader and scan verdict."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")
    if f.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied.")

    versions = db.query(FileVersion).filter(FileVersion.file_id == file_id).order_by(FileVersion.created_at.desc()).all()
    results = []
    for v in versions:
        uploader = db.query(User).filter(User.id == v.uploader_id).first()
        results.append({
            "id": v.id,
            "file_id": v.file_id,
            "version_tag": v.version_tag,
            "file_size": v.file_size,
            "file_size_formatted": format_size(v.file_size),
            "file_hash": v.file_hash,
            "uploader_username": uploader.username if uploader else "System",
            "security_status": f.security_status,
            "threat_score": f.threat_score,
            "created_at": to_ist(v.created_at)
        })
    return results

@router.post("/{file_id}/versions/upload")
async def upload_new_version(
    file_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Uploads a new version of an existing file through object storage & unified scanner."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id, FileRecord.user_id == current_user.id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    raw_bytes = await file.read()
    file_size = len(raw_bytes)
    hashes = compute_hashes(raw_bytes)

    # Determine version tag
    existing_count = db.query(FileVersion).filter(FileVersion.file_id == file_id).count()
    new_version_tag = f"v{existing_count + 1}.0"

    ext = os.path.splitext(f.filename)[1].lower()
    storage_key = f"users/{current_user.id}/versions/{f.id}_{new_version_tag}_{f.filename}"
    new_storage_path = save_file_bytes(storage_key, raw_bytes, content_type=f.mime_type)

    # Multi-Layer Rescan of new version
    scan_res = unified_scanner.scan(raw_bytes, f.filename)

    # Create Version
    ver = FileVersion(
        file_id=f.id,
        version_tag=new_version_tag,
        file_size=file_size,
        file_hash=hashes["sha256"],
        storage_path=new_storage_path,
        uploader_id=current_user.id,
        created_at=datetime.utcnow()
    )
    db.add(ver)

    # Persist SecurityScan record
    sec_scan = SecurityScan(
        file_id=f.id,
        user_id=current_user.id,
        file_hash=hashes["sha256"],
        threat_score=scan_res["threat_score"],
        final_verdict=scan_res["final_verdict"],
        security_status=scan_res["security_status"],
        ml_prediction=scan_res.get("ml_prediction", "CLEAN"),
        ml_probabilities=scan_res.get("ml_probabilities", {}),
        model_version=scan_res.get("model_version", "LightGBM v2.0"),
        heuristic_score=scan_res.get("heuristic_score", 0.0),
        heuristic_verdict=scan_res.get("heuristic_verdict", "CLEAN"),
        triggered_rules=scan_res.get("heuristic_rules", []),
        explanations=scan_res.get("reasons") or scan_res.get("explanations", []),
        scanned_at=datetime.utcnow()
    )
    db.add(sec_scan)

    # Update active FileRecord
    f.file_size = file_size
    f.file_hash = hashes["sha256"]
    f.storage_path = new_storage_path
    f.current_version = new_version_tag
    f.threat_score = scan_res["threat_score"]
    f.security_status = scan_res["security_status"]
    f.updated_at = datetime.utcnow()
    db.commit()

    # Recalculate storage quota
    recalculate_user_storage(db, current_user.id)
    storage_metrics = get_user_storage_metrics(db, current_user.id)

    AuditService.log(db, "NEW_VERSION", f"File {f.filename}", "SUCCESS", f"Version: {new_version_tag}", user_id=current_user.id, username=current_user.username)
    return {
        "message": f"Version {new_version_tag} uploaded successfully.",
        "version": new_version_tag,
        "threat_score": f.threat_score,
        "security_status": f.security_status,
        "scan": scan_res,
        "storage": storage_metrics
    }

@router.post("/{file_id}/versions/{version_id}/restore")
def restore_file_version(
    file_id: str,
    version_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Restores a previous file version as the active version."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")
    if f.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied.")

    ver = db.query(FileVersion).filter(FileVersion.id == version_id, FileVersion.file_id == file_id).first()
    if not ver:
        raise HTTPException(status_code=404, detail="Version not found.")

    f.file_size = ver.file_size
    f.file_hash = ver.file_hash
    f.storage_path = ver.storage_path
    f.current_version = f"{ver.version_tag} (Restored)"
    f.updated_at = datetime.utcnow()
    db.commit()

    AuditService.log(
        db, "RESTORE_VERSION", f"File {f.filename}", "SUCCESS",
        f"Restored to {ver.version_tag}", user_id=current_user.id, username=current_user.username
    )
    return {
        "status": "SUCCESS",
        "message": f"Successfully restored '{f.filename}' to {ver.version_tag}.",
        "active_version": f.current_version
    }

# =========================================================================
# Multi-Format File Viewer & Byte-Exact Downloader
# =========================================================================

@router.get("/{file_id}/download")
def download_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the exact original file bytes as an attachment.
    Blocks files currently in the Recycle Bin and enforces quarantine isolation.
    """
    f = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    if f.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied. You do not have permission to download this file.")

    if (f.security_status in ["MALICIOUS", "QUARANTINED"] or getattr(f, "is_quarantined", False)) and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Access denied. This file has been isolated into the Quarantine Vault due to malicious threat classification."
        )

    if f.is_in_recycle_bin:
        raise HTTPException(
            status_code=400,
            detail="File is currently in the Recycle Bin. Restore the file before viewing or downloading it."
        )

    # Check for S3 presigned URL
    presigned = generate_file_presigned_url(f.storage_path)
    if presigned:
        return {"download_url": presigned, "direct": True}

    f.storage_path = ensure_physical_file(f, db)

    EventService.record_event(
        db, "FILE_DOWNLOAD", user_id=current_user.id, file_id=f.id,
        file_hash=f.file_hash, result="SUCCESS", severity="INFO",
        metadata={"filename": f.filename}
    )

    return FastAPIFileResponse(
        path=f.storage_path,
        filename=f.filename,
        media_type=f.mime_type
    )

@router.get("/{file_id}/view")
def view_file_content(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Provides a structured, format-preserving view of the original file.
    Enforces quarantine restriction for non-admin users.
    """
    f = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    if f.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied. You do not have permission to view this file.")

    if (f.security_status in ["MALICIOUS", "QUARANTINED"] or getattr(f, "is_quarantined", False)) and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Access denied. This file has been isolated into the Quarantine Vault due to malicious threat classification."
        )

    if f.is_confidential:
        return {
            "format": "CONFIDENTIAL_LOCKED",
            "filename": f.filename,
            "file_size": f.file_size,
            "message": "This file is encrypted with AES-256-GCM in the Zero-Knowledge Confidential Vault. Please unlock with your secret PIN to view decrypted content."
        }

    if f.is_in_recycle_bin:
        raise HTTPException(
            status_code=400,
            detail="File is currently in the Recycle Bin. Restore the file before viewing or downloading it."
        )

    f.storage_path = ensure_physical_file(f, db)

    ext = f.extension.lower()
    file_size = f.file_size

    with open(f.storage_path, "rb") as fp:
        raw_bytes = fp.read()

    # 1. Plain Text, CSV, JSON, XML, Code
    if ext in [".txt", ".log", ".md", ".py", ".js", ".ts", ".html", ".css", ".sh", ".bat", ".ps1", ".java", ".c", ".cpp", ".sql", ".ini", ".conf", ".yaml", ".yml", ".env"]:
        try:
            text_content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text_content = str(raw_bytes)
        return {
            "format": "TEXT",
            "filename": f.filename,
            "file_size": file_size,
            "mime_type": f.mime_type,
            "content": text_content
        }

    if ext == ".json":
        try:
            parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            formatted = json.dumps(parsed, indent=2)
        except Exception:
            formatted = raw_bytes.decode("utf-8", errors="replace")
        return {
            "format": "JSON",
            "filename": f.filename,
            "file_size": file_size,
            "content": formatted
        }

    if ext == ".csv":
        text_content = raw_bytes.decode("utf-8", errors="replace")
        lines = [line.split(",") for line in text_content.splitlines()]
        return {
            "format": "CSV_TABLE",
            "filename": f.filename,
            "file_size": file_size,
            "rows": lines
        }

    # 2. DOCX Word Document
    if ext in [".docx", ".doc"]:
        html_content = ""
        try:
            mammoth_res = mammoth.convert_to_html(io.BytesIO(raw_bytes))
            html_content = mammoth_res.value
        except Exception:
            pass

        paragraphs = []
        tables = []
        try:
            doc = docx.Document(io.BytesIO(raw_bytes))
            for p in doc.paragraphs:
                if p.text.strip():
                    paragraphs.append({"style": p.style.name if p.style else "Normal", "text": p.text})
            
            for t in doc.tables:
                table_rows = []
                for row in t.rows:
                    table_rows.append([cell.text.strip() for cell in row.cells])
                tables.append(table_rows)
        except Exception:
            pass

        return {
            "format": "DOCX_RENDERED",
            "filename": f.filename,
            "file_size": file_size,
            "html_content": html_content,
            "paragraph_count": len(paragraphs),
            "paragraphs": paragraphs,
            "tables": tables
        }

    # 3. XLSX Excel Sheet
    if ext in [".xlsx", ".xls"]:
        try:
            wb = openpyxl.load_workbook(io.BytesIO(raw_bytes), data_only=True)
            sheets_data = {}
            for sheetname in wb.sheetnames:
                ws = wb[sheetname]
                rows = []
                for row in ws.iter_rows(values_only=True):
                    if any(c is not None for c in row):
                        rows.append([str(c) if c is not None else "" for c in row])
                    if len(rows) >= 500:
                        break
                sheets_data[sheetname] = rows

            return {
                "format": "XLSX_RENDERED",
                "filename": f.filename,
                "file_size": file_size,
                "sheet_names": wb.sheetnames,
                "sheets": sheets_data
            }
        except Exception as e:
            return {"format": "ERROR", "filename": f.filename, "error": str(e)}

    # 4. PPTX / PPT / Presentation Rendering (Exact visual coordinates, themes, shapes, images)
    if ext in [".pptx", ".ppt", ".pps", ".ppsx", ".odp", ".pot", ".potx"]:
        pres_res = PresentationService.render_presentation(raw_bytes, f.file_hash, f.filename)
        pres_res["file_size"] = file_size
        return pres_res

    # 5. ZIP Archive Hierarchy
    if ext in [".zip"]:
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                items = []
                for info in zf.infolist():
                    items.append({
                        "filename": info.filename,
                        "size_bytes": info.file_size,
                        "size_formatted": format_size(info.file_size),
                        "compressed_size": info.compress_size,
                        "is_dir": info.is_dir()
                    })
                return {
                    "format": "ZIP_TREE",
                    "filename": f.filename,
                    "file_size": file_size,
                    "total_entries": len(items),
                    "entries": items
                }
        except Exception as e:
            return {"format": "ERROR", "filename": f.filename, "error": str(e)}

    # 6. PDF, Image, Audio, Video
    if ext in [".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp3", ".wav", ".ogg", ".flac", ".mp4", ".webm", ".mov", ".avi"]:
        return {
            "format": "STREAMABLE_MEDIA",
            "filename": f.filename,
            "file_size": file_size,
            "mime_type": f.mime_type,
            "stream_url": f"/api/files/{f.id}/stream"
        }

    # 7. Executable / Binary Inspector -> Extract Strings & Hex Disassembly
    printable_strings = []
    current_str = []
    for b in raw_bytes[:100000]:
        if 32 <= b <= 126 or b in (9, 10, 13):
            current_str.append(chr(b))
        else:
            if len(current_str) >= 4:
                printable_strings.append("".join(current_str))
            current_str = []
        if len(printable_strings) >= 100:
            break

    # Hex Dump generation (first 512 bytes)
    hex_dump_rows = []
    chunk = raw_bytes[:512]
    for i in range(0, len(chunk), 16):
        sub = chunk[i:i+16]
        hex_bytes = " ".join(f"{b:02X}" for b in sub)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub)
        hex_dump_rows.append(f"{i:08X}  {hex_bytes:<48}  |{ascii_chars}|")

    return {
        "format": "BINARY_INSPECTOR",
        "filename": f.filename,
        "file_size": file_size,
        "file_size_formatted": format_size(file_size),
        "mime_type": f.mime_type,
        "file_hash": f.file_hash,
        "hex_dump": "\n".join(hex_dump_rows),
        "strings": printable_strings[:80],
        "message": "Binary Disassembly & Structural PE Inspector"
    }

@router.get("/{file_id}/stream")
def stream_file(
    file_id: str,
    db: Session = Depends(get_db)
):
    """Serves media stream inline (PDF, Image, Video, Audio)."""
    f = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not f or f.is_in_recycle_bin:
        raise HTTPException(status_code=404, detail="File not found.")

    if f.security_status in ["MALICIOUS", "QUARANTINED"] or getattr(f, "is_quarantined", False):
        raise HTTPException(
            status_code=403,
            detail="Access denied. This file has been isolated into the Quarantine Vault due to malicious threat classification."
        )

    f.storage_path = ensure_physical_file(f, db)

    return FastAPIFileResponse(
        path=f.storage_path,
        media_type=f.mime_type,
        headers={
            "Content-Disposition": f'inline; filename="{f.filename}"',
            "Accept-Ranges": "bytes",
            "X-Frame-Options": "SAMEORIGIN",
            "Access-Control-Allow-Origin": "*"
        }
    )
