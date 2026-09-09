with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    soc_text = f.read()

upload_for_user_endpoint = """
# =========================================================================
# Administrator File Upload & Ingestion For Users
# =========================================================================

@router.post("/files/upload-for-user")
async def admin_upload_file_for_user(
    request: Request,
    target_user_id: int = Form(...),
    file: UploadFile = File(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    \"\"\"
    Administrator File Ingestion Hub:
    Allows SOC Admin to ingest files directly into any user's repository with automated ML scanning.
    \"\"\"
    from backend.app.services.crypto_service import compute_hashes
    from backend.app.services.feature_extractor import extract_file_features
    from backend.app.services.ml_detector import predict_threat
    from backend.app.services.storage_service import generate_storage_path, sanitize_filename
    from backend.app.models.models import VerifiedCleanArtifact
    
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found.")
        
    raw_bytes = await file.read()
    file_size = len(raw_bytes)
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Cannot upload empty file.")
        
    # Check target user quota
    recalculate_user_storage(db, target_user.id)
    if target_user.used_quota_bytes + file_size > target_user.quota_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"Target user '{target_user.username}' storage quota exceeded. Available: {format_size(target_user.quota_bytes - target_user.used_quota_bytes)}"
        )
        
    # Hashes & metadata
    hashes = compute_hashes(raw_bytes)
    sha256 = hashes["sha256"]
    original_filename = file.filename or "uploaded_file"
    clean_filename = sanitize_filename(original_filename)
    ext = os.path.splitext(clean_filename)[1].lower()
    file_id, storage_path = generate_storage_path(ext)
    
    # Check Trust Registry
    trusted_artifact = db.query(VerifiedCleanArtifact).filter(
        VerifiedCleanArtifact.sha256 == sha256,
        VerifiedCleanArtifact.verification_status == "VERIFIED_CLEAN"
    ).first()
    
    if trusted_artifact:
        scan_result = {
            "threat_score": 0.0,
            "security_status": "VERIFIED_CLEAN",
            "model_version": "Trust Registry Override",
            "feature_version": "Exact SHA-256 Match",
            "probabilities": {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},
            "heuristic_score": 0.0,
            "triggered_rules": ["Recognized in Verified Clean Trust Registry"]
        }
    else:
        # Extract features and predict
        features = extract_file_features(raw_bytes, clean_filename)
        scan_result = predict_threat(features)
        
    # Write physical file
    with open(storage_path, "wb") as fp:
        fp.write(raw_bytes)
        
    # Create FileRecord
    file_rec = FileRecord(
        id=file_id,
        user_id=target_user.id,
        filename=clean_filename,
        original_filename=original_filename,
        file_size=file_size,
        mime_type=file.content_type or "application/octet-stream",
        extension=ext,
        storage_path=storage_path,
        file_hash=sha256,
        md5_hash=hashes["md5"],
        sha1_hash=hashes["sha1"],
        security_status=scan_result["security_status"],
        threat_score=scan_result["threat_score"],
        scan_status="COMPLETED",
        last_scanned_at=datetime.utcnow(),
        created_at=datetime.utcnow()
    )
    db.add(file_rec)
    
    # Save SecurityScan log
    scan_rec = SecurityScan(
        file_id=file_id,
        user_id=target_user.id,
        file_hash=sha256,
        threat_score=scan_result["threat_score"],
        ml_prediction=scan_result["security_status"],
        ml_probabilities=scan_result["probabilities"],
        model_version=scan_result["model_version"],
        heuristic_score=scan_result.get("heuristic_score", 0.0),
        triggered_rules=scan_result.get("triggered_rules", []),
        scanned_at=datetime.utcnow()
    )
    db.add(scan_rec)
    
    # Auto-quarantine if malicious
    if scan_result["security_status"] == "MALICIOUS":
        q_file = QuarantineFile(
            file_id=file_id,
            user_id=target_user.id,
            original_filename=clean_filename,
            file_hash=sha256,
            quarantine_path=storage_path,
            reason=f"High threat score: {scan_result['threat_score']}%",
            status="QUARANTINED",
            quarantined_at=datetime.utcnow()
        )
        db.add(q_file)
        
    recalculate_user_storage(db, target_user.id)
    
    AuditService.log(
        db, "ADMIN_INGEST_FILE_FOR_USER", f"File {clean_filename}", "SUCCESS",
        f"Admin ingested file into user '{target_user.username}' (ID #{target_user.id}). Status: {scan_result['security_status']}",
        user_id=current_admin.id, username=current_admin.username, role="ADMIN"
    )
    db.commit()
    db.refresh(file_rec)
    
    return {
        \"status\": \"SUCCESS\",
        \"file\": {
            \"id\": file_rec.id,
            \"filename\": file_rec.filename,
            \"file_size\": file_rec.file_size,
            \"file_size_formatted\": format_size(file_rec.file_size),
            \"target_user_id\": target_user.id,
            \"target_username\": target_user.username,
            \"security_status\": file_rec.security_status,
            \"threat_score\": file_rec.threat_score,
            \"file_hash\": file_rec.file_hash
        },
        \"scan\": scan_result,
        \"message\": f"Successfully ingested '{clean_filename}' into {target_user.username}'s repository."
    }
"""

if "admin_upload_file_for_user" not in soc_text:
    soc_text += "\n" + upload_for_user_endpoint
    with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
        f.write(soc_text)
    print("[OK] Added admin_upload_file_for_user endpoint to soc.py!")
else:
    print("[OK] admin_upload_file_for_user already present in soc.py")
