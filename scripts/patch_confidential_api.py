from datetime import timedelta

with open("backend/app/api/confidential.py", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Imports check
if "timedelta" not in text:
    text = text.replace(
        "from datetime import datetime",
        "from datetime import datetime, timedelta"
    )

# 2. Update _process_unlock
old_unlock_start = """def _process_unlock(file_id: str, pin: str, current_user: User, db: Session):
    f = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.user_id == current_user.id,
        FileRecord.is_confidential == True
    ).first()

    if not f:
        raise HTTPException(status_code=404, detail="Confidential file not found.")

    c_meta = f.confidential_meta
    if not c_meta:
        raise HTTPException(status_code=400, detail="Missing vault encryption metadata.")

    if not verify_pin_hash(pin, c_meta.pin_hash):
        AuditService.log(
            db, "UNLOCK_CONFIDENTIAL_FAIL", f"File {f.filename}", "FAILED",
            "Incorrect PIN attempt", user_id=current_user.id, username=current_user.username
        )
        raise HTTPException(status_code=400, detail="Wrong PIN, try again.")"""

new_unlock_start = """def _process_unlock(file_id: str, pin: str, current_user: User, db: Session):
    f = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.user_id == current_user.id,
        FileRecord.is_confidential == True
    ).first()

    if not f:
        raise HTTPException(status_code=404, detail="Confidential file not found.")

    c_meta = f.confidential_meta
    if not c_meta:
        raise HTTPException(status_code=400, detail="Missing vault encryption metadata.")

    # 1. Check Permanent Lockout
    if c_meta.is_permanently_locked or (c_meta.failed_attempts and c_meta.failed_attempts >= 9):
        c_meta.is_permanently_locked = True
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="File locked permanently. Cannot open ever sorry. Security threshold exceeded."
        )

    # 2. Check Timed Lockout (30 min or 2 hrs)
    now = datetime.utcnow()
    if c_meta.locked_until and c_meta.locked_until > now:
        remaining_secs = int((c_meta.locked_until - now).total_seconds())
        rem_min = (remaining_secs // 60) + 1
        lock_label = "30 minutes" if c_meta.lockout_stage == 1 else "2 hours"
        raise HTTPException(
            status_code=423,
            detail=f"File locked for {lock_label} due to consecutive failed PIN attempts. Try again later in {rem_min} minute(s)."
        )

    # If timed lockout expired, clear locked_until
    if c_meta.locked_until and c_meta.locked_until <= now:
        c_meta.locked_until = None
        db.commit()

    # 3. Check PIN Verification
    if not verify_pin_hash(pin, c_meta.pin_hash):
        c_meta.failed_attempts = (c_meta.failed_attempts or 0) + 1
        fa = c_meta.failed_attempts

        AuditService.log(
            db, "UNLOCK_CONFIDENTIAL_FAIL", f"File {f.filename}", "FAILED",
            f"Incorrect PIN attempt #{fa}", user_id=current_user.id, username=current_user.username
        )

        if fa == 1:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining.")
        elif fa == 2:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. WARNING: Only 1 attempt remaining before 30-minute lockout!")
        elif fa == 3:
            c_meta.lockout_stage = 1
            c_meta.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.commit()
            raise HTTPException(
                status_code=423,
                detail="File locked for 30 minutes due to 3 consecutive failed attempts. Try again later."
            )
        elif fa == 4:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining before 2-hour lockout.")
        elif fa == 5:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. WARNING: Only 1 attempt remaining before 2-hour lockout!")
        elif fa == 6:
            c_meta.lockout_stage = 2
            c_meta.locked_until = datetime.utcnow() + timedelta(hours=2)
            db.commit()
            raise HTTPException(
                status_code=423,
                detail="File locked for 2 hours due to repeated failed attempts. Try again later."
            )
        elif fa == 7:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining before PERMANENT LOCKOUT.")
        elif fa == 8:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. FINAL WARNING: Only 1 attempt remaining before PERMANENT LOCKOUT!")
        else:
            c_meta.lockout_stage = 3
            c_meta.is_permanently_locked = True
            c_meta.locked_until = None
            db.commit()
            raise HTTPException(
                status_code=403,
                detail="File locked permanently. Cannot open ever sorry."
            )

    # 4. Correct PIN -> Reset Lockout Status
    c_meta.failed_attempts = 0
    c_meta.lockout_stage = 0
    c_meta.locked_until = None
    db.commit()"""

text = text.replace(old_unlock_start, new_unlock_start)

# 3. Update list_confidential_files payload
old_list_block = """"threat_score": f.threat_score,
            "security_status": f.security_status,
            "created_at": f.created_at.strftime("%d %b %Y %H:%M")
        }
        for f in files
    ]"""

new_list_block = """"threat_score": f.threat_score,
            "security_status": f.security_status,
            "failed_attempts": f.confidential_meta.failed_attempts if f.confidential_meta else 0,
            "lockout_stage": f.confidential_meta.lockout_stage if f.confidential_meta else 0,
            "locked_until": f.confidential_meta.locked_until.strftime("%Y-%m-%d %H:%M:%S") if (f.confidential_meta and f.confidential_meta.locked_until) else None,
            "is_permanently_locked": f.confidential_meta.is_permanently_locked if f.confidential_meta else False,
            "created_at": f.created_at.strftime("%d %b %Y %H:%M")
        }
        for f in files
    ]"""

text = text.replace(old_list_block, new_list_block)

with open("backend/app/api/confidential.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated confidential.py with progressive lockout policy!")
