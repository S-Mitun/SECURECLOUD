with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

old_scan_rec = """    # Save SecurityScan log
    scan_rec = SecurityScan(
        file_id=file_id,
        user_id=target_user.id,
        file_hash=sha256,
        threat_score=scan_result["threat_score"],
        ml_prediction=scan_result["security_status"],
        ml_probabilities=scan_result.get("ml_probabilities") or scan_result.get("probabilities") or {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},
        model_version=scan_result["model_version"],
        heuristic_score=scan_result.get("heuristic_score", 0.0),
        triggered_rules=scan_result.get("triggered_rules", []),
        scanned_at=datetime.utcnow()
    )"""

new_scan_rec = """    # Save SecurityScan log
    threat_score = scan_result.get("threat_score", 0.0)
    security_status = scan_result.get("security_status", "CLEAN")
    final_verdict = scan_result.get("final_verdict") or security_status
    
    scan_rec = SecurityScan(
        file_id=file_id,
        user_id=target_user.id,
        file_hash=sha256,
        threat_score=threat_score,
        final_verdict=final_verdict,
        security_status=security_status,
        ml_prediction=scan_result.get("ml_prediction") or security_status,
        ml_probabilities=scan_result.get("ml_probabilities") or scan_result.get("probabilities") or {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},
        model_version=scan_result.get("model_version", "securecloud-lgbm-v2"),
        heuristic_score=scan_result.get("heuristic_score", 0.0),
        heuristic_verdict=scan_result.get("heuristic_verdict") or security_status,
        triggered_rules=scan_result.get("heuristic_rules") or scan_result.get("triggered_rules", []),
        explanations=scan_result.get("explanations", []),
        scanned_at=datetime.utcnow()
    )"""

text = text.replace(old_scan_rec, new_scan_rec)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated SecurityScan schema mapping in soc.py upload-for-user!")
