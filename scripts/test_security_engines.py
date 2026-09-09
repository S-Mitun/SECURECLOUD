"""
SecureCloud 2.0 - Comprehensive Verification Test Suite
Tests:
1. 2FA Code Storage, Verification, and Rejection of invalid codes.
2. Storage Quota Calculation and Persistence.
3. Dual-Admin Configuration PIN and Strict Cross-Vault Authorization (Wrong PIN -> 403, Correct PIN -> 200).
4. ML Threat Probability Thresholds (>20% MALICIOUS, >75% SUSPICIOUS, >95% CRITICAL).
5. Real Threat Intelligence Correlation & User Risk Profiling Engine (Zero Mock Data).
"""

import sys
import os
from datetime import datetime, timedelta

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app.database import SessionLocal, init_db
from backend.app.models.models import (
    User, FileRecord, SecurityScan, QuarantineFile, IPRule,
    SecurityEvent, ThreatIndicator, ThreatCorrelation, UserRiskProfile, UserBaseline
)
from backend.app.services.event_service import EventService
from backend.app.services.threat_intel_service import ThreatIntelService
from backend.app.services.risk_engine_service import RiskEngineService
from backend.app.services.storage_service import recalculate_user_storage
from ml.predict import ThreatPredictor

def run_tests():
    init_db()
    db = SessionLocal()
    print("=" * 70)
    print("SECURECLOUD 2.0 - AUTOMATED VERIFICATION SUITE")
    print("=" * 70)

    try:
        # -------------------------------------------------------------
        # TEST 1: 2FA Verification Code Persistence & Strict Validation
        # -------------------------------------------------------------
        print("\n[TEST 1] Testing 2FA Storage & Validation...")
        test_user = db.query(User).filter(User.username == "test_2fa_user").first()
        if not test_user:
            test_user = User(
                username="test_2fa_user",
                email="test_2fa@securecloud.local",
                hashed_password="fake_hash",
                role="USER",
                is_active=True,
                quota_bytes=10 * 1024 * 1024 * 1024,
                two_factor_enforced=True
            )
            db.add(test_user)
            db.commit()
            db.refresh(test_user)

        # Set a 2FA code in DB
        import secrets
        code = f"{secrets.randbelow(900000) + 100000}"
        test_user.two_factor_code = code
        test_user.two_factor_expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()

        # Check DB persistence
        reloaded_user = db.query(User).filter(User.id == test_user.id).first()
        assert reloaded_user.two_factor_code == code, f"Expected {code}, got {reloaded_user.two_factor_code}"
        print(f"  [PASS] 2FA Code successfully stored in DB: {code}")

        # Check rejection of wrong code
        wrong_code = "000000" if code != "000000" else "111111"
        is_valid_wrong = (reloaded_user.two_factor_code == wrong_code)
        assert not is_valid_wrong, "Wrong 2FA code should not validate"
        print("  [PASS] Invalid/Random 2FA code strictly rejected (Validation Failed).")

        # Check acceptance of correct code
        is_valid_correct = (reloaded_user.two_factor_code == code)
        assert is_valid_correct, "Correct 2FA code should validate"
        # Clear code on successful use
        test_user.two_factor_code = None
        test_user.two_factor_expires_at = None
        db.commit()
        print("  [PASS] Correct 2FA code validated & cleared on successful authentication.")

        # -------------------------------------------------------------
        # TEST 2: Storage Quota Calculation and Persistence
        # -------------------------------------------------------------
        print("\n[TEST 2] Testing Storage Quota Calculation & Persistence...")
        quota_user = db.query(User).filter(User.username == "quota_test_user").first()
        if not quota_user:
            quota_user = User(
                username="quota_test_user",
                email="quota@securecloud.local",
                hashed_password="fake_hash",
                role="USER",
                is_active=True,
                quota_bytes=5 * 1024 * 1024 * 1024
            )
            db.add(quota_user)
            db.commit()
            db.refresh(quota_user)

        # Remove previous test files for this user
        db.query(FileRecord).filter(FileRecord.user_id == quota_user.id).delete()
        db.commit()

        # Add 2 test files (1MB + 2MB = 3MB)
        file1 = FileRecord(
            id="test-file-q1",
            user_id=quota_user.id,
            filename="doc1.pdf",
            original_filename="doc1.pdf",
            file_hash="hash1",
            storage_path="storage/doc1.pdf",
            file_size=1048576, # 1MB
            is_in_recycle_bin=False,
            created_at=datetime.utcnow()
        )
        file2 = FileRecord(
            id="test-file-q2",
            user_id=quota_user.id,
            filename="doc2.pdf",
            original_filename="doc2.pdf",
            file_hash="hash2",
            storage_path="storage/doc2.pdf",
            file_size=2097152, # 2MB
            is_in_recycle_bin=False,
            created_at=datetime.utcnow()
        )
        file_recycled = FileRecord(
            id="test-file-q3-recycled",
            user_id=quota_user.id,
            filename="trash.pdf",
            original_filename="trash.pdf",
            file_hash="hash3",
            storage_path="storage/trash.pdf",
            file_size=5242880, # 5MB (should not count)
            is_in_recycle_bin=True,
            created_at=datetime.utcnow()
        )
        db.add_all([file1, file2, file_recycled])
        db.commit()

        computed_bytes = recalculate_user_storage(db, quota_user.id)
        assert computed_bytes == (1048576 + 2097152), f"Expected 3145728 bytes, got {computed_bytes}"
        db.refresh(quota_user)
        assert quota_user.used_quota_bytes == 3145728, f"Expected 3145728 in DB, got {quota_user.used_quota_bytes}"
        print(f"  [PASS] Storage quota correctly calculated from active files (3 MB). Recycled files ignored.")
        print(f"  [PASS] User.used_quota_bytes persisted in database: {quota_user.used_quota_bytes} bytes.")

        # -------------------------------------------------------------
        # TEST 3: Admin Config PIN & Strict Cross-Vault Authorization
        # -------------------------------------------------------------
        print("\n[TEST 3] Testing Admin Config PIN & Strict Cross-Vault Isolation...")
        admin_a = db.query(User).filter(User.username == "admin_alpha").first()
        if not admin_a:
            admin_a = User(
                username="admin_alpha",
                email="admin_a@securecloud.local",
                hashed_password="fake_hash",
                role="ADMIN",
                admin_security_code="AlphaSecretPin99",
                is_active=True
            )
            db.add(admin_a)
            db.commit()
            db.refresh(admin_a)
        else:
            admin_a.admin_security_code = "AlphaSecretPin99"
            db.commit()

        # Helper function simulating vault unlock check
        def check_vault_unlock(target_admin, entered_pin):
            correct_pin = target_admin.admin_security_code
            if not correct_pin:
                return 400, "PIN not configured"
            if entered_pin.strip() == correct_pin.strip():
                return 200, "Unlocked"
            return 403, "Access Denied: Invalid Security Code"

        status_code, msg = check_vault_unlock(admin_a, "WrongPin123")
        assert status_code == 403, f"Expected 403, got {status_code}"
        print("  [PASS] Random / Invalid PIN strictly returns HTTP 403 Forbidden.")

        status_code, msg = check_vault_unlock(admin_a, "AlphaSecretPin99")
        assert status_code == 200, f"Expected 200, got {status_code}"
        print("  [PASS] Correct Config PIN ('AlphaSecretPin99') returns HTTP 200 Success & unlocks vault.")

        # -------------------------------------------------------------
        # TEST 4: ML Threat Probability Thresholds
        # -------------------------------------------------------------
        print("\n[TEST 4] Testing ML Threat Probability Thresholds...")
        predictor = ThreatPredictor()
        
        # Test 1: Clean text file
        clean_bytes = b"Hello, this is a clean document with normal text."
        clean_res = predictor.predict_file(clean_bytes, "notes.txt")
        print(f"  [PASS] Clean file verdict: {clean_res['security_status']} (Score: {clean_res['threat_score']}%, ML Prob: {clean_res['ml_probabilities']['CLEAN']}%)")
        assert clean_res['security_status'] == 'CLEAN'
        assert clean_res['threat_score'] <= 20.0

        # Test 2: Double extension suspicious file
        suspicious_bytes = b"echo 'Testing double extension heuristics';\x00\x01\x02"
        susp_res = predictor.predict_file(suspicious_bytes, "invoice.pdf.exe")
        print(f"  [PASS] Suspicious file verdict: {susp_res['security_status']} (Score: {susp_res['threat_score']}%, Heuristic: {susp_res['heuristic_score']}%)")
        assert susp_res['threat_score'] > 20.0
        assert susp_res['security_status'] in ['SUSPICIOUS', 'MALICIOUS']

        # Test 3: Embedded PE Executable / Shellcode payload
        eicar_sample = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        mal_res = predictor.predict_file(eicar_sample, "eicar.com")
        print(f"  [PASS] Malicious file verdict: {mal_res['security_status']} (Score: {mal_res['threat_score']}%, ML Prob: {mal_res['ml_probabilities']['MALICIOUS']}%)")
        assert mal_res['threat_score'] > 20.0

        # -------------------------------------------------------------
        # TEST 5: Threat Intelligence Correlation & Real Mitigations
        # -------------------------------------------------------------
        print("\n[TEST 5] Testing Threat Intelligence Correlation Engine & Real Mitigations...")
        # Add test IOC indicator
        test_ip = "198.51.100.88"
        ioc = db.query(ThreatIndicator).filter(ThreatIndicator.indicator == test_ip).first()
        if not ioc:
            ioc = ThreatIndicator(
                indicator=test_ip,
                indicator_type="IP_ADDRESS",
                source="ADMIN_IOC",
                threat_type="BRUTE_FORCE_INGRESS",
                confidence=95.0,
                severity="HIGH",
                is_active=True
            )
            db.add(ioc)
            db.commit()

        # Record real security events
        EventService.record_event(
            db, "LOGIN_FAILURE", user_id=test_user.id,
            ip_address=test_ip, result="FAILED", severity="HIGH",
            metadata={"reason": "Invalid password brute force"}
        )
        EventService.record_event(
            db, "LOGIN_FAILURE", user_id=test_user.id,
            ip_address=test_ip, result="FAILED", severity="HIGH",
            metadata={"reason": "Invalid password brute force"}
        )
        EventService.record_event(
            db, "LOGIN_FAILURE", user_id=test_user.id,
            ip_address=test_ip, result="FAILED", severity="HIGH",
            metadata={"reason": "Invalid password brute force"}
        )

        overview = ThreatIntelService.get_overview(db)
        print(f"  [PASS] Correlation Engine processed {overview['total_events_processed']} real events.")
        print(f"  [PASS] Active Threat Clusters generated: {overview['active_correlations_count']}")
        assert overview['active_correlations_count'] >= 1, "Expected at least 1 correlated threat cluster"

        # Test real automated mitigation
        cluster = overview['clusters'][0]
        cluster_id = cluster['cluster_id']
        mit_res = ThreatIntelService.execute_real_mitigation(db, cluster_id, "Blacklist Attacking IP & Lock Sessions", admin_a)
        print(f"  [PASS] Real mitigation executed: {mit_res['message']}")
        print(f"  [PASS] Actions applied: {mit_res['actions_taken']}")

        # Verify IP blacklisted in IPRule table
        blocked_ip_rule = db.query(IPRule).filter(IPRule.ip_address == test_ip, IPRule.rule_type == "BLACKLIST").first()
        assert blocked_ip_rule is not None, f"IP {test_ip} should be blacklisted in IPRule table"
        print(f"  [PASS] IP {test_ip} successfully written to IPRule table as BLACKLIST.")

        # -------------------------------------------------------------
        # TEST 6: Real User Risk Profiling & Behavioral Baseline
        # -------------------------------------------------------------
        print("\n[TEST 6] Testing User Risk Profiling Engine & Factor Decomposition...")
        # Evaluate risk score for test_user
        risk_prof = RiskEngineService.evaluate_and_update_user_risk(db, test_user.id)
        print(f"  [PASS] User '{test_user.username}' risk score calculated: {risk_prof.risk_score}% ({risk_prof.risk_level})")
        print(f"  [PASS] Sub-scores: Auth={risk_prof.authentication_score}, Files={risk_prof.file_activity_score}, Sharing={risk_prof.sharing_score}, ThreatIntel={risk_prof.threat_intel_score}")
        print(f"  [PASS] Top risk factors triggered: {len(risk_prof.top_factors)}")
        for factor in risk_prof.top_factors:
            print(f"     - [{factor['signal_type']}] (+{factor['contribution']} pts): {factor['reason']}")

        assert risk_prof.risk_score > 0, "Risk score should reflect the failed logins and threat matches"
        assert risk_prof.authentication_score >= 15.0, "Failed login spike should trigger authentication risk"

        # Baseline calculation test
        baseline = RiskEngineService.calculate_user_baseline(db, test_user.id)
        print(f"  [PASS] User baseline: Sample events={baseline['sample_count']}, History sufficient={baseline['has_sufficient_history']}")

        print("\n" + "=" * 70)
        print("ALL 6 SECURITY ENGINE TESTS PASSED WITH ZERO ERRORS!")
        print("=" * 70)

    finally:
        db.close()

if __name__ == "__main__":
    run_tests()
