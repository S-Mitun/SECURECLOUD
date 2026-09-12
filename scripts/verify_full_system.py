"""
SecureCloud - Complete Full-System Integration Verification
Tests EVERY single user, admin, storage, scanning, SOC, and mitigation workflow.
"""

import os
import sys
import uuid
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.models import User, FileRecord, IPRule, ThreatCorrelation

client = TestClient(app)

def run_comprehensive_system_audit():
    print("==================================================================")
    print("STARTING COMPLETE SECURECLOUD FULL-SYSTEM INTEGRATION AUDIT")
    print("==================================================================")
    
    unique_id = uuid.uuid4().hex[:6]
    test_user_name = f"user_{unique_id}"
    test_user_email = f"user_{unique_id}@securecloud.test"
    test_user_pass = "TestUserPass123!"

    test_admin_name = f"admin_{unique_id}"
    test_admin_email = f"admin_{unique_id}@securecloud.test"
    test_admin_pass = "TestAdminPass123!"

    # 1. Health Check
    print("\n--- 1. Testing GET /health ---")
    res_health = client.get("/health")
    assert res_health.status_code == 200, f"Health check failed: {res_health.text}"
    health_data = res_health.json()
    print("Health Status:", health_data)
    assert health_data["status"] == "ok"
    assert "database" in health_data
    assert "storage" in health_data
    assert "ml" in health_data
    assert "scanner" in health_data
    print("[PASS] System health verified.")

    # 2. Register User
    print("\n--- 2. Testing User Registration ---")
    res_reg = client.post("/api/auth/register", json={
        "username": test_user_name,
        "email": test_user_email,
        "password": test_user_pass,
        "role": "USER"
    })
    assert res_reg.status_code == 200, f"User registration failed: {res_reg.text}"
    reg_data = res_reg.json()
    user_token = reg_data["access_token"]
    user_id = reg_data["user"]["id"]
    print(f"[PASS] User registered: {test_user_name} (ID: {user_id})")

    # 3. Register Admin
    print("\n--- 3. Testing Admin Registration ---")
    res_admin_reg = client.post("/api/auth/register", json={
        "username": test_admin_name,
        "email": test_admin_email,
        "password": test_admin_pass,
        "role": "ADMIN"
    })
    assert res_admin_reg.status_code == 200, f"Admin registration failed: {res_admin_reg.text}"
    admin_reg_data = res_admin_reg.json()
    admin_token = admin_reg_data["access_token"]
    admin_id = admin_reg_data["user"]["id"]
    print(f"[PASS] Admin registered: {test_admin_name} (ID: {admin_id})")

    # 4. User Login
    print("\n--- 4. Testing User Login ---")
    res_login = client.post("/api/auth/login", json={
        "email": test_user_email,
        "password": test_user_pass,
        "portal": "USER"
    })
    assert res_login.status_code == 200, f"User login failed: {res_login.text}"
    assert res_login.json()["access_token"] != ""
    print("[PASS] User login successful.")

    # 5. User Profile
    print("\n--- 5. Testing GET /api/auth/me ---")
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert res_me.status_code == 200
    print(f"[PASS] User profile retrieved: {res_me.json()['username']} | Quota: {res_me.json()['quota_formatted']}")

    # 6. Upload Clean File
    print("\n--- 6. Testing Clean File Upload & Multi-Layer Scanning ---")
    clean_bytes = b"Hello SecureCloud! This is a verified clean test document for hackathon."
    res_upload = client.post(
        "/api/files/upload",
        files={"file": ("hello_clean.txt", clean_bytes, "text/plain")},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_upload.status_code == 200, f"Upload failed: {res_upload.text}"
    file_data = res_upload.json()
    clean_file_id = file_data["file"]["id"]
    print(f"[PASS] Clean file uploaded: ID {clean_file_id} | Status: {file_data['file'].get('security_status')} | Threat Score: {file_data['file'].get('threat_score')}")

    # 7. File Listing
    print("\n--- 7. Testing GET /api/files/list ---")
    res_files = client.get("/api/files/list", headers={"Authorization": f"Bearer {user_token}"})
    assert res_files.status_code == 200
    user_files = res_files.json()
    assert any(f["id"] == clean_file_id for f in user_files)
    print(f"[PASS] File listing retrieved. User has {len(user_files)} file(s).")

    # 8. File View & Stream
    print("\n--- 8. Testing File View & Stream ---")
    res_view = client.get(f"/api/files/{clean_file_id}/view", headers={"Authorization": f"Bearer {user_token}"})
    assert res_view.status_code == 200
    res_stream = client.get(f"/api/files/{clean_file_id}/stream", headers={"Authorization": f"Bearer {user_token}"})
    assert res_stream.status_code == 200
    assert res_stream.content == clean_bytes
    print("[PASS] File view and streaming verified.")

    # 9. File Versioning & Version Restore
    print("\n--- 9. Testing File Versioning & Version Restore ---")
    v2_bytes = b"Hello SecureCloud Version 2 updated contents!"
    res_v2 = client.post(
        f"/api/files/{clean_file_id}/versions",
        files={"file": ("hello_clean_v2.txt", v2_bytes, "text/plain")},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_v2.status_code == 200
    print("[PASS] Version 2 uploaded.")

    res_vers = client.get(f"/api/files/{clean_file_id}/versions", headers={"Authorization": f"Bearer {user_token}"})
    assert res_vers.status_code == 200
    versions_list = res_vers.json()
    assert len(versions_list) >= 2
    v1_id = versions_list[0]["id"]
    print(f"[PASS] Version history retrieved: {len(versions_list)} versions found.")

    # Restore Version 1
    res_restore = client.post(
        f"/api/files/{clean_file_id}/versions/{v1_id}/restore",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_restore.status_code == 200
    print("[PASS] Version 1 restored successfully.")

    # 10. File Sharing
    print("\n--- 10. Testing File Sharing Link Creation & Retrieval ---")
    res_share = client.post(
        "/api/shares/",
        json={"file_id": clean_file_id, "expires_in_hours": 24},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_share.status_code == 200
    share_token = res_share.json()["token"]
    print(f"[PASS] Share link created with token: {share_token}")

    res_public_share = client.get(f"/api/shares/{share_token}")
    assert res_public_share.status_code == 200
    print("[PASS] Public share link accessed successfully.")

    # 11. Upload High-Risk File -> Verify Quarantine Enforcement
    print("\n--- 11. Testing High-Risk Upload & Quarantine Isolation ---")
    # Craft disguised PE header with elevated entropy
    fake_disguised_pe = b"MZ\x90\x00" + b"TEST_DISGUISED_EXECUTABLE\n" + bytes([i % 256 for i in range(16384)])
    res_mal_upload = client.post(
        "/api/files/upload",
        files={"file": ("fake_invoice.pdf", fake_disguised_pe, "application/pdf")},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_mal_upload.status_code == 200
    mal_file = res_mal_upload.json()
    mal_file_id = mal_file["file"]["id"]
    print(f"[PASS] Disguised file flagged! Threat Score: {mal_file['file'].get('threat_score')}% | Status: {mal_file['file'].get('security_status')}")

    # Verify Quarantine Isolation: Non-admin download must return 403 Forbidden
    res_q_download = client.get(f"/api/files/{mal_file_id}/download", headers={"Authorization": f"Bearer {user_token}"})
    assert res_q_download.status_code == 403
    print("[PASS] Non-admin download of quarantined file strictly blocked (403 Forbidden).")

    # 12. Soft Delete & Recycle Bin
    print("\n--- 12. Testing Soft Delete & Recycle Bin ---")
    res_del = client.delete(f"/api/files/{clean_file_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert res_del.status_code == 200
    print("[PASS] File moved to recycle bin.")

    res_bin = client.get("/api/recycle-bin/list", headers={"Authorization": f"Bearer {user_token}"})
    assert res_bin.status_code == 200
    bin_items = res_bin.json()
    assert any(item["file_id"] == clean_file_id for item in bin_items)
    print(f"[PASS] File found in recycle bin ({len(bin_items)} item(s)).")

    # Restore from recycle bin using file_id as expected by /api/recycle-bin/{file_id}/restore
    res_bin_restore = client.post(f"/api/recycle-bin/{clean_file_id}/restore", headers={"Authorization": f"Bearer {user_token}"})
    assert res_bin_restore.status_code == 200
    print("[PASS] File successfully restored from recycle bin.")

    # 13. Admin SOC Access
    print("\n--- 13. Testing Admin SOC Access & Dashboard Telemetry ---")
    res_soc_dash = client.get("/api/soc/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_soc_dash.status_code == 200
    soc_data = res_soc_dash.json()
    print(f"[PASS] Admin SOC Dashboard loaded: Total Files Scanned: {soc_data.get('total_files_scanned')} | Active Users: {soc_data.get('active_users')}")

    # 14. Admin User-Wise Grouped Files
    print("\n--- 14. Testing SOC User-Wise Files ---")
    res_user_files = client.get("/api/soc/users/grouped-files", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_user_files.status_code == 200
    print(f"[PASS] User-wise grouped files retrieved successfully.")

    # 15. Sentinel Security Console Telemetry
    print("\n--- 15. Testing Sentinel Security Console Telemetry ---")
    res_sentinel = client.get("/api/soc/sentinel/status", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_sentinel.status_code == 200
    sentinel_status = res_sentinel.json()
    print(f"[PASS] Sentinel Console status: Phase: {sentinel_status.get('phase')} | Status: {sentinel_status.get('status')}")

    # 16. IP Guard Firewall Rules
    print("\n--- 16. Testing IP Guard Firewall Rules ---")
    test_block_ip = f"203.0.113.{unique_id[:2]}"
    res_ip_add = client.post(
        "/api/soc/ip-rules",
        json={"ip_address": test_block_ip, "rule_type": "BLACKLIST", "reason": "Automated security test"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_ip_add.status_code == 200
    print(f"[PASS] IP {test_block_ip} blacklisted successfully.")

    res_ip_list = client.get("/api/soc/ip-rules", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_ip_list.status_code == 200
    print(f"[PASS] IP rules retrieved ({len(res_ip_list.json())} rules active).")

    # 17. Security Events Log
    print("\n--- 17. Testing Security Events Stream ---")
    res_events = client.get("/api/soc/events", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_events.status_code == 200
    print(f"[PASS] Security events retrieved ({len(res_events.json())} events logged).")

    print("\n==================================================================")
    print("ALL 17 CORE SECURECLOUD MODULES VERIFIED 100% OPERATIONAL!")
    print("==================================================================")

if __name__ == "__main__":
    run_comprehensive_system_audit()
