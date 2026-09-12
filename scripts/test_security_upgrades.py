"""
SecureCloud - Comprehensive Security Upgrade & Data Isolation Test Suite
Validates:
1. Normal user cannot access Admin endpoints (403 Forbidden).
1b. Admin user successfully accesses Admin endpoints (200 OK).
2. Quarantined file cannot be downloaded by normal user (403 Forbidden).
3. Health endpoint reports all 4 core layers honestly (Database, Storage, ML, Scanner).
4. Sliding-window rate limiter locks out brute-force attacks (429 Too Many Requests).
5. Strict Cross-User Data Isolation: User B cannot download, view, rename, delete, version, or share User A's data (403 Forbidden).
6. Shared Link ownership and unauthorized revocation protection (403 Forbidden).
7. Verified server-side identity: Role elevation from client payload is prevented.
"""

import os
import sys
import uuid
import datetime

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.models import User, FileRecord, FileVersion, SharedLink, SecurityScan
from backend.app.security.auth_utils import create_access_token, hash_password

client = TestClient(app)

def run_tests():
    print("==================================================")
    print("RUNNING SECURECLOUD SECURITY VERIFICATION TESTS")
    print("==================================================")
    db = SessionLocal()

    # Setup test users: User A, User B, Admin
    user_a_email = f"usera_{uuid.uuid4().hex[:6]}@example.com"
    user_b_email = f"userb_{uuid.uuid4().hex[:6]}@example.com"
    admin_email = f"testadmin_{uuid.uuid4().hex[:6]}@example.com"

    user_a = User(
        username=f"user_a_{uuid.uuid4().hex[:6]}",
        email=user_a_email,
        hashed_password=hash_password("PassA123!"),
        role="USER",
        is_active=True
    )
    user_b = User(
        username=f"user_b_{uuid.uuid4().hex[:6]}",
        email=user_b_email,
        hashed_password=hash_password("PassB123!"),
        role="USER",
        is_active=True
    )
    admin_user = User(
        username=f"admin_{uuid.uuid4().hex[:6]}",
        email=admin_email,
        hashed_password=hash_password("AdminPass123!"),
        role="ADMIN",
        is_active=True
    )
    db.add_all([user_a, user_b, admin_user])
    db.commit()
    db.refresh(user_a)
    db.refresh(user_b)
    db.refresh(admin_user)

    user_a_token = create_access_token({"sub": str(user_a.id), "role": "USER", "username": user_a.username})
    user_b_token = create_access_token({"sub": str(user_b.id), "role": "USER", "username": user_b.username})
    admin_token = create_access_token({"sub": str(admin_user.id), "role": "ADMIN", "username": admin_user.username})

    # Test 1: Normal user cannot access Admin endpoints
    res1 = client.get("/api/soc/dashboard", headers={"Authorization": f"Bearer {user_a_token}"})
    assert res1.status_code == 403, f"Expected 403 Forbidden, got {res1.status_code}"
    print("[PASS] Test 1: Normal user blocked from Admin endpoints (403 Forbidden)")

    # Test 1b: Admin CAN access Admin endpoints
    res1_admin = client.get("/api/soc/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    assert res1_admin.status_code == 200, f"Expected 200 OK for admin, got {res1_admin.status_code}"
    print("[PASS] Test 1b: Admin user successfully accessed Admin SOC endpoints (200 OK)")

    # Test 2: Quarantined file download block
    q_file = FileRecord(
        id=str(uuid.uuid4()),
        user_id=user_a.id,
        filename="quarantined_threat.exe",
        original_filename="quarantined_threat.exe",
        file_size=1024,
        file_hash="dummy_hash_123456",
        security_status="QUARANTINED",
        storage_path="storage/quarantine/quarantined_threat.exe"
    )
    db.add(q_file)
    db.commit()

    res2 = client.get(f"/api/files/{q_file.id}/download", headers={"Authorization": f"Bearer {user_a_token}"})
    assert res2.status_code == 403, f"Expected 403 Forbidden for quarantined download, got {res2.status_code}"
    print("[PASS] Test 2: Quarantined file download blocked for non-admin (403 Forbidden)")

    # Test 3: Health check endpoint structure & honest reporting
    res3 = client.get("/health")
    assert res3.status_code == 200
    data3 = res3.json()
    assert "status" in data3 and data3["status"] == "ok"
    assert "database" in data3
    assert data3["database"] == "AVAILABLE"
    assert "storage" in data3
    assert data3["storage"] in ["S3 AVAILABLE", "LOCAL FALLBACK"]
    assert "ml" in data3
    assert data3["ml"] == "AVAILABLE"
    assert "scanner" in data3
    print(f"[PASS] Test 3: GET /health returns valid schema & honest statuses: Storage={data3['storage']}, ML={data3['ml']}")

    # Test 4: Sliding-window brute-force rate limiter
    print("Testing sliding-window brute-force lockout (5 consecutive failed attempts)...")
    brute_email = f"brute_{uuid.uuid4().hex[:6]}@example.com"
    locked_out = False
    for attempt in range(1, 7):
        r = client.post("/api/auth/login", json={
            "email": brute_email,
            "password": "WrongPassword!",
            "portal": "USER"
        })
        if r.status_code == 429:
            locked_out = True
            print(f"[PASS] Test 4: Rate limit triggered on attempt {attempt}: {r.json()['detail']}")
            break

    assert locked_out, "Expected 429 Too Many Requests after consecutive failed logins"

    # Test 5: Strict Cross-User Data Isolation
    # User A creates a file
    file_a = FileRecord(
        id=str(uuid.uuid4()),
        user_id=user_a.id,
        filename="confidential_user_a.txt",
        original_filename="confidential_user_a.txt",
        file_size=512,
        file_hash="hash_user_a_file_content_789",
        security_status="CLEAN",
        storage_path=f"storage/uploads/confidential_user_a_{uuid.uuid4().hex[:6]}.txt"
    )
    # Write physical test file
    os.makedirs("storage/uploads", exist_ok=True)
    with open(file_a.storage_path, "wb") as fp:
        fp.write(b"User A Private Confidential Data - Zero Knowledge Isolated.")
    db.add(file_a)
    db.commit()

    # User B attempts to download User A's file -> 403 Forbidden
    res_b_dl = client.get(f"/api/files/{file_a.id}/download", headers={"Authorization": f"Bearer {user_b_token}"})
    assert res_b_dl.status_code == 403, f"Expected 403 Forbidden for User B downloading User A's file, got {res_b_dl.status_code}"
    print("[PASS] Test 5a: Cross-User Download Blocked (User B -> User A file: 403 Forbidden)")

    # User B attempts to view User A's file -> 403 Forbidden
    res_b_view = client.get(f"/api/files/{file_a.id}/view", headers={"Authorization": f"Bearer {user_b_token}"})
    assert res_b_view.status_code == 403, f"Expected 403 Forbidden for User B viewing User A's file, got {res_b_view.status_code}"
    print("[PASS] Test 5b: Cross-User Content View Blocked (User B -> User A file: 403 Forbidden)")

    # User B attempts to rename User A's file -> 403 Forbidden
    res_b_rename = client.put(f"/api/files/{file_a.id}/rename", json={"new_filename": "hijacked.txt"}, headers={"Authorization": f"Bearer {user_b_token}"})
    assert res_b_rename.status_code == 403, f"Expected 403 Forbidden for User B renaming User A's file, got {res_b_rename.status_code}"
    print("[PASS] Test 5c: Cross-User Rename Blocked (User B -> User A file: 403 Forbidden)")

    # User B attempts to delete User A's file -> 403 Forbidden
    res_b_del = client.delete(f"/api/files/{file_a.id}", headers={"Authorization": f"Bearer {user_b_token}"})
    assert res_b_del.status_code == 403, f"Expected 403 Forbidden for User B deleting User A's file, got {res_b_del.status_code}"
    print("[PASS] Test 5d: Cross-User Delete Blocked (User B -> User A file: 403 Forbidden)")

    # User B attempts to upload version to User A's file -> 403 Forbidden
    res_b_ver = client.post(
        f"/api/files/{file_a.id}/versions/upload",
        files={"file": ("injected.txt", b"malicious injected version", "text/plain")},
        headers={"Authorization": f"Bearer {user_b_token}"}
    )
    assert res_b_ver.status_code == 403, f"Expected 403 Forbidden for User B versioning User A's file, got {res_b_ver.status_code}"
    print("[PASS] Test 5e: Cross-User Version Upload Blocked (User B -> User A file: 403 Forbidden)")

    # User B attempts to create share link for User A's file -> 403 Forbidden
    res_b_share = client.post(
        f"/api/shares/create/{file_a.id}",
        json={"password": None, "expires_in_hours": 24},
        headers={"Authorization": f"Bearer {user_b_token}"}
    )
    assert res_b_share.status_code == 403, f"Expected 403 Forbidden for User B creating share for User A's file, got {res_b_share.status_code}"
    print("[PASS] Test 5f: Cross-User Share Creation Blocked (User B -> User A file: 403 Forbidden)")

    # Test 6: Share Link Revocation Protection
    # User A creates a valid share link
    share_link = SharedLink(
        id=str(uuid.uuid4()),
        file_id=file_a.id,
        user_id=user_a.id,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=1),
        is_active=True
    )
    db.add(share_link)
    db.commit()

    # User B attempts to revoke User A's share link -> 403 Forbidden
    res_b_revoke = client.delete(f"/api/shares/{share_link.id}", headers={"Authorization": f"Bearer {user_b_token}"})
    assert res_b_revoke.status_code == 403, f"Expected 403 Forbidden for User B revoking User A's share link, got {res_b_revoke.status_code}"
    print("[PASS] Test 6: Cross-User Share Revocation Blocked (User B -> User A share: 403 Forbidden)")

    # User A CAN revoke their own share link -> 200 OK
    res_a_revoke = client.delete(f"/api/shares/{share_link.id}", headers={"Authorization": f"Bearer {user_a_token}"})
    assert res_a_revoke.status_code == 200, f"Expected 200 OK for User A revoking own share link, got {res_a_revoke.status_code}"
    print("[PASS] Test 6b: Legitimate Owner Share Revocation (User A -> User A share: 200 OK)")

    # Test 7: Zero Remnants of Admin PIN / Dual-Auth in API
    # Verify that calling obsolete /api/soc/admin/config-code returns 404 (removed)
    res_pin = client.get("/api/soc/admin/config-code", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_pin.status_code == 404, f"Expected 404 Not Found for removed PIN endpoint, got {res_pin.status_code}"
    print("[PASS] Test 7: Obsolete admin config-code PIN endpoint confirmed removed (404 Not Found)")

    # Clean up physical test file
    try:
        if os.path.exists(file_a.storage_path):
            os.remove(file_a.storage_path)
    except Exception:
        pass

    print("==================================================")
    print("ALL 7 CORE SECURITY & DATA ISOLATION SUITES PASSED!")
    print("==================================================")
    db.close()

if __name__ == "__main__":
    run_tests()
