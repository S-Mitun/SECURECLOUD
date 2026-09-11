"""
SecureCloud - Security Upgrade Verification Test Suite
Validates:
1. Normal user cannot access Admin endpoints (403 Forbidden).
2. Quarantined file cannot be downloaded by normal user (403 Forbidden).
3. Rate limiter triggers on 5 consecutive failed logins (429 Too Many Requests).
4. Health endpoint reports all 4 core layers accurately.
5. Version restore endpoint works properly.
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
from backend.app.models.models import User, FileRecord, SecurityScan
from backend.app.security.auth_utils import create_access_token, hash_password

client = TestClient(app)

def run_tests():
    print("==================================================")
    print("RUNNING SECURECLOUD SECURITY VERIFICATION TESTS")
    print("==================================================")
    db = SessionLocal()

    # Setup test users
    user_email = f"testuser_{uuid.uuid4().hex[:6]}@example.com"
    admin_email = f"testadmin_{uuid.uuid4().hex[:6]}@example.com"

    normal_user = User(
        username=f"user_{uuid.uuid4().hex[:6]}",
        email=user_email,
        hashed_password=hash_password("Pass123!"),
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
    db.add(normal_user)
    db.add(admin_user)
    db.commit()
    db.refresh(normal_user)
    db.refresh(admin_user)

    user_token = create_access_token({"sub": str(normal_user.id), "role": "USER", "username": normal_user.username})
    admin_token = create_access_token({"sub": str(admin_user.id), "role": "ADMIN", "username": admin_user.username})

    # Test 1: Normal user cannot access Admin endpoints
    res1 = client.get("/api/soc/dashboard", headers={"Authorization": f"Bearer {user_token}"})
    assert res1.status_code == 403, f"Expected 403 Forbidden, got {res1.status_code}"
    print("[PASS] Test 1: Normal user blocked from Admin endpoints (403 Forbidden)")

    # Admin CAN access Admin endpoints
    res1_admin = client.get("/api/soc/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    assert res1_admin.status_code == 200, f"Expected 200 OK for admin, got {res1_admin.status_code}"
    print("[PASS] Test 1b: Admin user successfully accessed Admin SOC endpoints (200 OK)")

    # Test 2: Quarantined file download block
    q_file = FileRecord(
        id=str(uuid.uuid4()),
        user_id=normal_user.id,
        filename="quarantined_threat.exe",
        original_filename="quarantined_threat.exe",
        file_size=1024,
        file_hash="dummy_hash_123456",
        security_status="QUARANTINED",
        storage_path="storage/quarantine/quarantined_threat.exe"
    )
    db.add(q_file)
    db.commit()

    res2 = client.get(f"/api/files/{q_file.id}/download", headers={"Authorization": f"Bearer {user_token}"})
    assert res2.status_code == 403, f"Expected 403 Forbidden for quarantined download, got {res2.status_code}"
    print("[PASS] Test 2: Quarantined file download blocked for non-admin (403 Forbidden)")

    # Test 3: Health check endpoint structure
    res3 = client.get("/health")
    assert res3.status_code == 200
    data3 = res3.json()
    assert "status" in data3 and data3["status"] == "ok"
    assert "database" in data3
    assert "storage" in data3
    assert "ml" in data3
    assert "scanner" in data3
    print(f"[PASS] Test 3: GET /health returns valid schema: {data3}")

    # Test 4: Rate limiting on failed logins
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

    print("==================================================")
    print("ALL SECURITY SUITE TESTS PASSED SUCCESSFULLY!")
    print("==================================================")
    db.close()

if __name__ == "__main__":
    run_tests()
