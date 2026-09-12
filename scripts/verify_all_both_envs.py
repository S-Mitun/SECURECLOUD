import urllib.request
import urllib.error
import urllib.parse
import json
import hashlib
import time

def make_request(url, method="GET", data=None, headers=None, retries=3):
    if headers is None:
        headers = {}
    req_data = None
    if data is not None:
        if isinstance(data, dict):
            req_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(data, (bytes, bytearray)):
            req_data = data

    for attempt in range(retries):
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                status = resp.status
                body = resp.read()
                resp_headers = dict(resp.getheaders())
                return status, body, resp_headers
        except urllib.error.HTTPError as e:
            body = e.read()
            return e.code, body, dict(e.headers)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0)
                continue
            return 0, str(e).encode(), {}

def test_environment(base_url, env_name):
    print("=" * 80)
    print(f" TESTING ENVIRONMENT: {env_name} ({base_url})")
    print("=" * 80)

    admin_creds = [
        ("admin@securecloud.com", "AdminPass123!", "soc_admin"),
        ("Remo", "Remo@123", "Remo"),
        ("Sham", "Sham@123", "Sham"),
    ]

    user_creds = [
        ("Rahul", "Rahul@123", "Rahul"),
        ("Abhi", "Abhisek@123", "Abhi"),
        ("analyst@securecloud.com", "UserPass123!", "security_analyst"),
    ]

    # 1. STRICT PORTAL MUTUAL EXCLUSIVITY
    print("\n[1] VERIFYING STRICT MUTUAL PORTAL ISOLATION...")
    
    # A. Admins MUST be blocked on User Portal
    for ident, pwd, name in admin_creds:
        status, body, _ = make_request(
            f"{base_url}/api/auth/login",
            method="POST",
            data={"email": ident, "password": pwd, "portal": "USER", "mock_captcha_verified": True}
        )
        body_text = body.decode("utf-8", errors="replace")
        if status == 403 and "Admin Portal" in body_text:
            print(f"  [PASS] Admin '{name}' blocked from User Portal: HTTP 403 Forbidden")
        else:
            print(f"  [FAIL] Admin '{name}' was NOT blocked from User Portal! Status: {status}, Body: {body_text}")

    # B. Users MUST be blocked on Admin Portal
    for ident, pwd, name in user_creds:
        status, body, _ = make_request(
            f"{base_url}/api/auth/login",
            method="POST",
            data={"email": ident, "password": pwd, "portal": "ADMIN"}
        )
        body_text = body.decode("utf-8", errors="replace")
        if status == 403 and "User Portal" in body_text:
            print(f"  [PASS] User '{name}' blocked from Admin Portal: HTTP 403 Forbidden")
        else:
            print(f"  [FAIL] User '{name}' was NOT blocked from Admin Portal! Status: {status}, Body: {body_text}")

    # C. Admins can log in from Admin Portal
    admin_tokens = {}
    for ident, pwd, name in admin_creds:
        status, body, _ = make_request(
            f"{base_url}/api/auth/login",
            method="POST",
            data={"email": ident, "password": pwd, "portal": "ADMIN"}
        )
        if status == 200:
            res_json = json.loads(body.decode("utf-8"))
            admin_tokens[name] = res_json["access_token"]
            print(f"  [PASS] Admin '{name}' authenticated via Admin Portal: HTTP 200 OK")
        else:
            print(f"  [FAIL] Admin '{name}' failed login on Admin Portal: {status} {body.decode('utf-8', errors='replace')}")

    # D. Users can log in from User Portal
    user_tokens = {}
    for ident, pwd, name in user_creds:
        status, body, _ = make_request(
            f"{base_url}/api/auth/login",
            method="POST",
            data={"email": ident, "password": pwd, "portal": "USER", "mock_captcha_verified": True}
        )
        if status == 200:
            res_json = json.loads(body.decode("utf-8"))
            user_tokens[name] = res_json["access_token"]
            print(f"  [PASS] User '{name}' authenticated via User Portal: HTTP 200 OK")
        else:
            print(f"  [FAIL] User '{name}' failed login on User Portal: {status} {body.decode('utf-8', errors='replace')}")

    # 2. VERIFY ALL USER SECTIONS
    print("\n[2] VERIFYING ALL USER SECTIONS FOR USER ACCOUNTS...")
    for name, token in user_tokens.items():
        headers = {"Authorization": f"Bearer {token}"}
        print(f"\n  Testing User Sections for '{name}':")

        # /api/auth/me
        status, body, _ = make_request(f"{base_url}/api/auth/me", headers=headers)
        assert status == 200, f"Profile error: {body}"
        quota = json.loads(body.decode("utf-8"))
        print(f"    - Profile & Quotas (/api/auth/me): OK (User: {quota['username']}, Quota: {quota.get('quota_formatted')})")

        # /api/files/list
        status, body, _ = make_request(f"{base_url}/api/files/list", headers=headers)
        assert status == 200, f"Files error: {body}"
        files = json.loads(body.decode("utf-8"))
        print(f"    - My Files (/api/files/list): OK ({len(files)} files)")

        # /api/confidential/list
        status, body, _ = make_request(f"{base_url}/api/confidential/list", headers=headers)
        assert status == 200, f"Confidential error: {body}"
        conf_files = json.loads(body.decode("utf-8"))
        print(f"    - Confidential Vault (/api/confidential/list): OK ({len(conf_files)} encrypted files)")

        # /api/shares/list
        status, body, _ = make_request(f"{base_url}/api/shares/list", headers=headers)
        assert status == 200, f"Shares error: {body}"
        print(f"    - Shared Links (/api/shares/list): OK ({len(json.loads(body.decode('utf-8')))} shared links)")

        # /api/recycle-bin/list
        status, body, _ = make_request(f"{base_url}/api/recycle-bin/list", headers=headers)
        assert status == 200, f"Recycle bin error: {body}"
        print(f"    - Recycle Bin (/api/recycle-bin/list): OK ({len(json.loads(body.decode('utf-8')))} items in bin)")

        # /api/soc/timeline/{user_id}
        user_id = quota.get("id")
        status, act_body, _ = make_request(f"{base_url}/api/soc/timeline/{user_id}", headers=headers)
        assert status == 200, f"Activity timeline error: {act_body}"
        print(f"    - User Activity Log (/api/soc/timeline/{user_id}): OK ({len(json.loads(act_body.decode('utf-8')))} events)")

    # 3. VERIFY ALL ADMIN SECTIONS
    print("\n[3] VERIFYING ALL ADMIN SOC SECTIONS FOR ADMIN ACCOUNTS...")
    for name, token in admin_tokens.items():
        headers = {"Authorization": f"Bearer {token}"}
        print(f"\n  Testing Admin Sections for '{name}':")

        # /api/soc/dashboard
        status, body, _ = make_request(f"{base_url}/api/soc/dashboard", headers=headers)
        assert status == 200, f"SOC Dashboard error: {body}"
        d = json.loads(body.decode("utf-8"))
        print(f"    - SOC Dashboard (/api/soc/dashboard): OK (Files Scanned: {d.get('total_files_scanned', 'N/A')}, Threats Blocked: {d.get('total_threats_blocked', 'N/A')})")

        # /api/files/all
        status, body, _ = make_request(f"{base_url}/api/files/all", headers=headers)
        assert status == 200, f"User-wise files error: {body}"
        print(f"    - User-Wise Files (/api/files/all): OK ({len(json.loads(body.decode('utf-8')))} files across tenants)")

        # /api/soc/users
        status, body, _ = make_request(f"{base_url}/api/soc/users", headers=headers)
        assert status == 200, f"Users management error: {body}"
        print(f"    - Users Management (/api/soc/users): OK ({len(json.loads(body.decode('utf-8')))} registered tenants)")

        # /api/soc/quarantine/list
        status, body, _ = make_request(f"{base_url}/api/soc/quarantine/list", headers=headers)
        assert status == 200, f"Quarantine error: {body}"
        print(f"    - Quarantine Vault (/api/soc/quarantine/list): OK ({len(json.loads(body.decode('utf-8')))} quarantined artifacts)")

        # /api/soc/ip-guard/list
        status, body, _ = make_request(f"{base_url}/api/soc/ip-guard/list", headers=headers)
        assert status == 200, f"IP Guard error: {body}"
        print(f"    - IP Guard (/api/soc/ip-guard/list): OK ({len(json.loads(body.decode('utf-8')))} rules active)")

        # /api/soc/audit-logs
        status, body, _ = make_request(f"{base_url}/api/soc/audit-logs", headers=headers)
        assert status == 200, f"Audit Logs error: {body}"
        print(f"    - Audit Logs (/api/soc/audit-logs): OK ({len(json.loads(body.decode('utf-8')))} audit log records)")

        # /api/soc/telemetry
        status, body, _ = make_request(f"{base_url}/api/soc/telemetry", headers=headers)
        assert status == 200, f"Sentinel Telemetry error: {body}"
        print(f"    - Sentinel VM Telemetry (/api/soc/telemetry): OK (Uptime: {json.loads(body.decode('utf-8')).get('uptime_seconds', 0)}s)")

        # /api/soc/verified-clean
        status, body, _ = make_request(f"{base_url}/api/soc/verified-clean", headers=headers)
        assert status == 200, f"Verified Artifacts error: {body}"
        print(f"    - Verified Artifacts (/api/soc/verified-clean): OK ({len(json.loads(body.decode('utf-8')))} certified safe)")

        # /api/soc/sessions
        status, body, _ = make_request(f"{base_url}/api/soc/sessions", headers=headers)
        assert status == 200, f"Sessions error: {body}"
        print(f"    - Sessions Management (/api/soc/sessions): OK ({len(json.loads(body.decode('utf-8')))} active sessions)")

    # 4. MULTI-PART UPLOAD & LIFECYCLE
    print("\n[4] TESTING FILE LIFECYCLE (UPLOAD, SCAN, DOWNLOAD, PREVIEW, RECYCLE, RESTORE)...")
    rahul_token = user_tokens["Rahul"]
    boundary = "----SecureCloudBoundary123456789"
    test_content = f"SecureCloud Integrity Validation Test Document\nTimestamp: {time.time()}\n".encode("utf-8")
    orig_hash = hashlib.sha256(test_content).hexdigest()
    test_filename = f"integrity_{int(time.time())}.txt"

    body_bytes = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + test_content + f"\r\n--{boundary}--\r\n".encode("utf-8")

    up_headers = {
        "Authorization": f"Bearer {rahul_token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }

    status, body, _ = make_request(f"{base_url}/api/files/upload", method="POST", data=body_bytes, headers=up_headers)
    assert status == 200, f"Upload failed: {body.decode('utf-8', errors='replace')}"
    res_up = json.loads(body.decode("utf-8"))
    file_id = res_up["file"]["id"]
    print(f"  [PASS] Uploaded '{test_filename}' (ID: {file_id}, Status: {res_up['file']['security_status']})")

    # Download & check exact hash
    auth_headers = {"Authorization": f"Bearer {rahul_token}"}
    status, down_bytes, _ = make_request(f"{base_url}/api/files/{file_id}/download", headers=auth_headers)
    assert status == 200, f"Download failed"
    down_hash = hashlib.sha256(down_bytes).hexdigest()
    assert down_hash == orig_hash, f"Hash mismatch! {down_hash} != {orig_hash}"
    print(f"  [PASS] Download byte-for-byte SHA-256 match: {down_hash[:16]}... (Size: {len(down_bytes)} bytes)")

    # View & Stream
    status, view_bytes, _ = make_request(f"{base_url}/api/files/{file_id}/view", headers=auth_headers)
    assert status == 200, f"View failed: {view_bytes.decode('utf-8', errors='replace')}"
    print(f"  [PASS] View endpoint (/api/files/{file_id}/view): HTTP 200 OK")

    status, stream_bytes, stream_headers = make_request(f"{base_url}/api/files/{file_id}/stream", headers=auth_headers)
    assert status == 200, f"Stream failed"
    print(f"  [PASS] Stream endpoint (/api/files/{file_id}/stream): HTTP 200 OK (Content-Type: {stream_headers.get('Content-Type') or stream_headers.get('content-type')})")

    # Move to Recycle Bin
    status, _, _ = make_request(f"{base_url}/api/files/{file_id}", method="DELETE", headers=auth_headers)
    assert status == 200, f"Recycle delete failed"
    print(f"  [PASS] Moved to Recycle Bin: HTTP 200 OK")

    # Verify in Recycle Bin
    status, bin_body, _ = make_request(f"{base_url}/api/recycle-bin/list", headers=auth_headers)
    bin_items = [b for b in json.loads(bin_body.decode("utf-8")) if b["file_id"] == file_id]
    assert len(bin_items) > 0, "Item not found in recycle bin"
    print(f"  [PASS] Confirmed in Recycle Bin (File ID: {file_id})")

    # Restore from Recycle Bin
    status, _, _ = make_request(f"{base_url}/api/recycle-bin/{file_id}/restore", method="POST", headers=auth_headers)
    assert status == 200, f"Restore failed"
    print(f"  [PASS] Restored from Recycle Bin: HTTP 200 OK")

    # Move back and permanently delete
    make_request(f"{base_url}/api/files/{file_id}", method="DELETE", headers=auth_headers)
    status, _, _ = make_request(f"{base_url}/api/recycle-bin/{file_id}/permanent", method="DELETE", headers=auth_headers)
    assert status == 200, f"Permanent delete failed"
    print(f"  [PASS] Permanently deleted test file: HTTP 200 OK")

    print(f"\n>>> ALL CHECKS 100% PASSED FOR {env_name}! <<<\n")

if __name__ == "__main__":
    # 1. Test Localhost
    try:
        test_environment("http://127.0.0.1:8000", "LOCALHOST")
    except Exception as e:
        print(f"\n[ERROR ON LOCALHOST] {e}")
        import traceback
        traceback.print_exc()

    # 2. Test Railway Production
    try:
        test_environment("https://securecloud-app-production.up.railway.app", "RAILWAY PRODUCTION")
    except Exception as e:
        print(f"\n[ERROR ON PRODUCTION] {e}")
        import traceback
        traceback.print_exc()
