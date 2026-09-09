import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def run_acceptance_suite():
    print("==================================================================")
    print(">>> SECURECLOUD - ACCEPTANCE TEST SUITE")
    print("==================================================================")

    # 1. Admin Login
    res = client.post("/api/auth/login", json={
        "email": "admin@securecloud.com",
        "password": "AdminPass123!",
        "portal": "ADMIN"
    })
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    admin_token = res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("[PASS] 1. Admin Authentication (soc_admin)")

    # 2. User Login
    res_u = client.post("/api/auth/login", json={
        "email": "analyst@securecloud.com",
        "password": "UserPass123!",
        "portal": "USER"
    })
    assert res_u.status_code == 200, f"User login failed: {res_u.text}"
    user_token = res_u.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}
    print("[PASS] 2. User Authentication (security_analyst)")

    # 3. User Grouped Files & Synchronized Risk Scores
    res_grouped = client.get("/api/soc/users/grouped-files", headers=admin_headers)
    assert res_grouped.status_code == 200, f"Grouped files failed: {res_grouped.text}"
    users_data = res_grouped.json()
    assert len(users_data) > 0, "No users returned in grouped files"
    print(f"[PASS] 3. User-Wise Grouped Files & Synchronized Risk Scores ({len(users_data)} users)")

    # 4. Threat Intelligence Correlation Engine
    res_corr = client.get("/api/soc/threat-intelligence/correlation", headers=admin_headers)
    assert res_corr.status_code == 200, f"Correlation endpoint failed: {res_corr.text}"
    corr_data = res_corr.json()
    assert corr_data["clusters_count"] >= 3, "Insufficient correlation clusters"
    print(f"[PASS] 4. Threat Intelligence Correlation Engine ({corr_data['clusters_count']} Clusters)")

    # 5. User Risk Profiling Matrix
    res_risk = client.get("/api/soc/analytics/risk-profiling", headers=admin_headers)
    assert res_risk.status_code == 200, f"Risk profiling endpoint failed: {res_risk.text}"
    risk_data = res_risk.json()
    assert len(risk_data["profiles"]) > 0, "No risk profiles returned"
    print(f"[PASS] 5. User Risk Profiling Matrix ({len(risk_data['profiles'])} Behavioral Profiles)")

    # 6. Automated Security Response Policies
    res_pol = client.get("/api/soc/policies", headers=admin_headers)
    assert res_pol.status_code == 200, f"Policies endpoint failed: {res_pol.text}"
    pol_data = res_pol.json()
    assert len(pol_data) >= 4, "Default security policies missing"
    print(f"[PASS] 6. Automated Security Response Policies ({len(pol_data)} Active Policies)")

    # 7. Unified Quarantine & Threat Command Center
    res_quar = client.get("/api/soc/quarantine/list", headers=admin_headers)
    assert res_quar.status_code == 200, f"Quarantine endpoint failed: {res_quar.text}"
    quar_data = res_quar.json()
    print(f"[PASS] 7. Unified Quarantine & Threat Center ({len(quar_data)} Quarantined Threats)")

    # 8. Emergency Account Lockdown
    res_lock = client.post("/api/auth/emergency-lockdown", json={
        "password": "UserPass123!",
        "acknowledgement": True,
        "reason": "Test Suite Defense Trigger"
    }, headers=user_headers)
    assert res_lock.status_code == 200, f"Emergency lockdown failed: {res_lock.text}"
    lock_stats = res_lock.json()["stats"]
    assert lock_stats["lockdown_active"] == True, "Lockdown state not active"
    print(f"[PASS] 8. Emergency Account Lockdown Mode (Sessions Terminated: {lock_stats['sessions_terminated']})")

    print("==================================================================")
    print("ALL 8 ACCEPTANCE CRITERIA TESTS PASSED PERFECTLY (100% SUCCESS)!")
    print("==================================================================")

if __name__ == "__main__":
    run_acceptance_suite()
