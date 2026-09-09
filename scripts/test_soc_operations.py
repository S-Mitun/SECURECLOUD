import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

# Login admin
r = client.post('/api/auth/login', json={'email': 'admin@securecloud.com', 'password': 'AdminPass123!', 'portal': 'ADMIN'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

print("=== 1. Testing Real Mitigation Execution ===")
mit_res = client.post('/api/soc/threat-intelligence/mitigate-cluster', headers=headers, json={
    'cluster_id': 'THREAT CLUSTER #0042',
    'action': 'Enforce IP Blacklist on 198.51.100.42 and Quaratine Correlated Payloads'
})
print("Mitigation Response Status:", mit_res.status_code)
print("Actions Applied:", mit_res.json().get('actions_taken'))

# Verify IP was blacklisted in IP Guard
ip_data = client.get('/api/soc/ip-rules', headers=headers).json()
rules_list = ip_data if isinstance(ip_data, list) else ip_data.get('rules', [])
blacklisted_ips = [r['ip_address'] for r in rules_list if r.get('rule_type') == 'BLACKLIST']
print("Blacklisted IPs in IP Guard:", blacklisted_ips)

print("\n=== 2. Testing SOAR Policy Execution ===")
policies = client.get('/api/soc/policies', headers=headers).json()
if policies:
    p_id = policies[0]['id']
    trig_res = client.post(f'/api/soc/policies/{p_id}/trigger', headers=headers)
    print("Policy Trigger Status:", trig_res.status_code)
    print("Policy Exec Count:", trig_res.json().get('execution_count'))
    print("Actions Performed:", trig_res.json().get('actions_performed'))

print("\n=== 3. Testing Real 2FA Enforcement ===")
users = client.get('/api/soc/users', headers=headers).json()
target_u = [u for u in users if u['role'] == 'USER'][0]
two_fa_res = client.post('/api/soc/analytics/risk-profiling/enforce-2fa', headers=headers, json={'user_id': target_u['id']})
print("2FA Enforce Status:", two_fa_res.status_code)
print("User 2FA Status:", two_fa_res.json())

print("\n=== 4. Testing Real Account Lockdown ===")
lock_res = client.post('/api/soc/analytics/risk-profiling/lockdown-user', headers=headers, json={'user_id': target_u['id'], 'reason': 'Test Risk Lockdown'})
print("Lockdown Status:", lock_res.status_code)
print("Lockdown Details:", lock_res.json())
