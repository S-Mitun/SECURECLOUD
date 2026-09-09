import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)
r = client.post('/api/auth/login', json={'email': 'admin@securecloud.com', 'password': 'AdminPass123!', 'portal': 'ADMIN'})
headers = {'Authorization': f'Bearer {r.json()["access_token"]}'}

policies = client.get('/api/soc/policies', headers=headers).json()
print('Policies count:', len(policies))
p = policies[0]
print('Testing trigger on policy:', p)
res = client.post(f'/api/soc/policies/{p["id"]}/trigger', headers=headers)
print('Status:', res.status_code)
print('Response JSON:', res.json())
