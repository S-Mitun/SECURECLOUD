import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app
import io

client = TestClient(app)

# Login admin
r = client.post('/api/auth/login', json={'email': 'admin@securecloud.com', 'password': 'AdminPass123!', 'portal': 'ADMIN'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Get users
users = client.get('/api/soc/users', headers=headers).json()
target_user = users[0]
print(f"Testing admin upload for user: {target_user['username']} (ID: {target_user['id']})")

# Upload dummy test file
test_bytes = io.BytesIO(b"SecureCloud Automated Admin Ingestion Test Payload.")
files = {'file': ('admin_ingested_test.txt', test_bytes, 'text/plain')}
data = {'target_user_id': target_user['id']}

res = client.post('/api/soc/files/upload-for-user', headers=headers, data=data, files=files)
print("Upload for user response status:", res.status_code)
print("Upload for user response data:", res.json())
