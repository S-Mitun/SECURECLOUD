import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

# Login user
r = client.post('/api/auth/login', json={'email': 'analyst@securecloud.com', 'password': 'UserPass123!', 'portal': 'USER'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Get user files
r_files = client.get('/api/files/list', headers=headers)
files = r_files.json()
print('Total user files:', len(files))

if files:
    f = files[0]
    # Lock as confidential if not already
    client.post('/api/confidential/lock', json={'file_id': f['id'], 'pin': '123456', 'save_password': True}, headers=headers)
    
    print(f"=== Testing Progressive Lockout on {f['filename']} ===")
    for attempt in range(1, 4):
        res = client.post('/api/confidential/unlock', json={'file_id': f['id'], 'pin': '000000'}, headers=headers)
        print(f"Attempt {attempt}: status={res.status_code}, detail={res.json().get('detail')}")
