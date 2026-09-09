import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

# Login user
r = client.post('/api/auth/login', json={'email': 'analyst@securecloud.com', 'password': 'UserPass123!', 'portal': 'USER'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# List files
r_list = client.get('/api/confidential/list', headers=headers)
files = r_list.json()
print('Total confidential files:', len(files))
if len(files) > 0:
    target_id = files[0]['id']
    print('Testing unlock on file:', files[0]['filename'])
    for attempt in range(1, 5):
        res = client.post('/api/confidential/unlock', json={'file_id': target_id, 'pin': 'WRONGP'}, headers=headers)
        print(f'Attempt {attempt}: status={res.status_code}, detail="{res.json().get("detail")}"')
