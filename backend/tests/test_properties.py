from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_property_requires_manager_role():
    # Create a maintenance user
    r = client.post('/api/auth/signup', data={'name':'Maint','email':'maint@example.com','password':'m','role':'maintenance'})
    assert r.status_code == 200
    token = r.json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # Attempt to create property should be forbidden
    r2 = client.post('/api/properties', data={'name':'P1','address':'Addr'}, headers=headers)
    assert r2.status_code == 403 or r2.status_code == 401

    # Manager should NOT be able to create property
    r3 = client.post('/api/auth/signup', data={'name':'Mgr','email':'mgr2@example.com','password':'m','role':'manager'})
    token2 = r3.json()['access_token']
    headers2 = {'Authorization': f'Bearer {token2}'}
    r4 = client.post('/api/properties', data={'name':'P1','address':'Addr'}, headers=headers2)
    assert r4.status_code in (401, 403)

    # Admin can create property
    r5 = client.post('/api/auth/signup', data={'name':'Admin','email':'admin@example.com','password':'m','role':'admin'})
    token3 = r5.json()['access_token']
    headers3 = {'Authorization': f'Bearer {token3}'}
    r6 = client.post('/api/properties', data={'name':'P1','address':'Addr'}, headers=headers3)
    assert r6.status_code == 200
