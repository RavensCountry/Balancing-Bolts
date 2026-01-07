from fastapi.testclient import TestClient
from backend.main import app
import pytest

client = TestClient(app)

def test_signup_login_and_poller_and_reports():
    # Signup manager
    r = client.post("/api/auth/signup", data={"name":"Mgr","email":"mgr@example.com","password":"pass","role":"manager"})
    assert r.status_code == 200
    j = r.json()
    assert 'access_token' in j
    token = j['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # Poll status
    r = client.get('/api/resman/poller/status', headers=headers)
    assert r.status_code == 200
    assert 'running' in r.json()

    # Enable poller
    r = client.post('/api/resman/poller/enable', headers=headers)
    assert r.status_code == 200
    assert r.json().get('status') in ('enabled', 'already_running')

    # Disable poller
    r = client.post('/api/resman/poller/disable', headers=headers)
    assert r.status_code == 200
    assert r.json().get('status') in ('disabled', 'already_disabled')

    # Monthly report (no invoices yet)
    r = client.get('/api/reports/monthly', params={'year':2025,'month':12}, headers=headers)
    assert r.status_code == 200
    assert 'total' in r.json()

    # Yearly report
    r = client.get('/api/reports/yearly', params={'year':2025}, headers=headers)
    assert r.status_code == 200
    assert 'total' in r.json()
