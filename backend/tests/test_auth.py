from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_signup_and_invalid_login():
    # Signup a user (password must be at least 8 chars)
    r = client.post("/api/auth/signup", data={"name":"User","email":"user@example.com","password":"secretpass","role":"maintenance"})
    assert r.status_code == 200
    j = r.json()
    assert 'access_token' in j

    # Attempt login with wrong password
    r2 = client.post('/api/auth/login', data={'username':'user@example.com','password':'wrongpass'})
    assert r2.status_code == 401

    # Login with correct password
    r3 = client.post('/api/auth/login', data={'username':'user@example.com','password':'secretpass'})
    assert r3.status_code == 200
    assert 'access_token' in r3.json()
