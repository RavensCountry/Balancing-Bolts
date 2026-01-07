from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_inventory_pagination():
    # signup admin (only admins can create properties)
    r = client.post('/api/auth/signup', data={'name':'InvAdmin','email':'invmgr@example.com','password':'pw','role':'admin'})
    assert r.status_code == 200
    token = r.json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # create property
    r2 = client.post('/api/properties', data={'name':'PropInv','address':'Addr'}, headers=headers)
    assert r2.status_code == 200
    prop = r2.json()
    prop_id = prop['id']

    # add 25 inventory items
    for i in range(25):
        r3 = client.post('/api/inventory', data={'property_id': prop_id, 'name': f'Item{i}', 'description':'desc', 'quantity':1, 'cost': 10}, headers=headers)
        assert r3.status_code == 200

    # fetch page 2 with per_page=10
    r4 = client.get('/api/inventory', params={'page':2,'per_page':10,'property_id':prop_id}, headers=headers)
    assert r4.status_code == 200
    j = r4.json()
    assert j['page'] == 2
    assert j['per_page'] == 10
    assert j['total'] >= 25
    assert len(j['items']) == 10
