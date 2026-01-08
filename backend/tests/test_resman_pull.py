import os
import pytest
from backend import resman


def test_pull_raises_when_no_url(monkeypatch):
    # Ensure environment not set; function should raise RuntimeError
    monkeypatch.delenv('RESMAN_INVOICES_URL', raising=False)
    with pytest.raises(RuntimeError):
        resman.pull_once()


def test_pull_with_csv_and_json(monkeypatch, tmp_path):
    # Mock environment and requests.get to return CSV then JSON
    import requests

    csv_text = "vendor,date,total,property_id\nVendorA,2025-12-01,100.50,1\nVendorB,2025-12-02,200,2\n"

    class MockRespCSV:
        def __init__(self, text):
            self.text = text
            self.headers = {'content-type': 'text/csv'}

        def json(self):
            raise ValueError("not json")
        def raise_for_status(self):
            return None

    json_list = [
        {"vendor": "VendorC", "date": "2025-12-03", "total": 300, "property_id": 3},
    ]

    class MockRespJSON:
        def __init__(self, data):
            self._data = data
            self.headers = {'content-type': 'application/json'}

        @property
        def text(self):
            return ''

        def json(self):
            return self._data
        def raise_for_status(self):
            return None

    calls = {'n': 0}

    def fake_get(url, headers=None, timeout=30):
        # alternate between csv and json responses
        calls['n'] += 1
        if calls['n'] == 1:
            return MockRespCSV(csv_text)
        return MockRespJSON(json_list)

    monkeypatch.setenv('RESMAN_INVOICES_URL', 'https://example.com/invoices.csv')
    monkeypatch.setattr(requests, 'get', fake_get)
    # insert a ResmanToken row so pull_once will attempt to fetch
    from backend.database import engine
    from backend.models import ResmanToken, SQLModel
    from sqlmodel import Session
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        # clear existing tokens to avoid interference from other tests
        from sqlalchemy import text
        s.exec(text("DELETE FROM resmantoken"))
        s.commit()
        t1 = ResmanToken(access_token='fake1', refresh_token='r1', expires_at=None)
        t2 = ResmanToken(access_token='fake2', refresh_token='r2', expires_at=None)
        s.add(t1); s.add(t2)
        s.commit()

    res = resman.pull_once()
    assert isinstance(res, dict)
    assert res['pulled'] >= 3
