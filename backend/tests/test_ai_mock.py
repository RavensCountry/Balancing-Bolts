import pytest
from fastapi.testclient import TestClient
from backend.main import app
import backend.ai as ai_module

client = TestClient(app)


def test_ai_query_with_mock(monkeypatch):
    # signup a user to get a token
    r = client.post('/api/auth/signup', data={'name':'AIUser','email':'ai@example.com','password':'pw','role':'manager'})
    assert r.status_code == 200
    token = r.json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # Mock embedding and chat completion
    class FakeEmb:
        def __init__(self, embedding):
            self.embedding = embedding

    def fake_embed_create(model, input):
        return {'data': [{'embedding': [0.1, 0.2, 0.3]}]}

    def fake_chat_create(model, messages, max_tokens=500):
        return {'choices': [{'message': {'content': 'Mocked answer: total spent on white fridges is $1234.56'}}]}

    # Patch openai usage inside ai_module
    # ensure api_key is set so embed_text doesn't raise
    ai_module.openai.api_key = 'test'
    monkeypatch.setattr(ai_module.openai.Embedding, 'create', lambda model, input: fake_embed_create(model, input))
    monkeypatch.setattr(ai_module.openai.ChatCompletion, 'create', lambda model, messages, max_tokens=500: fake_chat_create(model, messages, max_tokens))

    # perform AI query
    r2 = client.post('/api/ai/query', json={'query': 'how much money have we spent on white fridges'}, headers=headers)
    assert r2.status_code == 200
    j = r2.json()
    assert 'Mocked answer' in j['answer']
