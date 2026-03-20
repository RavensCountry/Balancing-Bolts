import pytest
from fastapi.testclient import TestClient
from backend.main import app
import backend.ai as ai_module

client = TestClient(app)


def test_ai_query_with_mock(monkeypatch):
    # signup a user to get a token (password must be at least 8 chars)
    r = client.post('/api/auth/signup', data={'name': 'AIUser', 'email': 'ai@example.com', 'password': 'password1', 'role': 'manager'})
    assert r.status_code == 200
    token = r.json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # Mock responses for the new openai 1.x client-based API
    class MockEmbeddingData:
        embedding = [0.1, 0.2, 0.3]

    class MockEmbeddingResponse:
        data = [MockEmbeddingData()]

    class MockChatMessage:
        content = 'Mocked answer: total spent on white fridges is $1234.56'

    class MockChatChoice:
        message = MockChatMessage()

    class MockChatResponse:
        choices = [MockChatChoice()]

    class MockEmbeddings:
        def create(self, model, input):
            return MockEmbeddingResponse()

    class MockCompletions:
        def create(self, model, messages, max_tokens=500):
            return MockChatResponse()

    class MockChat:
        def __init__(self):
            self.completions = MockCompletions()

    class MockClient:
        def __init__(self):
            self.embeddings = MockEmbeddings()
            self.chat = MockChat()

    # Patch the module-level client and ensure OPENAI_API_KEY is set
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(ai_module, '_openai_client', MockClient())

    # perform AI query
    r2 = client.post('/api/ai/query', json={'query': 'how much money have we spent on white fridges'}, headers=headers)
    assert r2.status_code == 200
    j = r2.json()
    assert 'Mocked answer' in j['answer']
