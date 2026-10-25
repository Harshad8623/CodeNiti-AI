import dataclasses
import pytest
from fastapi.testclient import TestClient
import database
from config import settings
from main import app
from services.cache import cache

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(database,'settings',dataclasses.replace(settings,database_path=str(tmp_path/'isolated.db')))
    cache.clear()
    with TestClient(app) as http:
        http.headers.update({'X-Requested-With':'XMLHttpRequest'})
        node=app.middleware_stack
        while node is not None:
            if hasattr(node,'hits'):
                node.hits.clear()
            node=getattr(node,'app',None)
        yield http
    cache.clear()

@pytest.fixture
def signed_in(client):
    answer=client.post('/api/auth/register',json={'display_name':'Test Developer','email':'dev@example.org',
                                                   'password':'A-strong-test-password-2026'})
    assert answer.status_code==201,answer.text
    return client
