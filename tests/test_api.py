from unittest.mock import AsyncMock
import dataclasses
import services.pipeline as pipeline
from config import settings


def test_public_health_and_auth_gate(client):
    r=client.get('/')
    assert r.status_code==200 and 'कोडनीती' in r.text
    assert 'default-src' in r.headers['content-security-policy']
    assert client.get('/health').json()['status']=='healthy'
    assert client.get('/api/auth/me').json()['user'] is None
    assert client.get('/api/history').status_code==401
    assert client.get('/api/stats').status_code==401
    assert client.post('/api/compare',json={'code1':'a','code2':'b'}).status_code==401


def test_register_login_logout_and_revoke(client):
    registration={'display_name':'Saurabh Shinde','email':'TEAM@example.org','password':'very-long-safe-password-123'}
    response=client.post('/api/auth/register',json=registration)
    assert response.status_code==201
    assert response.cookies['codeniti_session']
    assert 'httponly' in response.headers['set-cookie'].lower()
    assert client.get('/api/auth/me').json()['user']['email']=='team@example.org'
    assert client.post('/api/auth/register',json=registration).status_code==409
    old_cookie=client.cookies.get('codeniti_session')
    assert client.post('/api/auth/logout',json={}).status_code==200
    assert client.get('/api/auth/me').json()['user'] is None
    client.cookies.set('codeniti_session',old_cookie)
    assert client.get('/api/auth/me').json()['user'] is None
    client.cookies.delete('codeniti_session')
    assert client.post('/api/auth/login',json={'email':registration['email'],'password':'incorrectpassword123'}).status_code==401
    assert client.post('/api/auth/login',json={'email':registration['email'],'password':registration['password']}).status_code==200
    assert client.get('/api/auth/me').json()['user']['display_name']=='Saurabh Shinde'


def test_saved_history_cache_and_metrics(signed_in):
    client=signed_in
    payload={'code1':'before = 1','code2':'before = 2'}
    first=client.post('/api/compare',json=payload).json()
    assert first['engine']=='diff' and first['saved'] is False
    assert client.get('/api/history').json()==[]
    payload['save_history']=True
    one=client.post('/api/compare',json=payload).json()
    two=client.post('/api/compare',json=payload).json()
    assert not one['cached'] and two['cached']
    assert len(client.get('/api/history').json())==2
    stats=client.get('/api/stats').json()
    assert stats['requests_total']==3
    assert stats['cache_hits']==1
    assert stats['cache_hit_rate_percent']>0
    assert stats['p95_latency_ms'] is not None
    assert stats['saved_analyses']==2
    assert stats['sample_size']==3
    # Invalidate cache when single history item is deleted
    history_items = client.get('/api/history').json()
    assert client.delete(f'/api/history/{history_items[0]["id"]}').status_code==200
    three = client.post('/api/compare', json=payload).json()
    assert not three['cached']


def test_user_data_isolation_and_account_deletion(signed_in):
    client=signed_in
    assert client.post('/api/compare',json={'code1':'private A','code2':'private B','save_history':True}).status_code==200
    first_id=client.get('/api/history').json()[0]['id']
    a_token=client.cookies.get('codeniti_session')
    client.post('/api/auth/logout',json={})
    register=client.post('/api/auth/register',json={'display_name':'Other User','email':'other@demo.org','password':'different-pass-2026'})
    assert register.status_code==201
    assert client.get('/api/history').json()==[]
    assert client.delete(f'/api/history/{first_id}').status_code==404
    client.cookies.delete('codeniti_session')
    client.cookies.set('codeniti_session',a_token)
    assert client.get('/api/history').status_code==401  # revoked token cannot impersonate previous user
    client.cookies.delete('codeniti_session')
    assert client.post('/api/auth/login',json={'email':'other@demo.org','password':'different-pass-2026'}).status_code==200
    assert client.delete('/api/auth/account').status_code==200
    assert client.get('/api/auth/me').json()['user'] is None
    assert client.post('/api/auth/login',json={'email':'other@demo.org','password':'different-pass-2026'}).status_code==401
    assert client.post('/api/auth/login',json={'email':'dev@example.org','password':'A-strong-test-password-2026'}).status_code==200
    assert len(client.get('/api/history').json())==1
    assert client.delete(f'/api/history/{first_id}').status_code==200
    assert client.delete(f'/api/history/{first_id}').status_code==404


def test_ai_mocked_and_private_mode(signed_in,monkeypatch):
    client=signed_in
    mocked=AsyncMock(return_value='## Quality review\n\nUse a better algorithm.')
    monkeypatch.setattr(pipeline,'call_gemini',mocked)
    body={'code':'def foo(): pass','language':'python','save_history':True}
    first=client.post('/api/optimize',json=body)
    second=client.post('/api/optimize',json=body)
    private=client.post('/api/optimize',json={**body,'save_history':False})
    assert all(res.status_code==200 for res in (first,second,private))
    assert not first.json()['cached'] and second.json()['cached']
    assert not private.json()['cached']
    assert mocked.await_count==2
    assert len(client.get('/api/history').json())==2


def test_validation_and_csrf(signed_in):
    client=signed_in
    for item in ({'code':''},{'code':'  '},{'code':'yes','language':'brainfuck'}):
        assert client.post('/api/optimize',json=item).status_code==422
    assert client.post('/api/compare',json={'code1':'a','code2':''}).status_code==422
    assert client.post('/api/compare',json={'code1':'a','code2':'b'},headers={'Origin':'https://attacker.test'}).status_code==403
    assert client.post('/api/compare',json={'code1':'a','code2':'b'},headers={'X-Requested-With':''}).status_code==403


def test_no_key_gemini_and_quota(signed_in,monkeypatch):
    from services import gemini
    client=signed_in
    monkeypatch.setattr(gemini,'settings',dataclasses.replace(settings,gemini_api_key=''))
    resp=client.post('/api/optimize',json={'code':'print(1)'})
    assert resp.status_code==503
    assert 'not configured' in resp.json()['detail']
    import routers.ai as ai
    monkeypatch.setattr(ai,'settings',dataclasses.replace(settings,ai_daily_limit=1))
    # Settings imported directly in database module, so patch quota there.
    import database
    monkeypatch.setattr(database,'settings',dataclasses.replace(database.settings,ai_daily_limit=1))
    blocked=client.post('/api/optimize',json={'code':'print(2)'})
    assert blocked.status_code==429


def test_mutation_requires_valid_registration(client):
    assert client.post('/api/auth/register',json={'display_name':'X','email':'bademail','password':'123'}).status_code==422
    assert client.post('/api/auth/register',json={'display_name':'Someone','email':'user@example.org','password':'123456789'}).status_code==422


def test_rate_limiter(signed_in):
    client=signed_in
    for _ in range(settings.rate_limit):
        assert client.post('/api/compare',json={'code1':'a','code2':'b'}).status_code==200
    blocked=client.post('/api/compare',json={'code1':'a','code2':'b'})
    assert blocked.status_code==429
    assert int(blocked.headers['retry-after'])>=1
    assert client.get('/health').status_code==200


def test_cached_ai_does_not_consume_additional_ai_quota(signed_in, monkeypatch):
    from unittest.mock import AsyncMock
    import database
    import services.pipeline as pipeline
    client = signed_in
    monkeypatch.setattr(database, 'settings', dataclasses.replace(database.settings, ai_daily_limit=1))
    mock = AsyncMock(return_value='## Review\n\nSample output.')
    monkeypatch.setattr(pipeline, 'call_gemini', mock)
    body = {'code': 'print("hello")', 'language': 'python', 'save_history': True}
    first = client.post('/api/optimize', json=body)
    second = client.post('/api/optimize', json=body)
    third = client.post('/api/optimize', json={**body, 'code': 'print("different")'})
    assert first.status_code == 200 and first.json()['cached'] is False
    assert second.status_code == 200 and second.json()['cached'] is True
    assert third.status_code == 429
    assert mock.await_count == 1
    assert client.get('/api/stats').json()['ai_remaining_today'] == 0


def test_authenticated_rate_limit_is_per_account(client):
    first = client.post('/api/auth/register',json={
        'display_name':'First Student','email':'first@uni.example','password':'AnExamplePassword-2026'})
    assert first.status_code == 201
    for _ in range(settings.rate_limit):
        assert client.post('/api/compare',json={'code1':'x','code2':'y'}).status_code == 200
    assert client.post('/api/compare',json={'code1':'x','code2':'y'}).status_code == 429
    assert client.post('/api/auth/logout',json={}).status_code == 200
    second=client.post('/api/auth/register',json={
        'display_name':'Second Student','email':'second@uni.example','password':'AnotherExamplePassword-2026'})
    assert second.status_code == 201
    assert client.post('/api/compare',json={'code1':'x','code2':'z'}).status_code == 200


def test_closed_loop_repair_verification(signed_in, monkeypatch):
    from unittest.mock import AsyncMock
    import services.gemini as gemini_mod
    client = signed_in
    clean_code = "```python\nimport os, subprocess\npath = os.environ.get('USER_DIR', '.')\nsubprocess.run(['ls', path], check=True)\n```"
    mock_repair = AsyncMock(return_value=clean_code)
    monkeypatch.setattr(gemini_mod, 'call_gemini', mock_repair)

    bad_code = 'import subprocess\napi_key = "secret_12345"\nsubprocess.run("ls " + path, shell=True)\n'
    resp = client.post('/api/verify-repair', json={'code': bad_code, 'language': 'python'})
    assert resp.status_code == 200
    data = resp.json()
    assert 'Closed-Loop' in data['result'] or 'Verification' in data['result']
    assert data['engine'] == 'bandit+ast+gemini'
    assert data['tool'] == 'verify-repair'
