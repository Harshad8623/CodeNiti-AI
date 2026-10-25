"""Real HTTP auth + offline diff smoke test.

Start `python main.py` in another terminal, then run:
  python scripts/smoke.py
  CODENITI_BASE_URL=https://your-railway-domain python scripts/smoke.py

Uses a disposable account and deletes it on success. Requires ENABLE_SIGNUP=true.
Never tests Gemini or consumes provider tokens.
"""
import json
import os
from http.cookiejar import CookieJar
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.error import HTTPError
from uuid import uuid4

BASE=os.getenv('CODENITI_BASE_URL','http://127.0.0.1:8000').rstrip('/')
opener=build_opener(HTTPCookieProcessor(CookieJar()))


def send(path,method='GET',data=None):
    headers={}
    if method!='GET':
        headers['X-Requested-With']='XMLHttpRequest'
        headers['Content-Type']='application/json'
    payload=json.dumps(data).encode('utf-8') if data is not None else None
    request=Request(BASE+path,data=payload,headers=headers,method=method)
    try:
        with opener.open(request,timeout=12) as response:
            return response.status,json.load(response)
    except HTTPError as exc:
        detail=exc.read().decode('utf-8',errors='replace')[:400]
        raise RuntimeError(f'{method} {path}: HTTP {exc.code}: {detail}') from exc


def run():
    assert send('/health')[1]['status']=='healthy'
    assert send('/api/auth/me')[1]['user'] is None
    email=f'smoke-{uuid4().hex[:16]}@example.invalid'
    created=False
    try:
        status,data=send('/api/auth/register','POST',{
            'display_name':'Temporary Smoke Test',
            'email':email,
            'password':'Disposable-long-test-password-2026'
        })
        assert status==201,data
        created=True
        assert send('/api/auth/me')[1]['user']['email']==email
        status,data=send('/api/compare','POST',{
            'code1':'print(1)', 'code2':'print(2)',
            'language':'python','save_history':True
        })
        assert status==200 and data['engine']=='diff' and '-print(1)' in data['result']
        assert len(send('/api/history')[1])==1
        assert send('/api/stats')[1]['saved_analyses']==1
        print('PASS: live HTTP health, registration, cookie session, diff, history and metrics')
    finally:
        if created:
            try:
                send('/api/auth/account','DELETE')
                print('Disposable test account deleted.')
            except Exception as exc:
                print('WARNING: Could not delete temporary test account:',exc)

if __name__=='__main__':
    run()
