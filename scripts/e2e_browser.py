"""Browser UI -> real FastAPI route checks with a TestClient transport bridge.

Why a bridge? It allows offline/internet-restricted Chromium to run this E2E
check. Browsers on ordinary laptops will use standard HTTP fetch instead.
Run: python scripts/e2e_browser.py
Needs: pip install -r requirements-dev.txt; playwright install chromium
"""
from pathlib import Path
import re
import sys
import tempfile
import dataclasses
import shutil
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
import database
from config import settings
from main import app

ROOT=Path(__file__).resolve().parents[1]
html=(ROOT/'templates/index.html').read_text(encoding='utf-8')
html=re.sub(r'<link[^>]+href="/static/css/style.css"[^>]*>','',html)
html=re.sub(r'<script[^>]+src="/static/js/app.js"[^>]*></script>','',html)
css=(ROOT/'static/css/style.css').read_text(encoding='utf-8')
js=(ROOT/'static/js/app.js').read_text(encoding='utf-8')


def run():
    with tempfile.TemporaryDirectory() as temp:
        database.settings=dataclasses.replace(settings,database_path=str(Path(temp)/'browser.db'))
        with TestClient(app) as http:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,executable_path=shutil.which('chromium') or None,args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1440,'height':900},device_scale_factor=1)
                page.set_default_timeout(6000)
                errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                def bridge(url,options):
                    response=http.request(options.get('method','GET'),url,headers=options.get('headers') or {},
                                          content=options.get('body'))
                    return {'body':response.text,'status':response.status_code}
                page.set_content(html,wait_until='domcontentloaded')
                page.add_style_tag(content=css)
                page.expose_function('__bridgeFetch',bridge)
                page.add_script_tag(content='''window.fetch=async function(url,opts={}){
                    const result=await window.__bridgeFetch(url,opts);
                    return new Response(result.body,{status:result.status,headers:{'Content-Type':'application/json'}});
                };''')
                page.add_script_tag(content=js)
                page.locator('#authOverlay:not(.hidden)').wait_for()
                page.locator('#registerTab').click()
                page.locator('#authName').fill('Browser Test User')
                page.locator('#authEmail').fill('browser@testing.example')
                page.locator('#authPassword').fill('Browser-test-password-2026')
                page.locator('#authSubmit').click()
                page.locator('#authOverlay:not(.hidden)').wait_for(state='hidden')
                assert page.locator('#accountLabel').inner_text()=='Browser'
                page.locator('[data-tool="compare"]').click()
                page.locator('#beforeInput').fill('x = 1')
                page.locator('#afterInput').fill('x = 2')
                page.locator('#saveHistory').check()
                page.locator('#runBtn').click()
                page.locator('#resultStatus.success').wait_for()
                assert '+x = 2' in page.locator('#outputArea').inner_text()
                assert page.locator('#resultStatus').inner_text()=='COMPLETE'
                page.evaluate('window.scrollTo(0, 0)')
                page.screenshot(path=str(ROOT/'docs'/'ui-desktop.png'),full_page=True)
                page.locator('#historyBtn').click()
                page.locator('.history-item').first.wait_for()
                assert 'x = 1' in page.locator('#drawerContent').inner_text()
                page.locator('#drawerClose').click()
                page.locator('#insightsBtn').click()
                page.get_by_text('Cache hit rate').wait_for()
                assert 'Cache hit rate' in page.locator('#drawerContent').inner_text()
                page.locator('#drawerClose').click()
                page.locator('#aboutBtn').click()
                assert 'DHUPPE HARSHAD' in page.locator('#drawerContent').inner_text().upper()
                assert 'Prof. J. N. Mohite' in page.locator('#drawerContent').inner_text()
                page.evaluate('window.scrollTo(0, 0)')
                page.screenshot(path=str(ROOT/'docs'/'ui-team.png'),full_page=True)
                page.locator('#drawerClose').click()
                page.locator('#accountBtn').click()
                page.get_by_text('Sign out',exact=True).click()
                page.locator('#authOverlay:not(.hidden)').wait_for()
                page.locator('#authEmail').fill('browser@testing.example')
                page.locator('#authPassword').fill('Browser-test-password-2026')
                page.locator('#authSubmit').click()
                page.locator('#authOverlay:not(.hidden)').wait_for(state='hidden')
                page.locator('#historyBtn').click()
                page.locator('.history-item').first.wait_for()
                page.locator('#drawerClose').click()
                # Mobile: ensure the navigation can be opened and the report remains present.
                page.set_viewport_size({'width':390,'height':844})
                page.locator('#menuBtn').click()
                assert 'open' in page.locator('#sidebar').get_attribute('class')
                page.locator('[data-tool="compare"]').click()
                page.evaluate('window.scrollTo(0, 0)')
                page.screenshot(path=str(ROOT/'docs'/'ui-mobile.png'),full_page=True)
                assert not errors,errors
                browser.close()
    print('PASS: auth/register/login/logout, diff analysis, private history, metrics, credits, mobile navigation, zero JS exceptions.')
    print('Browser exercise uses TestClient transport instead of real browser networking (restricted environment).')

if __name__=='__main__':
    run()
