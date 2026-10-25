"""Reproducible API/cache benchmark; real local diff engine, no Gemini cost.

Run: python scripts/benchmark.py
Writes docs/BENCHMARK_RESULTS.md. Run again on your actual deployment
for relevant platform results. AI generation is not measured by this script.
"""
import dataclasses
from datetime import datetime,timezone
from pathlib import Path
from statistics import mean,median
import sys
import tempfile
from time import perf_counter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import database
import middleware.rate_limiter as limiter
from config import settings
from fastapi.testclient import TestClient
from main import app


def run(rounds=35):
    with tempfile.TemporaryDirectory() as path:
        database.settings=dataclasses.replace(settings,database_path=str(Path(path)/'benchmark.db'))
        # This controlled local benchmark intentionally raises the rate ceiling.
        limiter.settings=dataclasses.replace(settings,rate_limit=200)
        from services.cache import cache
        cache.clear()
        with TestClient(app) as client:
            client.headers.update({'X-Requested-With':'XMLHttpRequest'})
            reg=client.post('/api/auth/register',json={'display_name':'Benchmark User','email':'bench@local.example',
                                                       'password':'long-benchmark-password-2026'})
            assert reg.status_code==201,reg.text
            items=[{'code1':f'def example():\n    return {i}',
                    'code2':f'def example():\n    return {i+1}',
                    'language':'python','save_history':True} for i in range(rounds)]
            cold=[]
            for payload in items:
                start=perf_counter()
                response=client.post('/api/compare',json=payload)
                assert response.status_code==200,response.text
                assert not response.json()['cached']
                cold.append((perf_counter()-start)*1000)
            warm=[]
            for payload in items:
                start=perf_counter()
                response=client.post('/api/compare',json=payload)
                assert response.status_code==200,response.text
                assert response.json()['cached']
                warm.append((perf_counter()-start)*1000)
            data=client.get('/api/stats').json()
            assert data['cache_hits']==rounds
            assert data['requests_total']==rounds*2
    reduction=round(100*(mean(cold)-mean(warm))/mean(cold),1)
    return {'rounds':rounds,'cold_ms':round(mean(cold),2),'warm_ms':round(mean(warm),2),
            'cold_median_ms':round(median(cold),2),'warm_median_ms':round(median(warm),2),
            'latency_reduction_percent':reduction,'cache_hit_rate_percent':data['cache_hit_rate_percent']}


if __name__=='__main__':
    v=run()
    text=f'''# Reproducible cache benchmark — कोडनीती AI

Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

**Workload:** Real FastAPI routes and SQLite, {v['rounds']} unique input pairs in a first cold pass, then the same {v['rounds']} input pairs in a cached pass. **Local deterministic code comparison only.** No Gemini API call, no hypothetical provider latency.

| Measure | Observed |
|---|---:|
| Cold average end-to-end latency | {v['cold_ms']} ms |
| Cached average end-to-end latency | {v['warm_ms']} ms |
| Cold median latency | {v['cold_median_ms']} ms |
| Cached median latency | {v['warm_median_ms']} ms |
| Relative change (average) | {v['latency_reduction_percent']}% |
| Cache-hit rate (overall 2-pass test) | {v['cache_hit_rate_percent']}% |

**How measured:** Python TestClient, in-process ASGI, using real SQLite and the real diff engine; timed client requests, including authentication lookup, DB writes and metrics. This is a small development-environment sample, not a claim about Railway latency, public network overhead, or Gemini speed. The average speedup can vary or be negative if DB writes dominate, and is not a SLA. Do not present it as a real-world provider benchmark. The per-account `/api/stats` endpoint also provides actual timing samples.

**Reproduce:** `python scripts/benchmark.py`. For more representative evidence, measure your Railway deployment after setting the environment, plus real Gemini cold/cached responses separately.
'''
    Path(__file__).resolve().parents[1].joinpath('docs','BENCHMARK_RESULTS.md').write_text(text)
    print(text)
