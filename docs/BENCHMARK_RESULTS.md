# Reproducible cache benchmark — कोडनीती AI

Date: 2026-10-25 18:45 UTC

**Workload:** Real FastAPI routes and SQLite, 35 unique input pairs in a first cold pass, then the same 35 input pairs in a cached pass. **Local deterministic code comparison only.** No Gemini API call, no hypothetical provider latency.

| Measure | Observed |
|---|---:|
| Cold average end-to-end latency | 5.08 ms |
| Cached average end-to-end latency | 3.41 ms |
| Cold median latency | 4.47 ms |
| Cached median latency | 3.13 ms |
| Relative change (average) | 32.9% |
| Cache-hit rate (overall 2-pass test) | 50.0% |

**How measured:** Python TestClient, in-process ASGI, using real SQLite and the real diff engine; timed client requests, including authentication lookup, DB writes and metrics. This is a small development-environment sample, not a claim about Railway latency, public network overhead, or Gemini speed. The average speedup can vary or be negative if DB writes dominate, and is not a SLA. Do not present it as a real-world provider benchmark. The per-account `/api/stats` endpoint also provides actual timing samples.

**Reproduce:** `python scripts/benchmark.py`. For more representative evidence, measure your Railway deployment after setting the environment, plus real Gemini cold/cached responses separately.
