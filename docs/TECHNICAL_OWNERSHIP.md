# Technical ownership workbook — कोडनीती AI

This guide is for the three team members to **read the implementation, explain it in a viva, and change it themselves**. Reading an AI-generated answer is not equivalent to understanding the code. Open each referenced module and run the exercises.

## 1. Trace the request end to end

Example: the signed-in user selects **Compare code**, sets `save_history=true`, and clicks the green button.

1. `static/js/app.js` → `payload()` validates that both editors contain text, then `run()` performs `fetch('/api/compare', ...)` with a same-origin cookie and `X-Requested-With: XMLHttpRequest` header.
2. `main.py` → `SecurityMiddleware` loads `request.state.user` from the cookie, rejects unsupported cross-origin state-changing requests and attaches security response headers.
3. `middleware/rate_limiter.py` → a bounded sliding-window counter checks the signed-in account's request count; unauthenticated login/signup attempts are IP-scoped.
4. `routers/ai.py` → FastAPI parses `CompareRequest` using Pydantic and `Depends(current_user)` rejects unauthenticated requests.
5. `services/pipeline.py` → builds a request fingerprint, tries the memory TTL/LRU cache, then the SQLite cache. On miss, it runs the local `difflib` adapter in a worker thread; a Gemini request is unnecessary.
6. `database.py` → if the user opted in, stores the output in the user-scoped result cache and saves the input/output in user history; it always records a small **metadata-only** timing metric.
7. The endpoint returns `AnalysisResponse`: `tool`, `result`, `engine`, `cached`, `duration_ms`, `saved`, `disclaimer`.
8. `static/js/app.js` renders the result through DOM elements with `textContent`, never arbitrary HTML from user/AI output.

**Exercise:** Trace the same flow for `/api/optimize`. Explain which step adds the AI request quota and which calls `google-genai` asynchronously.

## 2. The data model

| Table | Role | Data privacy/security consideration |
|---|---|---|
| `users` | name, email, salted PBKDF2 hash | Never store plaintext passwords |
| `sessions` | SHA-256 hash of opaque bearer token, expiry, user foreign key | Token is revocable and sent only through HttpOnly cookie |
| `history` | user-scoped saved code, prompt, tool, result | Plaintext; stored **only** with user opt-in |
| `response_cache` | user-scoped response and expiry | Prevent cross-account cache reads |
| `ai_quota` | number of AI cache misses per UTC calendar day | Prevent accidental API abuse; not a billing guarantee |
| `metrics` | per-user timing, tool, engine, cache hit | Does not store code/prompt text |

**Sample SQL — find latest analyses for one user:**

```sql
SELECT id, tool, language, created_at
FROM history
WHERE user_id = ?
ORDER BY id DESC
LIMIT 30;
```

**Sample SQL — why is this account scoped?** `DELETE FROM history WHERE user_id=? AND id=?` only deletes the row if the session owner matches it; a guessed numeric ID is not enough. Deleting the user cascades through dependent tables.

**Exercise:** Add a history filter by tool (e.g., show only `security`). Implement both the API filter with a fixed whitelist and the UI control, then add a test proving it cannot expose a second account's rows.

## 3. Cache correctness

The fingerprint is SHA-256 of sorted, canonical JSON containing:

- `user_id`; tool name; normalized Pydantic payload (including language);
- engine type (Gemini/diff/Ruff/Bandit);
- configured Gemini model, or local-engine revision;
- prompt revision (`PROMPT_VERSION`).

On an opt-in request: **RAM cache → SQLite cache → compute**. Both caches have expiry; the memory layer is capacity-bounded. Cache data is not encrypted; SHA-256 is used as a deterministic request identifier **not** as a confidentiality control. When `save_history=false`, caching is skipped entirely. For Gemini, a cached repeat does not reserve an additional AI quota slot.

**Concurrency limitation:** simultaneous cache misses may call the provider twice, and the RAM cache/rate limiter is single-worker. Advanced scaling would introduce per-key concurrency coordination and a shared store such as Redis.

**Exercise:** Change `PROMPT_VERSION` and confirm previously saved AI reports are not returned as cache hits. Add a unit test. Explain why language alone is not enough to identify an analysis request.

## 4. Authentication and threat model

- Registration validates email structure, a display name and passwords of 10–128 characters. `services/auth.py` salts and hashes the password with PBKDF2-HMAC-SHA256, 600,000 iterations, and uses constant-time digest comparison.
- Login returns a cryptographically random opaque session secret. The database stores only its SHA-256 digest. A cookie carries the token with `HttpOnly`, `SameSite=Lax`, and `Secure` in production.
- Logout invalidates the server token. `DELETE /api/auth/account` cascades account data deletion and clears in-memory cache data.
- JSON mutations require a custom same-origin header, and requests with a different `Origin` host are rejected. This helps against browser CSRF but is not a complete substitute for secure browser configuration, XSS review or a full threat model.
- Registration/login brute force is limited per IP. Authorized tool requests are limited per account. Quotas/limits are **not distributed across workers**.

**Exercises:** (a) Demonstrate that user B gets `404` when deleting A's history item. (b) Try a script tag in an AI-style report string; show it is displayed as text, not executed. (c) Explain why email verification and reset flows still matter before a public release.

## 5. Deterministic tools vs AI

- `services/static_analysis.py:compare()` calls `difflib.unified_diff` and reports changed lines. It compares **text**, not behavior. The two programs might be equivalent despite different syntax.
- `beautify()` invokes the Ruff CLI using stdin and a strict timeout. The submitted source is parsed/formatted, **never executed**. Only Python is supported.
- `security()` sends a temporary Python file to Bandit and parses its JSON findings with severity and line number. Static rules can miss vulnerabilities or return false positives; it is not a full OWASP audit.
- `services/gemini.py:call_gemini()` uses the async Google Gen AI client and a fixed system instruction. It protects the API key on the backend and catches provider timeouts. User content may still contain prompt injection. The model may hallucinate.

**Exercise:** Add 3 fixtures: SQL-injection-looking source, a Python `shell=True` example, and a malformed Python program. Record what each backend really detects, and do **not** claim full vulnerability coverage.

## 6. Complexity discussion example

```python
def has_duplicate(values):
    for i in range(len(values)):
        for j in range(i + 1, len(values)):
            if values[i] == values[j]:
                return True
    return False
```

Worst-case **O(n²) time, O(1) extra memory**. A set-based solution can obtain **O(n) expected time with O(n) extra memory** if average hash operations are constant time. Neither Gemini nor a static text diff constitutes formal proof. Add tests for `[]`, `[3]`, `[3,3]`, `[3,4]`, and large unique inputs. Discuss memory-vs-time tradeoffs.

## 7. Measure instead of guessing

`python scripts/benchmark.py` makes 35 unique `/api/compare` calls to a FastAPI `TestClient` (cold), then repeats the identical requests with opt-in cache (warm). It uses the real local code diff algorithm and SQLite. It does **not** measure public network time, real Gemini, model token usage or Railway runtime. The generated file `docs/BENCHMARK_RESULTS.md` reports cold/warm averages, medians, hit rate and percentage change.

**Exercise:** After Railway deployment, record: date, instance type, code commit, tool, input sizes, request counts, mean, p50, p95 and cache-hit rate. Run Gemini separately with controlled small non-sensitive input and make a clearly labeled table. Repeat runs and report variability rather than picking the best outcome.

## 8. Viva questions each member should be able to answer

1. How does a browser request reach a FastAPI router?
2. What is the purpose of a Pydantic model? What does 422 mean?
3. Why use async only for I/O-bound API calls, rather than for all CPU work?
4. Why is password hashing different from encrypting data?
5. Where is the session stored? How does revocation work?
6. Show a SQL query that prevents another user's report from being returned.
7. What are cold caches and warm caches? What invalidates a cache entry?
8. What prevents repeated identical AI requests from spending quota?
9. Why can a static security scanner miss vulnerabilities?
10. How does your UI avoid injecting untrusted HTML?
11. What limitations would you address before supporting many users?
12. Which changes did **you personally** implement, test, and debug?

## 9. Suggested team contribution assignments

These are proposed ownership areas—**not claims about who built the existing source**. Divide and record contributions truthfully:

- **Harshad Dhuppe:** backend API paths, pipeline/cache/quota, technical integration; demonstrate the cache and quota test.
- **Saurabh Shinde:** authentication/database/authorization, secure history and deletion; demonstrate the second-user isolation test.
- **Pradeep Kale:** responsive frontend, browser interactions, local tooling and benchmarks; demonstrate Ruff/Bandit tests and the design on mobile.

Every member should also be able to run the app from scratch and explain the whole architecture. Preserve commit history and real evidence of contributions for academic honesty.
