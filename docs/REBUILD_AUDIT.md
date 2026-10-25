# Rebuild audit and verification record — कोडनीती AI v3.0

## Source and cleanup

Original user archive: `AI-code-inteligence.zip`, containing parallel FastAPI, Node/Express and React/Vite implementations, `node_modules`, old local databases and `.env` files. The deliverable retains the FastAPI implementation with a new dependency-free frontend. Secrets, original databases, `.git`, compiled bytecode, local environments and old dependencies are excluded from the final ZIP.

## Changes and fixes

| Category | Implemented change |
|---|---|
| Academic identity | Devanagari wordmark, official requested project subtitle, college/department, year, full team IDs/enrollments and guide |
| UI | Custom CSS with neutral green/cream styling, responsive desktop/mobile layout, keyboard shortcut, history/performance/project drawers, safe report rendering |
| Server | Typed FastAPI routes, async Gemini integration via `google-genai`, configurable supported model, meaningful sanitized upstream errors |
| Account access | PBKDF2-HMAC-SHA256 hashes with unique salts, revocable random session tokens, HttpOnly cookies, account-scoped SQL, account removal |
| Privacy | Report contents stored only when explicitly opted in; private reports are user-scoped; code not saved in performance metrics |
| Local tools | Deterministic difflib, Ruff formatting and Bandit security scanning (no submitted source execution) |
| Caching | SHA-256 fingerprint with user/tool/request/model/version, TTL memory cache plus SQLite, opt-in-only caching, account isolation |
| Rate controls | Login/signup attempts limited by IP; authenticated analysis rate-limited by account; daily AI quota charged for new provider requests only (cached responses exempt) |
| Debugging | Fixed blocking Gemini call, unsafe exception disclosure, stale cache keys, unbounded limiter storage, unnecessary quota charges on cache hits, sign-out being rate-limited |
| Deployment | Dockerfile, railway.json, `.env.example`, one-worker settings, `/health`, Railway volume instructions and production-cookie config |
| Documentation | Technical ownership workbook, architecture, reproducible benchmark, major-project report outline and Railway checklist |

## Automated verification

- `python -m pytest -q`: **17 passed, 2 skipped**. Real Ruff and Bandit binary integration tests are skipped when binaries are unavailable in this isolated environment; their adapter logic is separately tested with mocked subprocess responses.
- Python `compileall` passed; `node --check static/js/app.js` passed.
- A real HTTP smoke test script now covers `/health`, registration, session cookie use, local diff, private history, metrics and disposable-account deletion against a running app.
- Browser interactions passed using Playwright with browser requests routed through an in-process FastAPI `TestClient`: registration, logout/login, diff analysis, account history, metrics, project/team panel, mobile navigation, without JavaScript exceptions. These are **not** real public-network E2E tests.
- Performance measured with a reproducible, real TestClient / SQLite / difflib workload. See `docs/BENCHMARK_RESULTS.md` for actual local measurements and conditions. It **does not** measure live Gemini or Railway network latency.

## Not verified and known limitations

- **Not deployed by this build.** Owner will publish to Railway and set public domain, persistent volume and secrets.
- **Live Gemini API call not performed.** Requires the owner's live key and network. Test the configured model after deployment.
- **Real Ruff/Bandit process runs not verified here.** Dependencies are declared for installation; re-run both tests after installation.
- **No real HTTP browser-to-Railway test performed.** Browser automation used a TestClient transport because direct local browser networking was blocked in the build environment.
- Public accounts have no email verification, password reset or MFA. User reports reside unencrypted in SQLite; authenticated access is enforced at the application layer.
- Process-local rate limiting/cache and SQLite limit safe scale-out. No distributed quota enforcement, production security certification or load testing is claimed.

## Recommended acceptance test before college presentation

1. Clean venv installation on a teammate's Windows laptop.
2. Run `pytest -q` with Ruff and Bandit installed; expect the 2 previously skipped real CLI tests to execute.
3. Create two test users, verify report isolation, account deletion and sign-out.
4. Demonstrate all 8 tool endpoints. Five AI tools require a live key; the three local tools must work without one.
5. Record at least one **real live Gemini response** and screenshot the result only if it contains no personal secrets.
6. Deploy to Railway, attach a persistent volume, and verify logins/history after a redeploy.
7. Record real deployed response timings and separate them from in-process benchmark values.
8. Review documentation and explain accurately which source/test changes each student personally made.
