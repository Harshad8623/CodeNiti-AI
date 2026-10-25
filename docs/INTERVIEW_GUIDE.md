# कोडनीती AI — Interview preparation guide

Use this guide to practice answering questions **with the code open**. Never claim an implementation or optimization that you did not verify.

## Your 60-second overview

> Our project कोडनीती AI is a full-stack code intelligence workbench built using FastAPI, Pydantic, vanilla JavaScript and SQLite. It combines five Gemini-powered assistants with deterministic local diffs, Ruff Python formatting and Bandit static security checks. We added hashed-password accounts, user-specific saved history, a two-level cache, versioned SHA-256 cache keys, an account-scoped rate limiter, daily AI request quotas, and a responsive multilingual-branded interface. I built it to understand API design, safe handling of untrusted developer input, and the practical boundaries of AI output.

This is an *example script*. Change it to accurately reflect what you built and can demonstrate.

## Architecture decisions and interview answers

**Q1. Why FastAPI?** Typed Pydantic validation, automatic OpenAPI docs, and native async endpoints for network-bound Gemini calls. This is still a monolith; a microservice design would be unnecessary complexity for a portfolio demo.

**Q2. Why Python + SQLite?** Python is productive for AST/static analysis integrations. SQLite needs no separate DB server and supports indexes/transactions for a small single-instance app. PostgreSQL becomes useful with sustained concurrent writes or multi-instance production deployment.

**Q3. Why aren't all tools Gemini?** Deterministic tasks need reproducible results. Standard-library diff and Ruff formatting are exact within their semantics; Bandit offers a limited, auditable ruleset. Gemini is more suitable for reasoning and explanations. None of these guarantee behavior correctness.

**Q4. What is the cache key?** A SHA-256 fingerprint of workspace, tool, validated payload, engine, model name, and system prompt revision. Entries expire using a TTL. Results are cached only after explicit save consent. A cache key is not an encryption key.

**Q5. What's the difference between the memory and database cache?** Memory is fast but lost after restart and local to one process. SQLite persists until expiry and survives restarts. A memory miss can be served by the database; fresh output is promoted to memory. A multi-worker system would benefit from shared Redis.

**Q6. How do you handle errors?** Pydantic returns 422 for invalid payloads; missing configuration gets 503, upstream timeouts 504, quota/limits 429, and provider problems 502. Users don't see upstream stack traces or credentials.

**Q7. How does rate limiting work?** Login and registration requests are rate limited by remote IP; authenticated analysis POSTs are limited per signed-in account using a rolling 60-second window in a bounded map. This works for one application process only; scaling requires shared state.

**Q8. How do you prevent XSS?** The browser creates DOM nodes and assigns untrusted AI output with `textContent` instead of inserting arbitrary HTML. The response uses a restrictive Content Security Policy. This is defense in depth; validate dependencies and future UI changes.

**Q9. Why is history opt-in?** User code can include private source or secrets. The user must explicitly opt in before the server stores report content; when off, only timing metadata is recorded. Opted-in reports are stored as plaintext in SQLite and require a logged-in, authorized account to view. Gemini tools still send input to the provider.

**Q10. How do you prevent executing malicious snippets?** The FastAPI app never executes user-submitted source. Ruff formats and Bandit statically inspects source in limited-time subprocesses. There is no arbitrary code runner. If adding one, use an isolated sandbox and strict CPU/memory/network/file limits.

**Q11. What did you test?** FastAPI endpoints, input validation, mocked AI and cached responses, password-session authentication, two-account data isolation and deletion, same-origin request checks, per-account limits and daily AI quotas. Formatter and security adapters are tested with mocked subprocesses where Ruff/Bandit binaries aren't available. Browser interactions were exercised through TestClient-transport Playwright, not a live Railway URL.

**Q12. What is the biggest remaining weakness?** There is login, but no email verification or password reset; reports are stored in plaintext SQLite; the limiter and memory cache are single-process; production load, actual live model output, and public Internet latency remain untested. Larger-scale deployment would need shared state, a managed database and formal operational security review.

## DSA story to pair with your project

Use `has_duplicate(nums)`:

1. Naive nested loops: O(n²) time, O(1) auxiliary space.
2. Maintain a `set` of seen elements and return on duplicates: average O(n) time and O(n) auxiliary space (assuming average O(1) hash operations).
3. Test empty list, singleton, duplicates, and distinct values. Explain trade-offs and worst-case assumptions.

The project should complement **independent DSA problem-solving**, not replace it.

## Claims you should not make without real data

- "Reduced latency by 90%" — first measure multiple cold/warm trials and report sample sizes.
- "Prevents all attacks" — static checks and CSP do not eliminate all vulnerabilities.
- "Production scalable" — this is currently designed for a single worker.
- "AI computes exact Big-O" — complexity analysis is explanatory estimation unless formally verified.
- "It runs and verifies generated tests" — test code is generated, not executed.
- "Guaranteed 20 LPA project" — there is no such guarantee.

## Two demo paths

1. **Without API key:** Sign into a test account, select Diff & compare and show a deterministic diff. With dependencies installed, demo Ruff formatting and a known Bandit finding. Show the opt-in save-history control and that a second account cannot see the report.
2. **With Gemini key:** Explain an algorithm manually, request AI optimization, compare revisions, generate unit tests and discuss human validation. Demonstrate the first AI request using quota, the repeated saved request hitting the cache, and inspect your per-account metrics. Do not claim measurements obtained on Railway before performing them.
