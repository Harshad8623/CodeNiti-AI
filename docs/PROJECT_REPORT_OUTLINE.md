# Final year major project report guide — कोडनीती AI

## Cover-page information (verify against your college's mandatory format)

**Title:** कोडनीती AI — AI Powered Code Intelligence Platform for Automated Optimization, Complexity Analysis & Security Auditing

**Institute:** CSMSS Chh. Shahu College of Engineering, Chhatrapati Sambhajinagar  
**Department:** Electronics & Computer Engineering  
**Academic year:** 2026–27  
**Guide:** Prof. J. N. Mohite

| College identifier | Enrollment number | Team member |
|---|---|---|
| EC4145 | 23025331844046 | DHUPPE HARSHAD MADHAV |
| EC4121 | 23025331844021 | SHINDE SAURABH BHAGAJI |
| EC4168 | 24025331844502 | KALE PRADEEP DYANESHWAR |

## Suggested contents

1. **Abstract:** Code review is often manual and time consuming. The project combines five Gemini-assisted development tasks with deterministic code diff, formatting and security checks. The prototype includes authenticated history, response caching and basic performance metrics. Do not claim accuracy/security benchmarks without evidence.
2. **Problem statement:** Repetitive code review, inconsistent formatting, misunderstanding complexity, and difficulty discovering common security misconfigurations.
3. **Objectives:** Offer understandable code reports; reduce duplicate provider requests; provide explicit privacy choices; supply reproducible diff/format/static-scan tools; support a simple responsive web workflow.
4. **Literature and technology review:** FastAPI/Pydantic REST APIs, Gemini and the limits of LLM reasoning, `difflib`, Ruff formatting, Bandit static checks, salted password hashes, TTL caching, relational SQL databases.
5. **Scope and constraints:** Python-only Ruff/Bandit, AI estimates vs proofs, no arbitrary code execution, single-worker SQLite backend, no email confirmation, and non-encrypted report storage.
6. **Requirements:** Python 3.11+, `requirements.txt`, local browser, optional Gemini API key; optional Railway deployment with a persistent volume.
7. **Architecture and design:** Browser → auth/security middleware → API routes → service layer → local tools or Gemini → memory/SQLite cache → SQLite user history/metrics.
8. **Database design:** Tables `users`, `sessions`, `history`, `response_cache`, `metrics`, `ai_quota`; primary keys, foreign-key constraints, user-scoped queries, cascading delete.
9. **Implementation:** Document source modules and APIs, input validation and error pathways, login flow, prompt boundaries and output rendering.
10. **Testing:** Endpoint tests, authorization isolation, quota/cache tests, input validation, adapter mocks, real installed Ruff/Bandit checks, browser interaction; record which tests ran locally and which await production credentials.
11. **Results:** Include screenshots, reproducible diff cache benchmark, sample format/security output after real binaries are installed, and observations about unsupported cases. Include sample size, hardware/runtime assumptions and variance.
12. **Security/privacy and limitations:** No secrets in source, password-hashed accounts, HttpOnly secure cookies in production, history opt-in, provider transmission warning, ruleset limitations and responsible deployment configuration.
13. **Conclusion and future scope:** Managed PostgreSQL/Redis, email verification, formal policy consent, richer language integrations, advanced tracing and carefully sandboxed execution only if required.
14. **References and appendices:** Cite official Google Gen AI, FastAPI, Ruff, Bandit, Railway and OWASP documentation; include GitHub link only after you publish it.

## Demo and viva checklist

- Explain the exact problem being solved and why a hybrid design is more credible than an AI-only wrapper.
- Demonstrate user registration and account-isolated history.
- Demonstrate a real Ruff formatting result, a real Bandit finding and a deterministic code diff; each requires their respective installed tool (apart from diff).
- Explain a Big-O example manually before showing AI estimates.
- Show cache misses and cache hits with controlled inputs; distinguish local benchmarks from live Gemini tests.
- Show mobile design, team credits, code architecture, test results and `git` contributions.
- Disclose limitations and AI assistance accurately; never describe unrun tests as executed.
