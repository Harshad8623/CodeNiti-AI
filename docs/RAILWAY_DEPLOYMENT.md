# Railway deployment — कोडनीती AI

**Who deploys:** The student team. These are preparation instructions only. No account, public URL, network-bound model call, domain purchase or Railway billing operation was performed as part of this rebuild.

## Before you publish

1. Create a **private or public GitHub repository** containing only the clean project directory. Check that `.env`, `data/`, local SQLite files, test artifacts and credentials are ignored. `git status` must not show a secret.
2. Make a new **Gemini API key** in your own Google AI Studio account and set a spending/budget alert at the provider. Never put the key in code, a README screenshot, or GitHub Actions logs.
3. Decide whether the site is a classroom demonstration or publicly accessible. With public signup, you may incur AI costs; set `AI_DAILY_LIMIT` conservatively and consider `ENABLE_SIGNUP=false` once demonstration accounts exist. Public signup does not include email verification.
4. This is a **single worker** SQLite application. Do not scale replicas with this design. A larger public launch would require a managed database and shared quotas/limits.

## Railway setup

1. In Railway, **New Project → Deploy from GitHub repository**. Select the repository. The included `Dockerfile` and `railway.json` configure installation, one Uvicorn worker, the Railway-assigned `PORT`, and health checks at `/health`.
2. In **Variables**, add these keys (values are illustrative, not real credentials):

   ```dotenv
   GEMINI_API_KEY=<paste-your-own-key-in-Railway-Variables>
   GEMINI_MODEL=gemini-3.8-flash
   APP_ENV=production
   DATABASE_PATH=/data/codeniti.db
   ENABLE_SIGNUP=true
   AI_DAILY_LIMIT=10
   RATE_LIMIT_PER_MINUTE=20
   CACHE_TTL_SECONDS=86400
   # Railway root-owned volumes need this when the image uses a non-root user:
   RAILWAY_RUN_UID=0
   ```

   `PORT` is provided by Railway, so **do not** hardcode it. For a school demonstration, keep the AI daily quota low until you understand billing and expected traffic.
3. Add a **Railway Volume** to this service and set **Mount Path** to `/data`. The database is located at `/data/codeniti.db`. Railway's documentation currently states volumes are mounted as `root`; because the Docker image normally runs as the non-root user `appuser`, set `RAILWAY_RUN_UID=0` **for a Railway deployment using this volume**, or plan a different deployment model that permits a non-root process to write safely. Running as root reduces containment; reevaluate before broader public use. **Do not omit the volume** if you want accounts and saved reports to survive redeployment.
4. Deploy, then in service **Settings → Networking → Generate Domain**. Confirm the URL uses HTTPS. The app sets session cookies `Secure` when `APP_ENV=production`.
5. Open `https://<your-domain>/health` and confirm `{"status":"healthy",...}`. If health fails, inspect logs for import errors, Gemini configuration problems or SQLite folder permissions.

## Verify the real deployment (manually)

- Visit the HTTPS URL in a private browser window. Confirm the Devanagari title renders and the layout works on phone-width screens.
- Create **two separate test accounts** with **unique passwords**, sign in and out, and confirm that Account B cannot view Account A's saved results.
- Run **Compare code** without Gemini; run **Python formatter** and **Security audit** to validate Ruff and Bandit were included in the Docker image. Use a known Bandit example such as a Python subprocess with `shell=True` and review the warning.
- Run **Code optimisation** with a small non-sensitive snippet; this is the **first true end-to-end Google Gemini call**, and it requires your live key and network access. If it returns 429/502/503, inspect the server logs/configuration without exposing secrets.
- Enable **Save to my history**, run the same saved AI input twice and confirm the second says **CACHED**; inspect the per-account performance metrics. Cache reuse is per user and not equivalent to a universal speed-up claim.
- Reload and sign back in. Redeploy the service and check that login/history remain; this is the proof the persistent volume is working.
- Check source-code content is not accidentally logged. Disable public registration (`ENABLE_SIGNUP=false`) if the app is intended only for a fixed evaluation panel.

## Production cautions

- Rate limits are **in-process**. Authentication routes are limited per IP; analysis routes per signed-in account. Session store and quota counters are in SQLite. Running two workers/replicas would defeat reliable in-memory rate limiting.
- Password hashes are PBKDF2-HMAC (not plaintext), but saved code and AI responses are **not encrypted at rest**. Anyone with database access—including infrastructure operators—can access saved source. Avoid uploading confidential code.
- The app uses simple password authentication without email ownership verification, password reset, OAuth, MFA, or a full legal/privacy-policy workflow. These are meaningful gaps for a public service.
- Set volume backups in Railway as appropriate. Local or in-process benchmarks do not predict user-perceived Internet latency.
- Do not claim the deployed site, key, external SDK response, or Railway database lifecycle was verified unless **you** have followed the checks above and obtained evidence.

Official references: https://docs.railway.com/guides/fastapi , https://docs.railway.com/volumes , https://ai.google.dev/gemini-api/docs/models
