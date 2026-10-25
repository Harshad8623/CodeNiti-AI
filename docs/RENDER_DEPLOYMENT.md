# Deploying CodeNiti AI to Render

This guide outlines how to deploy CodeNiti AI to [Render](https://render.com/) for free.

---

## Method 1: Automatic Deployment using Blueprint (`render.yaml`)

1. Push your repository to GitHub.
2. Log into [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** and select **Blueprint**.
4. Connect your GitHub repository.
5. Render will automatically detect `render.yaml` and configure the Python web service.
6. When prompted for environment variables:
   - Provide your `GEMINI_API_KEY` (from [Google AI Studio](https://aistudio.google.com/)).
7. Click **Apply**. Render will build and deploy your application.

---

## Method 2: Manual Web Service Deployment

1. On the Render Dashboard, click **New +** $\rightarrow$ **Web Service**.
2. Select your GitHub repository (`CodeNiti-AI`).
3. Fill in the following settings:
   - **Name:** `codeniti-ai` (or your choice)
   - **Region:** Any (e.g., Singapore or Frankfurt for low latency in India)
   - **Branch:** `main`
   - **Root Directory:** *(leave blank)*
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`
   - **Plan Type:** `Free`

4. Expand the **Environment Variables** section and add:
   - `GEMINI_API_KEY`: *(Your Google AI Studio API key)*
   - `GEMINI_MODEL`: `gemini-2.5-flash`
   - `APP_ENV`: `production`
   - `ENABLE_SIGNUP`: `true`
   - `AI_DAILY_LIMIT`: `30`
   - `RATE_LIMIT_PER_MINUTE`: `20`

5. Click **Create Web Service**.
6. Render will assign you a public URL (e.g., `https://codeniti-ai.onrender.com`).
