# Free Render deployment (public portfolio demonstration)

This project provides a single-service, Docker-based deployment that serves the
React dashboard and FastAPI API from the SAME domain. A PUBLIC READ-ONLY
mode uses fictional security events. There is no public log uploading, editing,
incident notes, or reset action.

## Publish to GitHub

Create a new GitHub repo, e.g. `Sentinel-SOC`, on your `subzero443` account.
From PowerShell (folder containing `Dockerfile`, `frontend`, and `backend`):

```powershell
cd "C:\Users\INVESTOR\Desktop\soc-sentinel-live"
git init
git add .
git commit -m "Add Sentinel SOC dashboard with public demo deployment"
git branch -M main
git remote add origin https://github.com/subzero443/Sentinel-SOC.git
git push -u origin main
```

If you're already in a git repository, do not repeat `git init` or
`git remote add`; instead commit and push your changes as normal.

## Deploy to Render

1. Visit https://dashboard.render.com/ and log in using GitHub.
2. Select **New > Web Service**.
3. Connect the `Sentinel-SOC` repository.
4. Set **Name** to an available name, such as `subzero-sentinel-soc`.
5. Set **Language / Runtime** to **Docker**.
6. Choose the **Free** plan and leave **Dockerfile Path** as `./Dockerfile`.
7. Leave the root directory blank. Set the health-check path to `/api/health` if shown.
8. Select **Deploy Web Service**.
9. Render builds React and FastAPI and provides an HTTPS `onrender.com` URL.

No custom Python start or Node build command is necessary: the Dockerfile
contains both. No API key is required.

## Verify the deployment

- `https://YOUR-SERVICE.onrender.com/` — React dashboard
- `https://YOUR-SERVICE.onrender.com/api/health` — live backend
- `https://YOUR-SERVICE.onrender.com/api/overview` — demo totals

Public read-only safety check (should respond **403**):

```powershell
Invoke-WebRequest -Method Post -Uri 'https://YOUR-SERVICE.onrender.com/api/demo/reset'
```

## Free-host limitations

- Render Free may spin down after 15 minutes idle; waking can take about a minute.
- Local SQLite changes do NOT persist after sleep/restart/redeployment.
- When the public demo restarts, it automatically recreates synthetic examples.
- Use locally for interactive analyst notes, log imports, demo resets, and status changes.
- Never upload real logs or store credentials in this public portfolio app.
- This is NOT an authenticated, production-ready SOC platform.

## Continue using your local development setup

Existing local commands still work:

- Python: `cd backend`; then `python -m uvicorn app.main:app --reload --port 8000`
- React: `cd frontend`; then `npm run dev`

The demo mode only enables inside Docker because the Dockerfile sets
`SOC_PUBLIC_DEMO=1` and `VITE_PUBLIC_DEMO=true`.
