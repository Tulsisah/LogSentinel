# Production Deployment Guide: AI-Based Log Analyzer & SOC Platform

This guide outlines how to deploy the AI LogSec platform to production.

---

## Deployment Options

Choose the deployment architecture that best fits your requirements:

| Option | Architecture | Complexity | Best For |
| :--- | :--- | :--- | :--- |
| **Option 1: Single Service (Render / Railway / Fly.io)** | FastAPI serves both API and React UI | ⭐ Simplest & Cheapest (1 free web service) | Quick deployment, portfolios, small SOC teams |
| **Option 2: Docker Container (VPS / DigitalOcean / AWS)** | Multi-stage Docker container (+ optional PostgreSQL) | ⭐⭐ Highly Portable | Self-hosted servers, corporate internal networks |
| **Option 3: Decoupled (Vercel Frontend + Render Backend)** | Frontend on Vercel CDN, Backend on Render/Railway | ⭐⭐ Scalable | High traffic, CDN caching for frontend |

---

## Option 1: Single Service on Render (Recommended & Simplest)

In this approach, Render builds both the frontend and backend, and the FastAPI server serves both from a single URL.

1. **Push your code to GitHub / GitLab**.
2. Go to [Render.com](https://render.com) and click **New +** → **Web Service**.
3. Connect your repository.
4. Set the following configuration:
   - **Environment**: `Python 3`
   - **Region**: Closest to you (e.g., Oregon, Frankfurt, Singapore)
   - **Build Command**:
     ```bash
     cd frontend && npm install && npm run build && cd ../backend && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
5. In **Environment Variables**, add:
   - `JWT_SECRET`: *(Generate a 32+ character random secret, e.g. using `python -c "import secrets; print(secrets.token_hex(32))"`)*
   - `DATABASE_URL`: *(Optional: If using Supabase / Neon / Render Postgres; leave empty to use local SQLite disk)*
6. Click **Deploy Web Service**.
7. Once deployed, open your Render URL (e.g. `https://log-analyzer.onrender.com`). The SOC Dashboard and all API endpoints are fully active!

---

## Option 2: Docker Deployment (Single Container / VPS)

### Using Docker Directly:
```bash
# 1. Build the production image
docker build -t log-analyzer .

# 2. Run the container
docker run -d \
  -p 8000:8000 \
  -e JWT_SECRET="your-secure-random-secret-key-here" \
  -v log_analyzer_data:/app/backend \
  --name log-analyzer-app \
  log-analyzer
```
Access the application at `http://YOUR_SERVER_IP:8000`.

### Using Docker Compose (With PostgreSQL):
```bash
# 1. Copy the environment file and set your JWT secret
cp .env.example .env

# 2. Launch backend and PostgreSQL
docker-compose up -d --build
```
Both the application and PostgreSQL will start automatically, with database persistence in `pgdata`.

---

## Option 3: Decoupled Deployment (Vercel + Render / Railway)

### Step A: Deploy Backend (Render or Railway)
1. In Render, deploy repository with Root Directory set to `backend`:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
2. Set Environment Variables:
   - `JWT_SECRET`: *Your random secret key*
   - `ALLOWED_ORIGINS`: `https://your-frontend-project.vercel.app` (your Vercel domain)
   - `DATABASE_URL`: *PostgreSQL connection string (Supabase / Neon)*
3. Note your backend URL (e.g. `https://log-analyzer-api.onrender.com`).

### Step B: Deploy Frontend (Vercel)
1. Go to [Vercel.com](https://vercel.com) and import your Git repository.
2. Set **Root Directory** to `frontend`.
3. Framework Preset will automatically detect **Vite**.
4. In **Environment Variables**, add:
   - `VITE_API_URL`: `https://log-analyzer-api.onrender.com/api` (your deployed backend URL + `/api`)
5. Click **Deploy**.

---

## Environment Variables Reference

| Variable | Required in Production? | Description | Example Value |
| :--- | :--- | :--- | :--- |
| `JWT_SECRET` | **YES** (Crucial) | Secret used to sign analyst authentication tokens. | `e4f9b8c2...32chars` |
| `DATABASE_URL` | Recommended for Cloud | PostgreSQL or SQLite database URI. | `postgresql://user:pass@host:5432/dbname` |
| `ALLOWED_ORIGINS` | If Decoupled | Comma-separated list of allowed frontend domains for CORS. | `https://my-app.vercel.app` |
| `PORT` | Auto-provided by hosts | Port the server listens on (defaults to 8000). | `8000` or `$PORT` |
| `VITE_API_URL` | Only if Decoupled | Backend API base URL for frontend client requests. | `https://api.my-soc.com/api` |

---

## Post-Deployment Verification Checklist

1. [ ] **Health Check**: Open `https://<YOUR_DOMAIN>/api/health` and verify `{"status": "ok"}`.
2. [ ] **Swagger Documentation**: Open `https://<YOUR_DOMAIN>/docs` and check that all SOC routes are registered.
3. [ ] **SOC Dashboard UI**: Open `https://<YOUR_DOMAIN>/` to ensure the React interface loads and renders charts.
4. [ ] **Sample Ingestion Test**: Navigate to `/upload` and click **Load Sample Logs** to verify database writing, rule correlation, and Isolation Forest ML scoring.
