import os
from dotenv import load_dotenv

# Load environment variables from .env before importing application modules
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .database import models, database
from .routes import logs, alerts, dashboard, incidents, ips, rules, reports, history, copilot, auth

# Safe auto-migration of database tables and columns
database.run_auto_migrations()
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="AI-Based Log Analyzer & SOC Security Engine",
    description="Enterprise Blue Team Security Intelligence Platform with Anomaly Detection, Threat Correlation, and AI SOC Copilot",
    version="2.0.0"
)

# Configure CORS dynamically
raw_origins = os.environ.get("ALLOWED_ORIGINS", "")
if raw_origins.strip() == "*":
    allow_origins = ["*"]
    allow_credentials = False
elif raw_origins.strip():
    allow_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    allow_credentials = True
else:
    # Default permissive development origins
    allow_origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]
    allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(logs.router, prefix="/api/logs", tags=["Logs"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(ips.router, prefix="/api/ips", tags=["IP Analysis"])
app.include_router(rules.router, prefix="/api/rules", tags=["Custom Rules"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(history.router, prefix="/api/history", tags=["Analysis History"])
app.include_router(copilot.router, prefix="/api/copilot", tags=["AI Copilot"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "message": "AI-LogSec Analytics Engine is active",
        "version": "2.0.0"
    }

# Optional SPA static serving if frontend is built
possible_dist_paths = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "frontend", "dist"),
    os.path.join(os.getcwd(), "frontend", "dist"),
    os.path.join(os.getcwd(), "dist"),
]

FRONTEND_DIST = None
for path in possible_dist_paths:
    if os.path.isdir(path) and os.path.exists(os.path.join(path, "index.html")):
        FRONTEND_DIST = path
        break

if FRONTEND_DIST:
    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.isdir(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))


