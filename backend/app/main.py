import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.core.database import engine, Base, SessionLocal
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.models import User, ActivityLog
from app.api import auth, users, activities, analytics, alerts, incidents, experiments, research_results
from app.core.migrations import upgrade_schema



def bootstrap_defaults():
    """Create optional starter accounts only when explicit passwords are configured."""
    db = SessionLocal()
    try:
        starter_accounts = [
            ("admin", "admin@sentinelai.local", "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD", "Admin"),
            ("analyst", "analyst@sentinelai.local", "SENTINEL_BOOTSTRAP_ANALYST_PASSWORD", "Analyst"),
            ("insider_target", "user@sentinelai.local", "SENTINEL_BOOTSTRAP_USER_PASSWORD", "User"),
        ]

        for username, email, password_env, role in starter_accounts:
            password = getattr(settings, password_env)
            existing = db.query(User).filter(User.username == username).first()
            if password and not existing:
                db.add(User(
                    username=username,
                    email=email,
                    hashed_password=get_password_hash(password),
                    role=role,
                ))

        db.flush()

        # Add harmless sample telemetry only for accounts that actually exist.
        if db.query(ActivityLog).count() == 0:
            users = {
                user.username: user.id
                for user in db.query(User).filter(
                    User.username.in_(["admin", "analyst", "insider_target"])
                ).all()
            }
            sample_specs = [
                ("admin", "LOGIN_SUCCESS", 0.2, False, 0, 2, 3600.0),
                ("analyst", "DOCUMENT_QUERY", 12.4, False, 0, 1, 1800.0),
                ("insider_target", "FILE_READ", 4.8, False, 0, 0, 1200.0),
            ]
            sample_logs = [
                ActivityLog(
                    user_id=users[username],
                    action_type=action,
                    bytes_transferred=transferred,
                    is_sensitive_file=sensitive,
                    failed_attempts=failed,
                    privilege_level=privilege,
                    session_duration_sec=duration,
                )
                for username, action, transferred, sensitive, failed, privilege, duration in sample_specs
                if username in users
            ]
            if sample_logs:
                db.add_all(sample_logs)

        db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    upgrade_schema(engine)
    bootstrap_defaults()
    yield

app = FastAPI(title="SentinelAI Enterprise Platform", version="0.6.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(activities.router)
app.include_router(analytics.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(experiments.router)
app.include_router(research_results.router)

@app.get("/health")
def health():
    return {"status": "healthy", "service": "sentinel-ai", "platform": "SentinelAI Enterprise Platform", "version": "0.6.0"}

# Frontend SPA distribution discovery
base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
possible_dist_paths = [
    os.path.join(base_dir, "frontend", "dist"),
    os.path.abspath("frontend/dist"),
    os.path.abspath("../frontend/dist"),
    "/app/frontend/dist"
]
FRONTEND_DIST = next((p for p in possible_dist_paths if os.path.exists(p) and os.path.exists(os.path.join(p, "index.html"))), None)

if FRONTEND_DIST:
    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    def serve_frontend_spa(full_path: str):
        if full_path.startswith("api/") or full_path in ("health", "docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "platform": "SentinelAI Enterprise Platform",
            "status": "ONLINE",
            "health": "/health",
            "api_docs": "/docs"
        }
