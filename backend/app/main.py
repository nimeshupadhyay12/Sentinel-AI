import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from app.core.database import engine, Base, SessionLocal
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.models import User, ActivityLog
from app.api import auth, users, activities, analytics, alerts, incidents, experiments, research_results, audit
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

APP_VERSION = "0.7.0"
logger = logging.getLogger("sentinel")

app = FastAPI(title="SentinelAI Enterprise Platform", version=APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# The SPA is self-hosted (no inline scripts, no CDNs), so a strict policy works.
# Recharts sets inline style attributes, hence style-src 'unsafe-inline'.
SPA_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
           "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
# Swagger UI / ReDoc load their bundles from a CDN; keep them working but framed-off.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://fastapi.tiangolo.com "
            "https://cdn.redoc.ly; worker-src 'self' blob:; frame-ancestors 'none'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    response.headers.setdefault(
        "Content-Security-Policy", DOCS_CSP if path in ("/docs", "/redoc") else SPA_CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    # Log server-side with the stack trace; never echo internals to the client.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# API routes
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(activities.router)
app.include_router(analytics.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(experiments.router)
app.include_router(research_results.router)
app.include_router(audit.router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "sentinel-ai",
            "platform": "SentinelAI Enterprise Platform", "version": APP_VERSION}


def resolve_frontend_file(dist: Path, requested: str) -> Path | None:
    """Map a URL path to a file strictly inside the built SPA directory.

    Returns None for anything that escapes ``dist`` (``..``, encoded separators,
    absolute or drive-qualified paths) or is not a regular file.
    """
    if not requested or "\x00" in requested:
        return None
    root = dist.resolve()
    try:
        candidate = (root / requested).resolve()
    except (OSError, ValueError):
        return None
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def find_frontend_dist() -> Path | None:
    base_dir = Path(__file__).resolve().parents[2]
    for candidate in (base_dir / "frontend" / "dist", Path("frontend/dist").resolve(),
                      Path("../frontend/dist").resolve(), Path("/app/frontend/dist")):
        if (candidate / "index.html").is_file():
            return candidate
    return None


FRONTEND_DIST = find_frontend_dist()
API_PREFIXES = ("api/", "docs", "redoc", "openapi.json", "health")

if FRONTEND_DIST:
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend_spa(full_path: str):
        if full_path.startswith(API_PREFIXES):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        file_path = resolve_frontend_file(FRONTEND_DIST, full_path)
        if file_path is not None:
            return FileResponse(file_path)
        if "/" in full_path.strip("/") and "." in full_path.rsplit("/", 1)[-1]:
            # A missing asset-like path should 404 rather than return index.html.
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "platform": "SentinelAI Enterprise Platform",
            "status": "ONLINE",
            "health": "/health",
            "api_docs": "/docs"
        }
