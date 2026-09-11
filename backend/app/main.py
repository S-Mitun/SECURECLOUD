"""
SecureCloud - FastAPI Application Root
"Secure Storage. Intelligent Protection."
"""

import os
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

from backend.app.database import engine, Base
from backend.app.config import BASE_DIR, CORS_ORIGINS
from backend.app.services.telemetry_service import increment_request_count

# Import all API routers
from backend.app.api.auth import router as auth_router
from backend.app.api.files import router as files_router
from backend.app.api.shares import router as shares_router
from backend.app.api.confidential import router as confidential_router
from backend.app.api.recycle_bin import router as recycle_bin_router
from backend.app.api.ml import router as ml_router
from backend.app.api.soc import router as soc_router
from backend.app.api.telemetry import router as telemetry_router
from backend.app.api.reports import router as reports_router
from backend.app.api.notifications import router as notifications_router

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecureCloud - Threat Detection & Security Intelligence Engine",
    description="Production-grade cloud storage with integrated ML threat classification and SOC intelligence.",
    version="2.0.0"
)

# CORS Middleware (Configurable via CORS_ORIGINS with safe defaults)
cors_origins_list = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]
if CORS_ORIGINS:
    extra_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
    cors_origins_list.extend(extra_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins_list,
    allow_origin_regex=r"^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$|^https:\/\/.*\.railway\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Telemetry & Security Headers Middleware
@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    increment_request_count()
    response = await call_next(request)
    # Practical Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Register Routers
app.include_router(auth_router)
app.include_router(files_router)
app.include_router(shares_router)
app.include_router(confidential_router)
app.include_router(recycle_bin_router)
app.include_router(ml_router)
app.include_router(soc_router)
app.include_router(telemetry_router)
app.include_router(reports_router)
app.include_router(notifications_router)

# Mount Frontend static files for Unified URL access on Railway / Local Port 8000
frontend_dir = BASE_DIR / "frontend"
dist_dir = frontend_dir / "dist"

if os.path.exists(dist_dir / "assets"):
    app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

if os.path.exists(frontend_dir / "css"):
    app.mount("/css", StaticFiles(directory=str(frontend_dir / "css")), name="css")
if os.path.exists(frontend_dir / "js"):
    app.mount("/js", StaticFiles(directory=str(frontend_dir / "js")), name="js")

@app.get("/")
async def root_index():
    target_index = dist_dir / "index.html" if os.path.exists(dist_dir / "index.html") else frontend_dir / "index.html"
    return FileResponse(str(target_index))

@app.get("/health")
def health_check():
    """
    Production health check returning real, honest operational status of
    Database, Storage, ML Engine, and Malware Scanner without exposing secrets.
    """
    # 1. Database check
    db_status = "connected"
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"degraded ({type(e).__name__})"

    # 2. Storage check
    from backend.app.services.storage_service import get_active_storage_info
    storage_info = get_active_storage_info()
    storage_status = "s3-connected" if storage_info["provider"] == "s3" else "local-storage"

    # 3. ML status check
    ml_status = "ready"
    from backend.app.config import ML_DIR
    model_path = ML_DIR / "models" / "active_model.joblib"
    if not model_path.exists():
        ml_status = "model-unavailable"

    # 4. Malware scanner check
    from scanner.scanner_service import unified_scanner
    clam_avail = unified_scanner.clamav.is_available()
    scanner_status = "clamav-active" if clam_avail else "Signature scanner unavailable; static/ML analysis continued."

    return {
        "status": "ok",
        "database": db_status,
        "storage": storage_status,
        "ml": ml_status,
        "scanner": scanner_status
    }

@app.get("/{full_path:path}")
async def serve_spa_route(full_path: str):
    # Do not intercept API, metrics, or docs routes
    if full_path.startswith("api/") or full_path in ["metrics", "docs", "openapi.json", "redoc"]:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    
    # Check if a static asset exists in dist directly (e.g. vite.svg, favicon.ico)
    candidate = dist_dir / full_path
    if candidate.is_file():
        return FileResponse(str(candidate))
    
    target_index = dist_dir / "index.html" if os.path.exists(dist_dir / "index.html") else frontend_dir / "index.html"
    return FileResponse(str(target_index))
