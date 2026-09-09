"""
SecureCloud 2.0 - FastAPI Application Root
"Secure Storage. Intelligent Protection."
"""

import os
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

from backend.app.database import engine, Base
from backend.app.config import BASE_DIR
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
    title="SecureCloud 2.0 - Threat Detection & Security Intelligence Engine",
    description="Production-grade cloud storage with integrated ML threat classification and SOC intelligence.",
    version="2.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_origin_regex=r"^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$|^https:\/\/.*\.railway\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Telemetry middleware to count API calls
@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    increment_request_count()
    response = await call_next(request)
    # Add Security Headers (Allowing Same-Origin Iframes for Document/PDF Previews)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
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
    return {
        "status": "healthy",
        "service": "SecureCloud 2.0",
        "app": "SecureCloud 2.0",
        "ml_engine": "ONLINE",
        "threat_engine": "ONLINE",
        "security_policy": "STRICT_ROLE_ISOLATION"
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
