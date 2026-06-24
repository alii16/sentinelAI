"""
Sentinel AI - Backend Application
Autonomous Multi-Agent AI Security Auditor
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import logging
import uvicorn

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1 import (
    auth, users, websites, scans, reports,
    ai, crawler, scanner, datasets, admin, dashboard, notifications, health
)
from app.websocket.scan_ws import router as ws_router
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.middleware.request_logger import RequestLoggerMiddleware

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinel-ai")

# App instance
app = FastAPI(
    title="Sentinel AI",
    description="Autonomous Multi-Agent AI Security Auditor API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ─────────────────────────────────────────────
# Middleware
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(RateLimiterMiddleware)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ─────────────────────────────────────────────
# Global exception handler
# ─────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "Internal Server Error"}
    )

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
PREFIX = "/api/v1"

app.include_router(health.router,         prefix=PREFIX,            tags=["Health"])
app.include_router(auth.router,           prefix=f"{PREFIX}/auth",  tags=["Auth"])
app.include_router(users.router,          prefix=f"{PREFIX}/users", tags=["Users"])
app.include_router(websites.router,       prefix=f"{PREFIX}/websites", tags=["Websites"])
app.include_router(scans.router,          prefix=f"{PREFIX}/scans", tags=["Scans"])
app.include_router(reports.router,        prefix=f"{PREFIX}/reports", tags=["Reports"])
app.include_router(ai.router,             prefix=f"{PREFIX}/ai",    tags=["AI"])
app.include_router(datasets.router,       prefix=f"{PREFIX}/datasets", tags=["Datasets"])
app.include_router(dashboard.router,      prefix=f"{PREFIX}/dashboard", tags=["Dashboard"])
app.include_router(notifications.router,  prefix=f"{PREFIX}/notifications", tags=["Notifications"])
app.include_router(admin.router,          prefix=f"{PREFIX}/admin", tags=["Admin"])
app.include_router(ws_router,             prefix="",                tags=["WebSocket"])

@app.on_event("startup")
async def startup():
    logger.info("Sentinel AI starting up...")
    # Create tables if they don't exist (Alembic handles migrations)
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)
    logger.info("Sentinel AI ready.")

@app.on_event("shutdown")
async def shutdown():
    logger.info("Sentinel AI shutting down.")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
