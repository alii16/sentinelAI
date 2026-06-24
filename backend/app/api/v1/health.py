"""Sentinel AI - Health Check API."""
from fastapi import APIRouter
from app.utils.response import ok

router = APIRouter()

@router.get("/health")
async def health():
    return ok({
        "status": "healthy",
        "service": "Sentinel AI",
        "version": "1.0.0"
    })
