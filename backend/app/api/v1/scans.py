"""Sentinel AI - Scans API."""
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Scan, Website, ScanLog, ScanProgress, ScanQueue, Notification
from app.utils.response import ok, fail
from app.utils.activity import log_activity
from datetime import datetime, timezone

router = APIRouter()


class ScanCreate(BaseModel):
    website_id: int
    mode: str = "standard"
    max_depth: int = 5
    max_pages: int = 1000
    timeout_ms: int = 10000


def scan_to_dict(s: Scan):
    return {
        "id": s.id, "website_id": s.website_id, "user_id": s.user_id,
        "mode": s.mode, "status": s.status,
        "max_depth": s.max_depth, "max_pages": s.max_pages,
        "security_score": float(s.security_score) if s.security_score else None,
        "grade": s.grade, "risk_level": s.risk_level,
        "total_pages": s.total_pages, "total_endpoints": s.total_endpoints,
        "total_findings": s.total_findings,
        "critical_count": s.critical_count, "high_count": s.high_count,
        "medium_count": s.medium_count, "low_count": s.low_count,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "duration_seconds": s.duration_seconds,
        "created_at": s.created_at.isoformat()
    }


@router.post("")
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Verify website ownership
    website = (await db.execute(
        select(Website).where(Website.id == body.website_id, Website.user_id == current_user.id, Website.deleted_at.is_(None))
    )).scalar_one_or_none()
    if not website:
        return fail("Website tidak ditemukan", 404)

    # Create scan
    scan = Scan(
        website_id=body.website_id, user_id=current_user.id,
        mode=body.mode, max_depth=body.max_depth,
        max_pages=body.max_pages, timeout_ms=body.timeout_ms
    )
    db.add(scan)
    await db.flush()

    # Create progress record
    progress = ScanProgress(scan_id=scan.id, current_agent="Menunggu")
    db.add(progress)

    # Create queue entry
    queue = ScanQueue(scan_id=scan.id, priority=5)
    db.add(queue)

    await db.commit()
    await db.refresh(scan)

    # Notify
    notif = Notification(user_id=current_user.id, type="scan_started",
                         title="Scan dimulai", body=f"Scan untuk {website.name} telah dimulai")
    db.add(notif)
    await db.commit()

    # Start background scan
    from app.ai.orchestrator.orchestrator import run_scan_pipeline
    background_tasks.add_task(run_scan_pipeline, scan.id, website.url)

    await log_activity(db, current_user.id, "start_scan", "scan", scan.id)
    return ok(scan_to_dict(scan), 201)


@router.get("")
async def list_scans(
    page: int = 1, limit: int = 10,
    current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    q = select(Scan).where(Scan.user_id == current_user.id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    scans = (await db.execute(q.order_by(Scan.created_at.desc()).offset((page-1)*limit).limit(limit))).scalars().all()
    return ok({"items": [scan_to_dict(s) for s in scans], "total": total, "page": page, "limit": limit})


@router.get("/history")
async def scan_history(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(
        select(Scan).where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc()).limit(50)
    )).scalars().all()
    return ok([scan_to_dict(s) for s in scans])


@router.get("/{scan_id}")
async def get_scan(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)
    return ok(scan_to_dict(scan))


@router.get("/{scan_id}/progress")
async def scan_progress(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)
    prog = (await db.execute(select(ScanProgress).where(ScanProgress.scan_id == scan_id))).scalar_one_or_none()
    return ok({
        "progress": prog.percentage if prog else 0,
        "current_agent": prog.current_agent if prog else "",
        "status": scan.status,
        "pages_found": prog.pages_found if prog else 0,
        "endpoints_found": prog.endpoints_found if prog else 0,
        "stages": {
            "discovery": prog.discovery_pct if prog else 0,
            "technology": prog.technology_pct if prog else 0,
            "endpoint": prog.endpoint_pct if prog else 0,
            "scanner": prog.scanner_pct if prog else 0,
            "verification": prog.verification_pct if prog else 0,
            "report": prog.report_pct if prog else 0,
        }
    })


@router.get("/{scan_id}/logs")
async def scan_logs(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    logs = (await db.execute(
        select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at)
    )).scalars().all()
    return ok([{"id": l.id, "level": l.level, "agent": l.agent, "message": l.message,
                "created_at": l.created_at.isoformat()} for l in logs])


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)
    scan.status = "cancelled"
    await db.commit()
    return ok({"message": "Scan dibatalkan"})


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)
    await db.delete(scan)
    await db.commit()
    return ok(None, 204, "Scan dihapus")


@router.get("/{scan_id}/website")
async def get_scan_website(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get the website associated with a scan."""
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)

    website = (await db.execute(
        select(Website).where(Website.id == scan.website_id)
    )).scalar_one_or_none()

    if not website:
        return fail("Website tidak ditemukan", 404)

    return ok({
        "id":          website.id,
        "name":        website.name,
        "url":         website.url,
        "domain":      website.domain,
        "category":    website.category,
        "description": website.description,
        "status":      website.status,
    })
