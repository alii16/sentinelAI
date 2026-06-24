"""Sentinel AI - Dashboard API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Website, Scan, AIPrediction
from app.utils.response import ok

router = APIRouter()


@router.get("/statistics")
async def statistics(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    uid = current_user.id
    total_websites = (await db.execute(
        select(func.count()).select_from(Website).where(Website.user_id == uid, Website.deleted_at.is_(None))
    )).scalar() or 0
    total_scans = (await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == uid)
    )).scalar() or 0
    completed = (await db.execute(
        select(Scan).where(Scan.user_id == uid, Scan.status == "completed")
        .order_by(Scan.completed_at.desc()).limit(1)
    )).scalar_one_or_none()
    running = (await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == uid, Scan.status == "running")
    )).scalar() or 0

    # Aggregate severity from all scans
    scans = (await db.execute(
        select(Scan).where(Scan.user_id == uid, Scan.status == "completed")
    )).scalars().all()
    critical = sum(s.critical_count for s in scans)
    high = sum(s.high_count for s in scans)
    medium = sum(s.medium_count for s in scans)
    low = sum(s.low_count for s in scans)
    avg_score = sum(float(s.security_score or 0) for s in scans) / max(len(scans), 1)

    return ok({
        "website": total_websites,
        "scan": total_scans,
        "running": running,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "security_score": round(avg_score, 1),
        "last_score": float(completed.security_score) if completed and completed.security_score else None,
        "last_grade": completed.grade if completed else None,
    })


@router.get("/chart/security-score")
async def chart_security_score(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(
        select(Scan).where(Scan.user_id == current_user.id, Scan.status == "completed", Scan.security_score.isnot(None))
        .order_by(Scan.completed_at.desc()).limit(10)
    )).scalars().all()
    data = [{"date": s.completed_at.strftime("%d/%m") if s.completed_at else "-",
              "score": float(s.security_score), "grade": s.grade} for s in reversed(scans)]
    return ok(data)


@router.get("/chart/severity")
async def chart_severity(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(
        select(Scan).where(Scan.user_id == current_user.id, Scan.status == "completed")
    )).scalars().all()
    return ok({
        "critical": sum(s.critical_count for s in scans),
        "high": sum(s.high_count for s in scans),
        "medium": sum(s.medium_count for s in scans),
        "low": sum(s.low_count for s in scans),
    })


@router.get("/chart/activity")
async def chart_activity(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(
        select(Scan).where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc()).limit(30)
    )).scalars().all()
    data = [{"date": s.created_at.strftime("%d/%m"), "status": s.status} for s in reversed(scans)]
    return ok(data)
