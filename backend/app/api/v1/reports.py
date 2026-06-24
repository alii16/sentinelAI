"""Sentinel AI - Reports API."""
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Report, Scan
from app.utils.response import ok, fail
import os

router = APIRouter()


def report_dict(r: Report):
    return {
        "id": r.id, "scan_id": r.scan_id, "title": r.title,
        "security_score": float(r.security_score) if r.security_score else None,
        "grade": r.grade, "risk_level": r.risk_level,
        "executive_summary": r.executive_summary,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "has_pdf": bool(r.pdf_path and os.path.exists(r.pdf_path)),
        "has_json": bool(r.json_path and os.path.exists(r.json_path)),
        "has_csv": bool(r.csv_path and os.path.exists(r.csv_path)),
        "created_at": r.created_at.isoformat()
    }


@router.get("")
async def list_reports(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    reports = (await db.execute(
        select(Report).where(Report.user_id == current_user.id, Report.deleted_at.is_(None))
        .order_by(Report.created_at.desc()).limit(50)
    )).scalars().all()
    return ok([report_dict(r) for r in reports])


@router.get("/{report_id}")
async def get_report(report_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )).scalar_one_or_none()
    if not r:
        return fail("Laporan tidak ditemukan", 404)
    return ok(report_dict(r))


@router.get("/{report_id}/pdf")
async def download_pdf(report_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )).scalar_one_or_none()
    if not r or not r.pdf_path or not os.path.exists(r.pdf_path):
        return fail("File PDF tidak tersedia", 404)
    return FileResponse(r.pdf_path, media_type="application/pdf",
                        filename=f"sentinel_report_{report_id}.pdf")


@router.get("/{report_id}/json")
async def download_json(report_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )).scalar_one_or_none()
    if not r or not r.json_path or not os.path.exists(r.json_path):
        return fail("File JSON tidak tersedia", 404)
    return FileResponse(r.json_path, media_type="application/json",
                        filename=f"sentinel_report_{report_id}.json")


@router.get("/{report_id}/csv")
async def download_csv(report_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )).scalar_one_or_none()
    if not r or not r.csv_path or not os.path.exists(r.csv_path):
        return fail("File CSV tidak tersedia", 404)
    return FileResponse(r.csv_path, media_type="text/csv",
                        filename=f"sentinel_report_{report_id}.csv")
