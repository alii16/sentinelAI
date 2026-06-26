"""Sentinel AI - Reports API."""
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user, decode_token
from app.models.models import Report, Scan, Technology
from app.repositories.user_repository import UserRepository
from app.utils.response import ok, fail
import os

router = APIRouter()


def report_dict(r: Report):
    return {
        "id":                r.id,
        "scan_id":           r.scan_id,
        "title":             r.title,
        "security_score":    float(r.security_score) if r.security_score else None,
        "grade":             r.grade,
        "risk_level":        r.risk_level,
        "executive_summary": r.executive_summary,
        "generated_at":      r.generated_at.isoformat() if r.generated_at else None,
        "has_pdf":           bool(r.pdf_path  and os.path.exists(r.pdf_path)),
        "has_json":          bool(r.json_path and os.path.exists(r.json_path)),
        "has_csv":           bool(r.csv_path  and os.path.exists(r.csv_path)),
        "created_at":        r.created_at.isoformat(),
    }


async def resolve_user_id(request: Request, db: AsyncSession) -> int | None:
    """
    Resolve user_id dari:
    1. Authorization: Bearer <token>  (fetch / XHR)
    2. ?token=<token>                 (direct browser URL)
    """
    # 1. Coba dari header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        # 2. Coba dari query param
        token = request.query_params.get("token", "")

    if not token:
        return None

    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        repo = UserRepository(db)
        user = await repo.get_by_id(int(user_id))
        return user.id if (user and user.is_active) else None
    except Exception:
        return None


# ── Standard endpoints (pakai Bearer auth) ───────────────────────

@router.get("")
async def list_reports(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    reports = (await db.execute(
        select(Report)
        .where(Report.user_id == current_user.id, Report.deleted_at.is_(None))
        .order_by(Report.created_at.desc())
        .limit(50)
    )).scalars().all()
    return ok([report_dict(r) for r in reports])


@router.get("/by-scan/{scan_id}")
async def get_report_by_scan(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cari report berdasarkan scan_id."""
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)

    r = (await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id, Report.user_id == current_user.id)
        .order_by(Report.created_at.desc())
    )).scalar_one_or_none()

    return ok(report_dict(r) if r else None)


@router.get("/technologies/{scan_id}")
async def get_technologies(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Teknologi yang terdeteksi pada scan tertentu."""
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )).scalar_one_or_none()
    if not scan:
        return fail("Scan tidak ditemukan", 404)

    techs = (await db.execute(
        select(Technology)
        .where(Technology.scan_id == scan_id)
        .order_by(Technology.confidence.desc())
    )).scalars().all()

    return ok([{
        "id":         t.id,
        "name":       t.name,
        "version":    t.version,
        "category":   t.category,
        "confidence": t.confidence,
        "source":     t.source,
    } for t in techs])


@router.get("/{report_id}")
async def get_report(
    report_id: int,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )).scalar_one_or_none()
    if not r:
        return fail("Laporan tidak ditemukan", 404)
    return ok(report_dict(r))


# ── Download endpoints ─────────────────────────────────────────────
# Mendukung dua cara auth:
# 1. Authorization: Bearer <token>  → dari fetch/XHR
# 2. ?token=<jwt>                   → dari direct browser link (tab baru)
# Nama file menggunakan nama asli dari disk (scan_39_1782388993.pdf)

@router.get("/{report_id}/pdf")
async def download_pdf(
    report_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    user_id = await resolve_user_id(request, db)
    if not user_id:
        return fail("Unauthorized", 401)

    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == user_id)
    )).scalar_one_or_none()
    if not r or not r.pdf_path or not os.path.exists(r.pdf_path):
        return fail("File PDF tidak tersedia", 404)

    filename = os.path.basename(r.pdf_path)  # e.g. scan_39_1782388993.pdf
    return FileResponse(r.pdf_path, media_type="application/pdf", filename=filename)


@router.get("/{report_id}/json")
async def download_json(
    report_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    user_id = await resolve_user_id(request, db)
    if not user_id:
        return fail("Unauthorized", 401)

    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == user_id)
    )).scalar_one_or_none()
    if not r or not r.json_path or not os.path.exists(r.json_path):
        return fail("File JSON tidak tersedia", 404)

    filename = os.path.basename(r.json_path)
    return FileResponse(r.json_path, media_type="application/json", filename=filename)


@router.get("/{report_id}/csv")
async def download_csv(
    report_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    user_id = await resolve_user_id(request, db)
    if not user_id:
        return fail("Unauthorized", 401)

    r = (await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == user_id)
    )).scalar_one_or_none()
    if not r or not r.csv_path or not os.path.exists(r.csv_path):
        return fail("File CSV tidak tersedia", 404)

    filename = os.path.basename(r.csv_path)
    return FileResponse(r.csv_path, media_type="text/csv", filename=filename)
