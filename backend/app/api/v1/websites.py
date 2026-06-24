"""Sentinel AI - Websites API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, AnyHttpUrl
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Website, Scan
from app.utils.response import ok, fail
from app.utils.activity import log_activity
from datetime import datetime

router = APIRouter()


class WebsiteCreate(BaseModel):
    name: str
    url: str
    category: Optional[str] = None
    description: Optional[str] = None


class WebsiteUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None


def website_to_dict(w: Website, last_score=None):
    return {
        "id": w.id, "name": w.name, "url": w.url,
        "domain": w.domain, "category": w.category,
        "description": w.description, "status": w.status,
        "last_scan_at": w.last_scan_at.isoformat() if w.last_scan_at else None,
        "last_score": last_score,
        "created_at": w.created_at.isoformat()
    }


@router.get("")
async def list_websites(
    page: int = 1, limit: int = 10, search: str = "",
    current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    q = select(Website).where(Website.user_id == current_user.id, Website.deleted_at.is_(None))
    if search:
        q = q.where(Website.name.ilike(f"%{search}%"))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    websites = (await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return ok({"items": [website_to_dict(w) for w in websites], "total": total, "page": page, "limit": limit})


@router.post("")
async def create_website(body: WebsiteCreate, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from urllib.parse import urlparse
    domain = urlparse(body.url).netloc
    w = Website(user_id=current_user.id, name=body.name, url=body.url,
                domain=domain, category=body.category, description=body.description)
    db.add(w)
    await db.commit()
    await db.refresh(w)
    await log_activity(db, current_user.id, "create_website", "website", w.id)
    return ok(website_to_dict(w), 201)


@router.get("/{website_id}")
async def get_website(website_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    w = (await db.execute(
        select(Website).where(Website.id == website_id, Website.user_id == current_user.id, Website.deleted_at.is_(None))
    )).scalar_one_or_none()
    if not w:
        return fail("Website tidak ditemukan", 404)
    # Get last scan score
    last_scan = (await db.execute(
        select(Scan).where(Scan.website_id == website_id, Scan.status == "completed")
        .order_by(Scan.completed_at.desc()).limit(1)
    )).scalar_one_or_none()
    return ok(website_to_dict(w, last_scan.security_score if last_scan else None))


@router.put("/{website_id}")
async def update_website(website_id: int, body: WebsiteUpdate, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    w = (await db.execute(
        select(Website).where(Website.id == website_id, Website.user_id == current_user.id, Website.deleted_at.is_(None))
    )).scalar_one_or_none()
    if not w:
        return fail("Website tidak ditemukan", 404)
    if body.name: w.name = body.name
    if body.category is not None: w.category = body.category
    if body.description is not None: w.description = body.description
    await db.commit()
    return ok(website_to_dict(w))


@router.delete("/{website_id}")
async def delete_website(website_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    w = (await db.execute(
        select(Website).where(Website.id == website_id, Website.user_id == current_user.id, Website.deleted_at.is_(None))
    )).scalar_one_or_none()
    if not w:
        return fail("Website tidak ditemukan", 404)
    from datetime import timezone
    w.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    await log_activity(db, current_user.id, "delete_website", "website", website_id)
    return ok(None, 204, "Website dihapus")
