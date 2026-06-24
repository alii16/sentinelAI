"""Sentinel AI - Users API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user, require_admin
from app.models.models import User
from app.utils.response import ok, fail

router = APIRouter()


class UserUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("")
async def list_users(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(
        select(User).options(selectinload(User.role)).where(User.deleted_at.is_(None))
    )).scalars().all()
    return ok([{
        "id": u.id, "name": u.name, "email": u.email,
        "role": u.role.name if u.role else "user",
        "is_active": u.is_active,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "created_at": u.created_at.isoformat()
    } for u in users])


@router.get("/{user_id}")
async def get_user(user_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    u = (await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )).scalar_one_or_none()
    if not u:
        return fail("Pengguna tidak ditemukan", 404)
    return ok({"id": u.id, "name": u.name, "email": u.email,
                "role": u.role.name if u.role else "user", "is_active": u.is_active})


@router.put("/{user_id}")
async def update_user(user_id: int, body: UserUpdate,
                      admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        return fail("Pengguna tidak ditemukan", 404)
    if body.name is not None:
        u.name = body.name
    if body.is_active is not None:
        u.is_active = 1 if body.is_active else 0
    await db.commit()
    return ok({"message": "Pengguna diperbarui"})


@router.delete("/{user_id}")
async def delete_user(user_id: int, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timezone
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        return fail("Pengguna tidak ditemukan", 404)
    u.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    return ok(None, 204, "Pengguna dihapus")
