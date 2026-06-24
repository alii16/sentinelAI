"""Sentinel AI - Notifications API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Notification
from app.utils.response import ok, fail

router = APIRouter()

@router.get("")
async def list_notifications(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    notifs = (await db.execute(
        select(Notification).where(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc()).limit(50)
    )).scalars().all()
    return ok([{"id": n.id, "type": n.type, "title": n.title, "body": n.body,
                "is_read": n.is_read, "created_at": n.created_at.isoformat()} for n in notifs])

@router.put("/read/{notif_id}")
async def mark_read(notif_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    n = (await db.execute(select(Notification).where(Notification.id == notif_id, Notification.user_id == current_user.id))).scalar_one_or_none()
    if n:
        n.is_read = 1
        n.read_at = datetime.now(timezone.utc)
        await db.commit()
    return ok({"message": "Ditandai sudah dibaca"})

@router.put("/read-all")
async def mark_all_read(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    notifs = (await db.execute(select(Notification).where(Notification.user_id == current_user.id, Notification.is_read == 0))).scalars().all()
    for n in notifs:
        n.is_read = 1
        n.read_at = datetime.now(timezone.utc)
    await db.commit()
    return ok({"message": "Semua notifikasi ditandai sudah dibaca"})

@router.delete("/{notif_id}")
async def delete_notification(notif_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    n = (await db.execute(select(Notification).where(Notification.id == notif_id, Notification.user_id == current_user.id))).scalar_one_or_none()
    if n:
        await db.delete(n)
        await db.commit()
    return ok(None, 204)
