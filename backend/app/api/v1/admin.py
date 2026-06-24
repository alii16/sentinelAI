"""Sentinel AI - Admin API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import require_admin
from app.models.models import Setting, ActivityLog, MLModel
from app.utils.response import ok
from typing import Optional

router = APIRouter()


@router.get("/settings")
async def get_settings(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    settings_list = (await db.execute(select(Setting))).scalars().all()
    return ok({s.key_name: s.value for s in settings_list})


@router.put("/settings")
async def update_settings(body: dict, admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    for key, val in body.items():
        s = (await db.execute(select(Setting).where(Setting.key_name == key))).scalar_one_or_none()
        if s:
            s.value = str(val)
    await db.commit()
    return ok({"message": "Pengaturan diperbarui"})


@router.get("/system")
async def system_info(admin=Depends(require_admin)):
    import platform
    info = {
        "python": platform.python_version(),
        "os": platform.system(),
        "cpu": 0,
        "memory": 0,
        "disk": 0,
    }
    try:
        import psutil
        info["cpu"] = psutil.cpu_percent(interval=0.1)
        info["memory"] = psutil.virtual_memory().percent
        info["disk"] = psutil.disk_usage("/").percent
    except ImportError:
        pass
    return ok(info)


@router.get("/users")
async def list_users(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    from app.models.models import User
    from sqlalchemy.orm import selectinload
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


@router.get("/logs")
async def activity_logs(admin=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    logs = (await db.execute(
        select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(100)
    )).scalars().all()
    return ok([{
        "id": l.id, "user_id": l.user_id, "action": l.action,
        "entity": l.entity, "entity_id": l.entity_id,
        "created_at": l.created_at.isoformat()
    } for l in logs])
