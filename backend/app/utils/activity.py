"""Sentinel AI - Activity logging utility."""
from app.models.models import ActivityLog
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Any


async def log_activity(
    db: AsyncSession,
    user_id: Optional[int],
    action: str,
    entity: str = None,
    entity_id: int = None,
    metadata: Any = None
):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        entity=entity,
        entity_id=entity_id,
        meta_data=metadata
    )
    db.add(log)
    try:
        await db.flush()
    except Exception:
        pass
