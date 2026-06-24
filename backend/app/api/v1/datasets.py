"""Sentinel AI - Datasets API."""
from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Dataset
from app.utils.response import ok, fail
import os, shutil
from app.core.config import settings

router = APIRouter()

@router.get("")
async def list_datasets(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    ds = (await db.execute(select(Dataset).where(Dataset.deleted_at.is_(None)).order_by(Dataset.created_at.desc()))).scalars().all()
    return ok([{"id": d.id, "name": d.name, "description": d.description,
                "version": d.version, "status": d.status, "sample_count": d.sample_count,
                "created_at": d.created_at.isoformat()} for d in ds])

@router.post("")
async def upload_dataset(name: str, file: UploadFile = File(...),
                          current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    os.makedirs(settings.DATASET_PATH, exist_ok=True)
    path = os.path.join(settings.DATASET_PATH, file.filename)
    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    size = os.path.getsize(path)
    d = Dataset(user_id=current_user.id, name=name, file_path=path, file_size=size, status="ready")
    db.add(d)
    await db.commit()
    await db.refresh(d)
    return ok({"id": d.id, "name": d.name, "status": d.status}, 201)

@router.delete("/{dataset_id}")
async def delete_dataset(dataset_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(Dataset).where(Dataset.id == dataset_id))).scalar_one_or_none()
    if not d:
        return fail("Dataset tidak ditemukan", 404)
    from datetime import datetime, timezone
    d.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    return ok(None, 204)
