"""Sentinel AI - AI API."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import AIPrediction, Recommendation, AIChatSession, AIChatMessage, AIMemory, MLModel
from app.utils.response import ok, fail

router = APIRouter()


class ChatRequest(BaseModel):
    scan_id: int
    message: str
    session_id: Optional[int] = None


@router.get("/summary/{scan_id}")
async def ai_summary(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    preds = (await db.execute(
        select(AIPrediction).where(AIPrediction.scan_id == scan_id)
    )).scalars().all()
    return ok([{
        "id": p.id, "prediction": p.prediction, "severity": p.severity,
        "confidence": float(p.confidence), "owasp_category": p.owasp_category,
        "cwe_id": p.cwe_id, "is_verified": p.is_verified
    } for p in preds])


@router.get("/recommendation/{scan_id}")
async def ai_recommendations(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    recs = (await db.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id)
        .order_by(Recommendation.priority)
    )).scalars().all()
    return ok([{
        "id": r.id, "title": r.title, "summary": r.summary,
        "cause": r.cause, "impact": r.impact, "solution": r.solution,
        "priority": r.priority, "owasp_ref": r.owasp_ref,
        "cwe_ref": r.cwe_ref,
        "cvss_score": float(r.cvss_score) if r.cvss_score else None,
        "affected_url": r.affected_url, "checklist": r.checklist
    } for r in recs])


@router.get("/predictions/{scan_id}")
async def ai_predictions(scan_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    preds = (await db.execute(
        select(AIPrediction).where(AIPrediction.scan_id == scan_id)
    )).scalars().all()
    return ok([{
        "id": p.id, "prediction": p.prediction, "severity": p.severity,
        "confidence": float(p.confidence), "owasp_category": p.owasp_category,
        "cwe_id": p.cwe_id, "evidence": p.evidence
    } for p in preds])


@router.post("/chat")
async def ai_chat(body: ChatRequest, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from app.ai.chat.chat import chat_with_ai
    result = await chat_with_ai(db, current_user.id, body.scan_id, body.message, body.session_id)
    return ok(result)


@router.get("/memory/{website_id}")
async def ai_memory(website_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    memories = (await db.execute(
        select(AIMemory).where(AIMemory.website_id == website_id)
        .order_by(AIMemory.created_at)
    )).scalars().all()
    return ok([{
        "scan_id": m.scan_id, "security_score": float(m.security_score or 0),
        "grade": m.grade, "risk_level": m.risk_level,
        "total_findings": m.total_findings, "created_at": m.created_at.isoformat()
    } for m in memories])


@router.get("/models")
async def list_models(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    models = (await db.execute(select(MLModel))).scalars().all()
    return ok([{
        "id": m.id, "name": m.name, "algorithm": m.algorithm,
        "version": m.version,
        "accuracy": float(m.accuracy) if m.accuracy else None,
        "precision_score": float(m.precision_score) if m.precision_score else None,
        "recall_score": float(m.recall_score) if m.recall_score else None,
        "f1_score": float(m.f1_score) if m.f1_score else None,
        "roc_auc": float(m.roc_auc) if m.roc_auc else None,
        "is_active": m.is_active, "status": m.status,
        "trained_at": m.trained_at.isoformat() if m.trained_at else None
    } for m in models])


@router.put("/models/{model_id}/activate")
async def activate_model(model_id: int, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Deactivate all
    all_models = (await db.execute(select(MLModel))).scalars().all()
    for m in all_models:
        m.is_active = 0
    # Activate target
    target = (await db.execute(select(MLModel).where(MLModel.id == model_id))).scalar_one_or_none()
    if not target:
        return fail("Model tidak ditemukan", 404)
    target.is_active = 1
    await db.commit()
    return ok({"message": f"Model {target.name} diaktifkan"})
