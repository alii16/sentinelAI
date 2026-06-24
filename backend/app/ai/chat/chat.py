"""Sentinel AI - AI Chat Agent (powered by Groq)."""
import logging
import json
from asyncio import to_thread

import groq
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import (
    Scan, Website, AIPrediction, Recommendation,
    Technology, AIChatSession, AIChatMessage, AIMemory
)
from app.core.config import settings

logger = logging.getLogger("sentinel.chat")


def _extract_groq_answer(response) -> str | None:
    if response is None:
        return None

    choices = getattr(response, "choices", None)
    if choices is None and isinstance(response, dict):
        choices = response.get("choices")

    if choices:
        choice = choices[0]
        if isinstance(choice, dict):
            message = choice.get("message")
        else:
            message = getattr(choice, "message", None)

        if message:
            if isinstance(message, dict):
                return message.get("content")
            return getattr(message, "content", None)

    if isinstance(response, dict):
        return response.get("output") or response.get("text")

    return None


def _extract_anthropic_answer(data) -> str | None:
    if not isinstance(data, dict):
        return None

    if content := data.get("completion"):
        return content

    if content := data.get("text"):
        return content

    if content := data.get("content"):
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                return first.get("text") or first.get("content")
            return first
        if isinstance(content, str):
            return content

    if result := data.get("result"):
        if isinstance(result, dict):
            return result.get("content") or result.get("output") or result.get("text")
        return result

    return None


def _extract_google_answer(data) -> str | None:
    if not isinstance(data, dict):
        return None

    candidates = data.get("candidates")
    if isinstance(candidates, list) and candidates:
        candidate = candidates[0]
        if isinstance(candidate, dict):
            return candidate.get("content") or candidate.get("output") or candidate.get("text")
        return str(candidate)

    if output := data.get("output"):
        if isinstance(output, dict):
            return output.get("content") or output.get("text")
        return str(output)

    if response_text := data.get("response"):
        return str(response_text)

    return None


async def get_scan_context(db: AsyncSession, scan_id: int) -> str:
    """Build context string from scan data for AI chat."""
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        return "Tidak ada data scan yang tersedia."

    website = (await db.execute(
        select(Website).where(Website.id == scan.website_id)
    )).scalar_one_or_none()

    techs = (await db.execute(
        select(Technology).where(Technology.scan_id == scan_id)
    )).scalars().all()

    preds = (await db.execute(
        select(AIPrediction).where(AIPrediction.scan_id == scan_id)
    )).scalars().all()

    recs = (await db.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id)
    )).scalars().all()

    # AI Memory - historical data
    history = (await db.execute(
        select(AIMemory).where(AIMemory.website_id == scan.website_id)
        .order_by(AIMemory.created_at)
    )).scalars().all()

    ctx = f"""=== DATA AUDIT KEAMANAN SENTINEL AI ===

Website: {website.url if website else 'Unknown'}
Scan ID: {scan.id}
Mode: {scan.mode}
Status: {scan.status}
Security Score: {float(scan.security_score or 0):.1f}/100
Grade: {scan.grade or 'N/A'}
Risk Level: {scan.risk_level or 'N/A'}
Total Halaman: {scan.total_pages}
Total Endpoint: {scan.total_endpoints}
Temuan Critical: {scan.critical_count}
Temuan High: {scan.high_count}
Temuan Medium: {scan.medium_count}
Temuan Low: {scan.low_count}
Total Temuan: {scan.total_findings}
Durasi: {scan.duration_seconds or 0} detik

=== TEKNOLOGI TERDETEKSI ===
"""
    for t in techs:
        ctx += f"- {t.name} ({t.category}, confidence: {t.confidence}%)\n"

    ctx += "\n=== TEMUAN KEAMANAN ===\n"
    for p in preds:
        ctx += f"- [{p.severity.upper()}] {p.prediction} (confidence: {float(p.confidence):.0f}%, OWASP: {p.owasp_category}, CWE: {p.cwe_id})\n"

    ctx += "\n=== REKOMENDASI ===\n"
    for r in recs:
        ctx += f"- [{r.priority.upper()}] {r.title}\n  Solusi: {r.solution[:200] if r.solution else '-'}\n"

    if len(history) > 1:
        ctx += "\n=== RIWAYAT KEAMANAN ===\n"
        for m in history[-5:]:
            ctx += f"- Scan {m.scan_id}: Score {float(m.security_score or 0):.1f} Grade {m.grade}\n"

    return ctx


async def chat_with_ai(
    db: AsyncSession,
    user_id: int,
    scan_id: int,
    message: str,
    session_id: int = None
) -> dict:
    """Process a chat message and return AI response."""
    # Get or create session
    if session_id:
        session = (await db.execute(
            select(AIChatSession).where(AIChatSession.id == session_id)
        )).scalar_one_or_none()
    else:
        session = None

    if not session:
        session = AIChatSession(user_id=user_id, scan_id=scan_id, title=message[:50])
        db.add(session)
        await db.flush()

    # Save user message
    user_msg = AIChatMessage(session_id=session.id, role="user", content=message)
    db.add(user_msg)
    await db.flush()

    # Get conversation history
    history = (await db.execute(
        select(AIChatMessage).where(AIChatMessage.session_id == session.id)
        .order_by(AIChatMessage.created_at)
    )).scalars().all()

    # Build context
    context = await get_scan_context(db, scan_id)

    # Build messages for Claude
    system_prompt = f"""Kamu adalah Sentinel AI Security Assistant - asisten keamanan website yang cerdas dan berpengalaman.

        Tugasmu adalah menjawab pertanyaan pengguna HANYA berdasarkan data hasil audit keamanan yang telah dilakukan.
        JANGAN mengarang informasi yang tidak ada dalam data audit.
        Selalu jawab dalam Bahasa Indonesia yang profesional dan mudah dipahami.
        Berikan jawaban yang spesifik, akurat, dan actionable.

        Jika pengguna menanyakan sesuatu yang tidak ada dalam data audit, beritahu dengan sopan bahwa kamu hanya bisa menjawab berdasarkan hasil scan yang ada.

        DATA HASIL AUDIT:
        {context}
    """

    messages = []
    for msg in history[:-1]:  # Exclude last user message (already added)
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": message})

    # Choose provider
    provider = (settings.AI_PROVIDER or "groq").lower()
    ai_answer = None

    if provider == "groq":
        if not settings.GROQ_API_KEY:
            logger.error("Groq provider selected but GROQ_API_KEY is not configured.")
            ai_answer = (
                "Maaf, konfigurasi Groq belum lengkap. Silakan atur GROQ_API_KEY di file .env "
                "atau gunakan provider lain dengan API key yang valid."
            )
        else:
            try:
                client = groq.Groq(api_key=settings.GROQ_API_KEY)
                groq_messages = [{"role": "system", "content": system_prompt}] + messages

                def call_groq():
                    return client.chat.completions.create(
                        model=settings.GROQ_MODEL,
                        messages=groq_messages,
                        temperature=0.7,
                        max_tokens=1024,
                    )

                response = await to_thread(call_groq)
                ai_answer = _extract_groq_answer(response)
                if not ai_answer:
                    logger.error("Groq response missing answer, raw response: %s", response)
                    ai_answer = "Maaf, tidak dapat memproses pertanyaan Anda saat ini."
            except Exception as e:
                logger.error("Groq API error: %s", e, exc_info=True)
                ai_answer = _fallback_response(message, context)

    elif provider == "anthropic":
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                payload = {
                    "model": settings.AI_MODEL,
                    "max_tokens": 1500,
                    "system": system_prompt,
                    "messages": messages
                }
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json=payload,
                    timeout=30.0
                )

                # Log status and body for non-200 responses to diagnose 401/403
                if response.status_code != 200:
                    try:
                        resp_body = response.text
                    except Exception:
                        resp_body = "<unreadable response body>"
                    logger.error("Anthropic API returned status %s", response.status_code)
                    logger.error("Anthropic response body: %s", resp_body)

                try:
                    data = response.json()
                except Exception as e:
                    logger.error("Failed to parse Anthropic JSON response: %s", e)
                    data = {}

                ai_answer = _extract_anthropic_answer(data)
                if not ai_answer:
                    logger.error("Anthropic missing answer, raw json: %s", data)
                    ai_answer = "Maaf, tidak dapat memproses pertanyaan Anda saat ini."
        except Exception as e:
            logger.error("Anthropic API error: %s", e, exc_info=True)
            ai_answer = _fallback_response(message, context)

    elif provider == "google":
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                # Build a simple prompt combining system and conversation
                prompt_text = system_prompt + "\n\n"
                for m in messages:
                    role = m.get("role")
                    content = m.get("content")
                    prompt_text += f"{role}: {content}\n"

                url = f"https://generativelanguage.googleapis.com/v1beta2/models/{settings.GOOGLE_MODEL}:generate?key={settings.GOOGLE_API_KEY}"
                g_payload = {
                    "prompt": {"text": prompt_text},
                    "maxOutputTokens": 1024
                }
                response = await client.post(url, json=g_payload, timeout=30.0)

                if response.status_code != 200:
                    try:
                        resp_body = response.text
                    except Exception:
                        resp_body = "<unreadable response body>"
                    logger.error("Google Generative API returned status %s", response.status_code)
                    logger.error("Google response body: %s", resp_body)

                try:
                    data = response.json()
                except Exception as e:
                    logger.error("Failed to parse Google Generative JSON response: %s", e)
                    data = {}

                ai_answer = _extract_google_answer(data)
                if not ai_answer:
                    logger.error("Google missing answer, raw json: %s", data)
                    ai_answer = "Maaf, tidak dapat memproses pertanyaan Anda saat ini."
        except Exception as e:
            logger.error("Google Generative API error: %s", e, exc_info=True)
            ai_answer = _fallback_response(message, context)

    else:
        logger.error("Unknown AI_PROVIDER: %s", provider)
        ai_answer = _fallback_response(message, context)

    # Save AI response
    ai_msg = AIChatMessage(session_id=session.id, role="assistant", content=ai_answer)
    db.add(ai_msg)
    await db.commit()

    return {
        "session_id": session.id,
        "answer": ai_answer,
        "message_id": ai_msg.id
    }


def _fallback_response(message: str, context: str) -> str:
    """Rule-based fallback when Claude API is unavailable."""
    msg_lower = message.lower()
    
    if any(w in msg_lower for w in ["score", "nilai", "skor"]):
        return "Berdasarkan hasil audit, Security Score website Anda dihitung berdasarkan jumlah dan tingkat keparahan temuan yang ditemukan. Temuan Critical dan High memberikan penalti terbesar pada skor. Silakan lihat detail temuan di halaman Report untuk informasi lengkap."
    
    if any(w in msg_lower for w in ["rekomendasi", "perbaiki", "fix", "solusi"]):
        return "Berdasarkan hasil audit, prioritas perbaikan utama adalah menangani temuan Critical dan High terlebih dahulu. Setiap temuan dilengkapi dengan langkah perbaikan spesifik yang dapat Anda ikuti. Lihat tab Rekomendasi pada halaman Report untuk detail lengkap."
    
    if any(w in msg_lower for w in ["teknologi", "framework", "cms", "server"]):
        return "Teknologi yang terdeteksi pada website Anda tersedia di bagian Technology Detection pada laporan audit. Informasi ini membantu dalam memahami attack surface dan potensi kerentanan spesifik teknologi yang digunakan."
    
    return "Saya adalah Sentinel AI Security Assistant. Saya dapat menjawab pertanyaan berdasarkan hasil audit keamanan website Anda. Silakan tanyakan tentang Security Score, temuan kerentanan, rekomendasi perbaikan, atau teknologi yang terdeteksi."
