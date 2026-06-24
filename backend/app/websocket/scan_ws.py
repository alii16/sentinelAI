"""Sentinel AI - WebSocket for realtime scan progress."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
import asyncio
import json
import logging

router = APIRouter()
logger = logging.getLogger("sentinel.ws")

# Active connections: scan_id -> list of WebSocket
connections: dict[int, list[WebSocket]] = {}


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    if scan_id not in connections:
        connections[scan_id] = []
    connections[scan_id].append(websocket)
    logger.info(f"WS client connected for scan {scan_id}")
    
    try:
        from app.core.database import AsyncSessionLocal
        from app.models.models import Scan, ScanProgress
        
        while True:
            async with AsyncSessionLocal() as db:
                scan = (await db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )).scalar_one_or_none()
                
                prog = (await db.execute(
                    select(ScanProgress).where(ScanProgress.scan_id == scan_id)
                )).scalar_one_or_none()

                if scan:
                    msg = {
                        "event": "progress",
                        "scan_id": scan_id,
                        "status": scan.status,
                        "percentage": prog.percentage if prog else 0,
                        "current_agent": prog.current_agent if prog else "",
                        "pages_found": prog.pages_found if prog else 0,
                        "endpoints_found": prog.endpoints_found if prog else 0,
                        "stages": {
                            "discovery": prog.discovery_pct if prog else 0,
                            "technology": prog.technology_pct if prog else 0,
                            "endpoint": prog.endpoint_pct if prog else 0,
                            "scanner": prog.scanner_pct if prog else 0,
                            "verification": prog.verification_pct if prog else 0,
                            "report": prog.report_pct if prog else 0,
                        }
                    }
                    await websocket.send_text(json.dumps(msg))
                    
                    if scan.status in ("completed", "failed", "cancelled"):
                        # Send final event
                        final = {"event": scan.status, "scan_id": scan_id,
                                 "security_score": float(scan.security_score or 0),
                                 "grade": scan.grade}
                        await websocket.send_text(json.dumps(final))
                        break
            
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        logger.info(f"WS client disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WS error for scan {scan_id}: {e}")
    finally:
        if scan_id in connections and websocket in connections[scan_id]:
            connections[scan_id].remove(websocket)


async def broadcast_to_scan(scan_id: int, data: dict):
    """Broadcast a message to all WebSocket clients watching a scan."""
    if scan_id in connections:
        dead = []
        for ws in connections[scan_id]:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            connections[scan_id].remove(ws)
