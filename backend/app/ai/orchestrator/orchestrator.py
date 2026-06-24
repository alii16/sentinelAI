"""
Sentinel AI - AI Orchestrator
Central controller for all AI Agents during a scan pipeline.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("sentinel.orchestrator")


async def run_scan_pipeline(scan_id: int, target_url: str):
    """
    Main scan pipeline. Called as a background task.
    Runs all agents in order and updates progress.
    """
    from app.core.database import AsyncSessionLocal
    from app.models.models import Scan, ScanProgress, ScanLog, Notification, Website, AIMemory
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        try:
            # ── Load scan ──────────────────────────────────────────────
            scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            def add_log(agent: str, message: str, level: str = "info"):
                # Schedule log write in a separate session to avoid concurrent DB use
                async def _write_log():
                    try:
                        async with AsyncSessionLocal() as _db:
                            _db.add(ScanLog(scan_id=scan_id, agent=agent, message=message, level=level))
                            await _db.commit()
                    except Exception as e:
                        logger.debug(f"Failed to write ScanLog asynchronously: {e}")

                try:
                    asyncio.create_task(_write_log())
                except Exception:
                    # Fallback: synchronous add if task creation fails
                    try:
                        db.add(ScanLog(scan_id=scan_id, agent=agent, message=message, level=level))
                    except Exception:
                        logger.debug("Failed to add ScanLog to main session as fallback")

            async def update_progress(agent: str, pct: int, **stage_pcts):
                # Use a dedicated session for progress updates to avoid concurrent operations
                try:
                    async with AsyncSessionLocal() as _db:
                        prog = (await _db.execute(select(ScanProgress).where(ScanProgress.scan_id == scan_id))).scalar_one_or_none()
                        if prog:
                            prog.current_agent = agent
                            prog.percentage = pct
                            for k, v in stage_pcts.items():
                                setattr(prog, k, v)
                            _db.add(prog)
                        await _db.commit()
                except Exception as e:
                    logger.debug(f"update_progress failed (async session): {e}")

            add_log("Orchestrator", f"Memulai audit keamanan untuk {target_url}")
            await db.commit()

            # ── STAGE 1: Discovery ─────────────────────────────────────
            await update_progress("Discovery Agent", 5)
            add_log("Discovery", "Memulai crawling website...")
            await db.commit()

            from app.ai.discovery.crawler import DiscoveryAgent
            discovery = DiscoveryAgent(db, scan_id, target_url, scan.max_depth, scan.max_pages)
            discovery_result = await discovery.run()

            scan.total_pages = discovery_result.get("pages_found", 0)
            await update_progress("Discovery Agent", 20, discovery_pct=100, pages_found=scan.total_pages)
            add_log("Discovery", f"Discovery selesai: {scan.total_pages} halaman ditemukan")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 2: Technology Detection ─────────────────────────
            await update_progress("Technology Agent", 25)
            add_log("Technology", "Mendeteksi teknologi website...")
            await db.commit()

            from app.ai.technology.fingerprint import TechnologyAgent
            tech_agent = TechnologyAgent(db, scan_id, discovery_result)
            await tech_agent.run()

            await update_progress("Technology Agent", 35, technology_pct=100)
            add_log("Technology", "Deteksi teknologi selesai")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 3: Endpoint Intelligence ────────────────────────
            await update_progress("Endpoint Agent", 38)
            add_log("Endpoint", "Menganalisis dan memprioritaskan endpoint...")
            await db.commit()

            from app.ai.endpoint.extractor import EndpointAgent
            endpoint_agent = EndpointAgent(db, scan_id, discovery_result)
            endpoint_result = await endpoint_agent.run()

            scan.total_endpoints = endpoint_result.get("endpoints_found", 0)
            await update_progress("Endpoint Agent", 50, endpoint_pct=100, endpoints_found=scan.total_endpoints)
            add_log("Endpoint", f"Ditemukan {scan.total_endpoints} endpoint dengan prioritas")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 4: Attack Planner ────────────────────────────────
            await update_progress("Attack Planner", 52)
            add_log("Attack Planner", "Menyusun strategi audit...")
            await db.commit()

            from app.ai.attack_planner.planner import AttackPlannerAgent
            planner = AttackPlannerAgent(db, scan_id, endpoint_result)
            strategy = await planner.run()

            await update_progress("Attack Planner", 60)
            add_log("Attack Planner", f"Strategi audit tersusun: {len(strategy.get('tasks', []))} tugas")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 5: Active Scanner ────────────────────────────────
            await update_progress("Scanner Agent", 62)
            add_log("Scanner", "Menjalankan active security testing...")
            await db.commit()

            from app.ai.scanner.worker import ScannerAgent
            scanner = ScannerAgent(db, scan_id, strategy, scan.timeout_ms)
            scan_results = await scanner.run(
                progress_callback=lambda p: asyncio.create_task(
                    update_progress("Scanner Agent", 62 + int(p * 0.15), scanner_pct=p)
                )
            )

            await update_progress("Scanner Agent", 78, scanner_pct=100)
            add_log("Scanner", f"Scanning selesai: {len(scan_results)} hasil dikumpulkan")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 6: Verification (ML) ─────────────────────────────
            await update_progress("Verification Agent", 80)
            add_log("Verification", "Menjalankan analisis Machine Learning...")
            await db.commit()

            from app.ai.verification.verifier import VerificationAgent
            verifier = VerificationAgent(db, scan_id, scan_results)
            logger.info(f"Invoking VerificationAgent.run for scan {scan_id} at {datetime.now(timezone.utc).isoformat()}")
            try:
                # Guard with a timeout to detect hangs during ML inference or IO
                predictions = await asyncio.wait_for(verifier.run(), timeout=300)
                logger.info(f"VerificationAgent.run completed for scan {scan_id} with {len(predictions)} predictions")
            except asyncio.TimeoutError:
                logger.error(f"VerificationAgent.run timed out for scan {scan_id}")
                predictions = []
            except Exception as e:
                logger.error(f"VerificationAgent.run failed for scan {scan_id}: {e}", exc_info=True)
                predictions = []

            await update_progress("Verification Agent", 88, verification_pct=100)
            add_log("Verification", f"Prediksi ML selesai: {len(predictions)} temuan")
            await db.commit()

            if scan.status == "cancelled":
                return

            # ── STAGE 7: Risk Assessment ───────────────────────────────
            await update_progress("Risk Agent", 90)
            add_log("Risk", "Menghitung Security Score...")
            await db.commit()

            from app.ai.risk.score import RiskAgent
            risk_agent = RiskAgent(db, scan_id, predictions)
            risk_result = await risk_agent.run()

            scan.security_score = risk_result["score"]
            scan.grade = risk_result["grade"]
            scan.risk_level = risk_result["risk_level"]
            scan.critical_count = risk_result["critical"]
            scan.high_count = risk_result["high"]
            scan.medium_count = risk_result["medium"]
            scan.low_count = risk_result["low"]
            scan.total_findings = risk_result["total"]
            await db.commit()

            # ── STAGE 8: Recommendation ────────────────────────────────
            await update_progress("Recommendation Agent", 92)
            add_log("Recommendation", "Membuat rekomendasi keamanan...")
            await db.commit()

            from app.ai.recommendation.recommendation import RecommendationAgent
            rec_agent = RecommendationAgent(db, scan_id, predictions)
            await rec_agent.run()

            await db.commit()

            # ── STAGE 9: Report ────────────────────────────────────────
            await update_progress("Report Agent", 95, report_pct=50)
            add_log("Report", "Membuat laporan keamanan...")
            await db.commit()

            from app.ai.report.pdf import ReportAgent
            report_agent = ReportAgent(db, scan_id)
            await report_agent.run(
                discovery_result=discovery_result,
                endpoint_result=endpoint_result,
                scan_results=scan_results,
                predictions=predictions
            )

            await update_progress("Report Agent", 100, report_pct=100)
            add_log("Report", "Laporan berhasil dibuat")

            # ── Complete ───────────────────────────────────────────────
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())

            # Update website last scan
            website = (await db.execute(select(Website).where(Website.id == scan.website_id))).scalar_one_or_none()
            if website:
                website.last_scan_at = scan.completed_at

            # Save AI Memory
            memory = AIMemory(
                website_id=scan.website_id, scan_id=scan_id,
                security_score=scan.security_score, grade=scan.grade,
                risk_level=scan.risk_level, total_findings=scan.total_findings,
                critical_count=scan.critical_count, high_count=scan.high_count,
                medium_count=scan.medium_count, low_count=scan.low_count
            )
            db.add(memory)

            # Notify user
            score_display = f"{scan.security_score:.1f}" if scan.security_score else "N/A"
            notif = Notification(
                user_id=scan.user_id, type="scan_completed",
                title="Scan selesai",
                body=f"Audit {website.name if website else ''} selesai. Security Score: {score_display} ({scan.grade})"
            )
            db.add(notif)

            await db.commit()
            add_log("Orchestrator", f"Audit selesai. Security Score: {score_display} Grade {scan.grade}")
            await db.commit()
            logger.info(f"Scan {scan_id} completed successfully. Score: {score_display}")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            try:
                from sqlalchemy import select as sel
                scan = (await db.execute(sel(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(e)
                    scan.completed_at = datetime.now(timezone.utc)
                    db.add(ScanLog(scan_id=scan_id, level="error", agent="Orchestrator",
                                   message=f"Scan gagal: {str(e)}"))
                    await db.commit()
            except Exception as ex:
                logger.error(f"Failed to mark scan as failed: {ex}")
