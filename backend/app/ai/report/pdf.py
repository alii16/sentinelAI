"""Sentinel AI - Report Agent (PDF/JSON/CSV)."""
import logging
import os
import json
import csv
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.models import (
    Scan, Website, Technology, AIPrediction,
    Recommendation, Report, ScanLog, Page
)
from app.core.config import settings

logger = logging.getLogger("sentinel.report")


class ReportAgent:
    def __init__(self, db: AsyncSession, scan_id: int):
        self.db = db
        self.scan_id = scan_id

    async def run(
        self,
        discovery_result: dict | None = None,
        endpoint_result: dict | None = None,
        scan_results: list | None = None,
        predictions: list | None = None,
    ):
        scan = (await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )).scalar_one_or_none()
        if not scan:
            return

        website = (await self.db.execute(
            select(Website).where(Website.id == scan.website_id)
        )).scalar_one_or_none()

        techs = (await self.db.execute(
            select(Technology).where(Technology.scan_id == self.scan_id)
        )).scalars().all()

        preds = (await self.db.execute(
            select(AIPrediction).where(AIPrediction.scan_id == self.scan_id)
        )).scalars().all()

        recs = (await self.db.execute(
            select(Recommendation).where(Recommendation.scan_id == self.scan_id)
        )).scalars().all()

        logs = (await self.db.execute(
            select(ScanLog).where(ScanLog.scan_id == self.scan_id).order_by(ScanLog.created_at)
        )).scalars().all()

        discovery_result = discovery_result or {}
        endpoint_result = endpoint_result or {}
        scan_results = scan_results or []
        predictions = predictions or []

        os.makedirs(settings.REPORT_PATH, exist_ok=True)
        ts = int(datetime.now(timezone.utc).timestamp())
        base = f"scan_{self.scan_id}_{ts}"

        exec_summary = self._build_summary(scan, website, preds, recs)
        discovery_summary = self._build_discovery_summary(discovery_result)
        endpoint_summary = self._build_endpoint_summary(endpoint_result)
        timeline = self._build_timeline(logs)

        # JSON report
        json_path = os.path.join(settings.REPORT_PATH, f"{base}.json")
        json_data = {
            "scan_id": scan.id,
            "website": {
                "name": website.name if website else None,
                "url": website.url if website else None,
                "domain": website.domain if website else None,
                "category": website.category if website else None,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "security_score": float(scan.security_score or 0),
            "grade": scan.grade,
            "risk_level": scan.risk_level,
            "executive_summary": exec_summary,
            "discovery": discovery_summary,
            "endpoint_summary": endpoint_summary,
            "technologies": [{"name": t.name, "category": t.category, "confidence": t.confidence} for t in techs],
            "findings": [
                {
                    "prediction": p.prediction,
                    "severity": p.severity,
                    "confidence": float(p.confidence),
                    "owasp": p.owasp_category,
                    "cwe": p.cwe_id,
                    "evidence": p.evidence,
                    "probability": p.probability,
                }
                for p in preds
            ],
            "recommendations": [
                {
                    "title": r.title,
                    "summary": r.summary,
                    "cause": r.cause,
                    "impact": r.impact,
                    "solution": r.solution,
                    "priority": r.priority,
                    "owasp_ref": r.owasp_ref,
                    "cwe_ref": r.cwe_ref,
                    "cvss": float(r.cvss_score or 0),
                    "affected_url": r.affected_url,
                    "checklist": r.checklist,
                }
                for r in recs
            ],
            "scan_results": scan_results,
            "timeline": timeline,
            "summary": {
                "total_pages": scan.total_pages,
                "total_endpoints": scan.total_endpoints,
                "total_findings": scan.total_findings,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
            },
        }

        # Add pages and assets from discovery
        if discovery_result:
            json_data["discovery"]["pages"] = discovery_result.get("pages", [])
            json_data["discovery"]["forms"] = discovery_result.get("forms", [])
            json_data["discovery"]["assets"] = discovery_result.get("assets", [])
            json_data["discovery"]["javascript_files"] = discovery_result.get("javascript_files", [])
            json_data["discovery"]["css_files"] = discovery_result.get("css_files", [])
            json_data["discovery"]["internal_links"] = discovery_result.get("internal_links", [])
            json_data["discovery"]["external_links"] = discovery_result.get("external_links", [])
            json_data["discovery"]["api_endpoints"] = discovery_result.get("api_endpoints", [])

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        # CSV report
        csv_path = os.path.join(settings.REPORT_PATH, f"{base}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["No", "Temuan", "Severity", "Confidence", "OWASP", "CWE"])
            for i, p in enumerate(preds, 1):
                writer.writerow([i, p.prediction, p.severity, f"{p.confidence:.0f}%",
                                  p.owasp_category, p.cwe_id])

        # PDF report
        pdf_path = await self._generate_pdf(
            scan, website, techs, preds, recs, exec_summary,
            discovery_summary, endpoint_summary, timeline, base
        )

        # Save report record
        report = Report(
            scan_id=self.scan_id,
            user_id=scan.user_id,
            title=f"Laporan Audit Keamanan - {website.name if website else scan_id}",
            pdf_path=pdf_path,
            json_path=json_path,
            csv_path=csv_path,
            executive_summary=exec_summary,
            security_score=scan.security_score,
            grade=scan.grade,
            risk_level=scan.risk_level,
            generated_at=datetime.now(timezone.utc)
        )
        self.db.add(report)
        await self.db.flush()

    def _build_summary(self, scan, website, preds, recs) -> str:
        site = website.url if website else "Unknown"
        score = float(scan.security_score or 0)
        grade = scan.grade or "N/A"
        return (
            f"Audit keamanan untuk {site} telah selesai dilakukan oleh Sentinel AI. "
            f"Website mendapatkan Security Score {score:.1f}/100 dengan Grade {grade}. "
            f"Ditemukan {scan.critical_count} temuan Critical, {scan.high_count} High, "
            f"{scan.medium_count} Medium, dan {scan.low_count} Low. "
            f"Total {len(recs)} rekomendasi perbaikan telah disiapkan."
        )

    def _build_discovery_summary(self, discovery_result: dict) -> dict:
        return {
            "pages_found": discovery_result.get("pages_found", 0),
            "forms_found": discovery_result.get("forms_found", 0),
            "endpoints_found": len(discovery_result.get("endpoints", [])),
            "assets_found": len(discovery_result.get("assets", [])),
            "internal_links": discovery_result.get("internal_links", []),
            "external_links": discovery_result.get("external_links", []),
            "api_endpoints": discovery_result.get("api_endpoints", []),
            "javascript_files": discovery_result.get("javascript_files", []),
            "css_files": discovery_result.get("css_files", []),
        }

    def _build_endpoint_summary(self, endpoint_result: dict) -> dict:
        return {
            "endpoints_found": endpoint_result.get("endpoints_found", 0),
            "top_endpoints": [
                {"url": e.get("url"), "method": e.get("method"), "priority": e.get("score")}
                for e in endpoint_result.get("endpoints", [])[:20]
            ]
        }

    def _build_timeline(self, logs: list) -> list:
        return [
            {
                "timestamp": l.created_at.isoformat() if l.created_at else None,
                "agent": l.agent,
                "level": l.level,
                "message": l.message,
            }
            for l in logs
        ]

    async def _generate_pdf(
        self,
        scan,
        website,
        techs,
        preds,
        recs,
        summary,
        discovery_summary,
        endpoint_summary,
        timeline,
        base,
    ) -> str:
        pdf_path = os.path.join(settings.REPORT_PATH, f"{base}.pdf")
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []

            BLACK = colors.HexColor("#09090B")
            GRAY = colors.HexColor("#71717A")
            RED = colors.HexColor("#EF4444")
            ORANGE = colors.HexColor("#F97316")
            YELLOW = colors.HexColor("#F59E0B")
            GREEN = colors.HexColor("#10B981")
            BLUE = colors.HexColor("#3B82F6")
            BG = colors.HexColor("#F4F4F5")

            h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=22, textColor=BLACK,
                                 spaceAfter=6, fontName="Helvetica-Bold")
            h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, textColor=BLACK,
                                 spaceAfter=4, spaceBefore=14, fontName="Helvetica-Bold")
            body = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, textColor=BLACK,
                                  spaceAfter=4, leading=14)
            muted = ParagraphStyle("muted", parent=styles["Normal"], fontSize=9, textColor=GRAY,
                                   spaceAfter=2)

            # Header
            story.append(Paragraph("SENTINEL AI", h1))
            story.append(Paragraph("Laporan Audit Keamanan Website", muted))
            story.append(Paragraph(f"Tanggal: {datetime.now().strftime('%d %B %Y, %H:%M')} WIB", muted))
            story.append(HRFlowable(width="100%", thickness=1, color=BLACK, spaceAfter=12))

            # Score card
            score = float(scan.security_score or 0)
            grade = scan.grade or "-"
            sev_color = RED if score < 60 else ORANGE if score < 70 else YELLOW if score < 80 else GREEN
            score_table = Table([
                [Paragraph(f"<b>Security Score</b>", body),
                 Paragraph(f"<b>{score:.1f}</b>", ParagraphStyle("sc", fontSize=24, textColor=sev_color, fontName="Helvetica-Bold")),
                 Paragraph(f"<b>Grade: {grade}</b>", ParagraphStyle("gr", fontSize=18, textColor=sev_color, fontName="Helvetica-Bold")),
                 Paragraph(f"<b>Risk: {(scan.risk_level or 'N/A').upper()}</b>", body)]
            ], colWidths=["25%", "25%", "25%", "25%"])
            score_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), BG),
                ("ROWBACKGROUNDS", (0,0), (-1,-1), [BG]),
                ("ALIGN", (0,0), (-1,-1), "CENTER"),
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                ("PADDING", (0,0), (-1,-1), 12),
            ]))
            story.append(score_table)
            story.append(Spacer(1, 12))

            # Executive Summary
            story.append(Paragraph("Ringkasan Eksekutif", h2))
            story.append(Paragraph(summary, body))
            story.append(Spacer(1, 8))

            # Stats
            stats_data = [
                ["Metrik", "Nilai"],
                ["Website", website.url if website else "-"],
                ["Total Halaman", str(scan.total_pages)],
                ["Total Endpoint", str(scan.total_endpoints)],
                ["Durasi Scan", f"{scan.duration_seconds or 0} detik"],
                ["Mode Scan", scan.mode.upper()],
                ["Critical", str(scan.critical_count)],
                ["High", str(scan.high_count)],
                ["Medium", str(scan.medium_count)],
                ["Low", str(scan.low_count)],
            ]
            stats_table = Table(stats_data, colWidths=["50%", "50%"])
            stats_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLACK),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, BG]),
                ("GRID", (0,0), (-1,-1), 0.5, GRAY),
                ("PADDING", (0,0), (-1,-1), 6),
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 12))

            # Technologies
            if techs:
                story.append(Paragraph("Teknologi Terdeteksi", h2))
                tech_rows = [["Teknologi", "Kategori", "Confidence"]]
                for t in techs:
                    tech_rows.append([t.name, t.category or "-", f"{t.confidence}%"])
                tech_table = Table(tech_rows, colWidths=["40%", "30%", "30%"])
                tech_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), BLACK),
                    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE", (0,0), (-1,-1), 9),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, BG]),
                    ("GRID", (0,0), (-1,-1), 0.5, GRAY),
                    ("PADDING", (0,0), (-1,-1), 6),
                ]))
                story.append(tech_table)
                story.append(Spacer(1, 12))

            # Discovery & Endpoints
            story.append(Paragraph("Ringkasan Discovery & Endpoint", h2))
            discovery_rows = [
                ["Metric", "Nilai"],
                ["Halaman Ditemukan", str(discovery_summary.get("pages_found", 0))],
                ["Form Ditemukan", str(discovery_summary.get("forms_found", 0))],
                ["Endpoint Ditemukan", str(discovery_summary.get("endpoints_found", 0))],
                ["Aset Ditemukan", str(discovery_summary.get("assets_found", 0))],
                ["Endpoint API", str(len(discovery_summary.get("api_endpoints", [])))],
            ]
            discovery_table = Table(discovery_rows, colWidths=["50%", "50%"])
            discovery_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLACK),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, BG]),
                ("GRID", (0,0), (-1,-1), 0.5, GRAY),
                ("PADDING", (0,0), (-1,-1), 6),
            ]))
            story.append(discovery_table)
            story.append(Spacer(1, 12))

            # Findings
            if preds:
                story.append(Paragraph("Temuan Keamanan", h2))
                pred_rows = [["No", "Temuan", "Severity", "Confidence", "OWASP"]]
                SEV_COLORS = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN, "info": BLUE}
                for i, p in enumerate(preds, 1):
                    sev_c = SEV_COLORS.get(p.severity, GRAY)
                    pred_rows.append([
                        str(i), p.prediction, p.severity.upper(),
                        f"{float(p.confidence):.0f}%", p.owasp_category or "-"
                    ])
                pred_table = Table(pred_rows, colWidths=["6%", "38%", "16%", "16%", "24%"])
                pred_style = TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), BLACK),
                    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE", (0,0), (-1,-1), 8),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, BG]),
                    ("GRID", (0,0), (-1,-1), 0.5, GRAY),
                    ("PADDING", (0,0), (-1,-1), 5),
                    ("ALIGN", (0,0), (0,-1), "CENTER"),
                ])
                pred_table.setStyle(pred_style)
                story.append(pred_table)
                story.append(Spacer(1, 12))

            # Recommendations
            if recs:
                story.append(Paragraph("Rekomendasi Perbaikan", h2))
                for i, r in enumerate(recs, 1):
                    story.append(Paragraph(f"{i}. {r.title}", ParagraphStyle(
                        "rtitle", parent=styles["Normal"], fontSize=11, fontName="Helvetica-Bold",
                        spaceAfter=2, textColor=BLACK)))
                    story.append(Paragraph(f"<b>Prioritas:</b> {r.priority.upper()} | <b>OWASP:</b> {r.owasp_ref or '-'} | <b>CWE:</b> {r.cwe_ref or '-'}", muted))
                    if r.cause:
                        story.append(Paragraph(f"<b>Penyebab:</b> {r.cause}", body))
                    if r.solution:
                        story.append(Paragraph(f"<b>Solusi:</b> {r.solution}", body))
                    story.append(Spacer(1, 6))

            if endpoint_summary and endpoint_summary.get("top_endpoints"):
                story.append(Paragraph("Top Endpoint Prioritas", h2))
                endpoint_rows = [["URL", "Method", "Priority"]]
                for ep in endpoint_summary.get("top_endpoints", []):
                    endpoint_rows.append([ep.get("url", "-"), ep.get("method", "-"), str(ep.get("priority", "-"))])
                endpoint_table = Table(endpoint_rows, colWidths=["55%", "20%", "25%"])
                endpoint_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), BLACK),
                    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE", (0,0), (-1,-1), 9),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, BG]),
                    ("GRID", (0,0), (-1,-1), 0.5, GRAY),
                    ("PADDING", (0,0), (-1,-1), 6),
                ]))
                story.append(endpoint_table)
                story.append(Spacer(1, 12))

            # Timeline
            if timeline:
                story.append(Paragraph("Timeline Scan", h2))
                for item in timeline[-10:]:
                    story.append(Paragraph(f"{item['timestamp']} - [{item['agent']}] {item['message']}", body))
                story.append(Spacer(1, 12))

            # Footer
            story.append(HRFlowable(width="100%", thickness=1, color=GRAY, spaceBefore=12))
            story.append(Paragraph("Laporan ini dibuat secara otomatis oleh Sentinel AI. Untuk informasi lebih lanjut, hubungi tim keamanan Anda.", muted))

            doc.build(story)
            logger.info(f"PDF report generated: {pdf_path}")

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            # Create a minimal text-based PDF fallback
            try:
                from reportlab.pdfgen import canvas
                c = canvas.Canvas(pdf_path, pagesize=A4)
                c.drawString(100, 750, f"Sentinel AI - Security Report")
                c.drawString(100, 720, f"Scan ID: {scan.id}")
                c.drawString(100, 700, f"Security Score: {float(scan.security_score or 0):.1f}")
                c.save()
            except Exception:
                pdf_path = ""

        return pdf_path
