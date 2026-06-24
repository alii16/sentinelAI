"""Sentinel AI - Risk Assessment Agent."""
import logging
from typing import List, Dict
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.risk")

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
SCORE_GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "E")]
RISK_LABELS = {"A": "low", "B": "low", "C": "medium", "D": "high", "E": "critical"}


class RiskAgent:
    def __init__(self, db: AsyncSession, scan_id: int, predictions: List[Dict]):
        self.db = db
        self.scan_id = scan_id
        self.predictions = predictions

    async def run(self) -> Dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        weighted_sum = 0

        for p in self.predictions:
            sev = p.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
                confidence = p.get("confidence", 50) / 100
                weighted_sum += SEVERITY_WEIGHTS.get(sev, 0) * confidence

        # Calculate score as a normalized penalty based on severity and confidence.
        # This keeps the score proportional instead of forcing a zero floor for any large finding set.
        total_findings = sum(counts.values())
        if total_findings == 0:
            score = 100.0
        else:
            average_penalty = weighted_sum / total_findings
            score = 100.0 - (average_penalty / 10.0) * 100.0
            score = max(0.0, min(100.0, score))

        # If there are any critical findings, apply a mild additional warning factor.
        if counts["critical"]:
            score -= counts["critical"] * 2
            score = max(0.0, score)

        grade = next((g for threshold, g in SCORE_GRADES if score >= threshold), "E")
        risk_level = RISK_LABELS.get(grade, "medium")

        return {
            "score": round(score, 2),
            "grade": grade,
            "risk_level": risk_level,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "total": total_findings,
        }
