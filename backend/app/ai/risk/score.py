"""
Sentinel AI - Risk Assessment Agent
Security Score methodology:
  - Starts at 100
  - Deducted by unique findings weighted by severity
  - Partial credit restored by positive signals (HTTPS, good headers, etc.)
  - Final score reflects real-world risk level, not raw finding count

Reference: similar to how Qualys SSL Labs, Observatory by Mozilla, and
Immuniweb score websites — bonus for good practices, penalty for issues.
"""
import logging
from typing import List, Dict
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.risk")

# ── Penalty per unique finding (not per occurrence) ─────────────
SEVERITY_PENALTY = {
    "critical": 25,   # e.g. SQL Injection confirmed
    "high":     12,   # e.g. Critical headers missing, XSS
    "medium":    6,   # e.g. Missing headers, insecure cookie
    "low":       2,   # e.g. Server version disclosure
    "info":      0,
}

# ── Bonus points for positive security signals ──────────────────
POSITIVE_BONUS = {
    "has_hsts":      8,   # HSTS header present
    "has_csp":       8,   # CSP header present
    "uses_https":    10,  # Site uses HTTPS
    "server_stable": 2,   # No 500 errors
}

# Maximum total bonus capped at 20 pts to avoid inflating score
MAX_BONUS = 20

# Grade thresholds (consistent with industry: A=90+, B=80+, etc.)
SCORE_GRADES = [
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "E"),
]

RISK_LABELS = {
    "A+": "safe",
    "A":  "low",
    "B":  "low",
    "C":  "medium",
    "D":  "high",
    "E":  "critical",
}

# How finding descriptions map to max penalty
# Ensures the same finding type is only penalised once
FINDING_PENALTY_OVERRIDE = {
    # These are serious — full penalty
    "SQL Injection":                 25,
    "Cross-Site Scripting (XSS)":   18,
    "Broken Access Control":         18,
    "File Upload Endpoint Detected": 12,
    "Insecure Content Security Policy": 8,
    # Config issues — moderate
    "Critical Security Headers Missing": 12,
    "Missing Security Headers":           6,
    "Insecure Cookie Configuration":      6,
    "Missing SameSite Cookie Flag":       3,
    # Information leakage — mild
    "Information Disclosure":        5,
    "Server Version Disclosure":     3,
    "Technology Stack Disclosure":   2,
}


class RiskAgent:
    def __init__(self, db: AsyncSession, scan_id: int, predictions: List[Dict]):
        self.db          = db
        self.scan_id     = scan_id
        self.predictions = predictions

    async def run(self) -> Dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_penalty = 0.0

        # ── 1. Penalties: one penalty per unique prediction name ──
        penalised_predictions: set = set()

        for p in self.predictions:
            sev       = p.get("severity", "info")
            pred_name = p.get("prediction", "")
            confidence = p.get("confidence", 50) / 100

            if sev in counts:
                counts[sev] += 1

            if pred_name in penalised_predictions:
                continue
            penalised_predictions.add(pred_name)

            # Use override penalty if defined, else severity default
            base_penalty = FINDING_PENALTY_OVERRIDE.get(
                pred_name,
                SEVERITY_PENALTY.get(sev, 0)
            )
            # Scale penalty by confidence — low confidence = smaller deduction
            total_penalty += base_penalty * confidence

        # ── 2. Positive signals bonus ─────────────────────────────
        collected_signals: set = set()
        for p in self.predictions:
            for sig in p.get("positive_signals", []):
                collected_signals.add(sig)

        # Also check evidence fields
        for p in self.predictions:
            ev = p.get("evidence", {})
            if ev.get("present_security_headers"):
                n_present = len(ev["present_security_headers"])
                if n_present >= 6:
                    collected_signals.add("has_csp")
                    collected_signals.add("has_hsts")

        bonus = min(
            sum(POSITIVE_BONUS.get(sig, 0) for sig in collected_signals),
            MAX_BONUS
        )

        # ── 3. Compute final score ────────────────────────────────
        # Start at 100, apply penalty, then add bonus
        raw_score = 100.0 - total_penalty + bonus
        score     = round(max(0.0, min(100.0, raw_score)), 2)

        # No findings at all → assume not much was scanned, be conservative
        if not self.predictions:
            score = 75.0  # unknown, not perfect

        # Grade
        grade      = next((g for threshold, g in SCORE_GRADES if score >= threshold), "E")
        risk_level = RISK_LABELS.get(grade, "medium")

        result = {
            "score":      score,
            "grade":      grade,
            "risk_level": risk_level,
            "critical":   counts["critical"],
            "high":       counts["high"],
            "medium":     counts["medium"],
            "low":        counts["low"],
            "total":      sum(counts.values()),
            "bonus":      round(bonus, 1),
            "penalty":    round(total_penalty, 1),
        }

        logger.info(
            f"[Risk] scan={self.scan_id} score={score} grade={grade} "
            f"penalty={total_penalty:.1f} bonus={bonus:.1f} "
            f"findings={result['total']}"
        )
        return result
