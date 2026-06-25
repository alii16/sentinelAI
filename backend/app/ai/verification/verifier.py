"""
Sentinel AI - Verification Agent
Classifies scan results using rule-based + ML, with proper deduplication.
Each unique finding type is reported ONCE per scan (not once per endpoint).
"""
import logging
import os
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import AIPrediction, MLModel

logger = logging.getLogger("sentinel.verification")

# ── Rule-based classification ────────────────────────────────────
# indicator_key → {prediction, severity, confidence, owasp, cwe}
RULE_BASED = {
    "sql_error_response": {
        "prediction": "SQL Injection",
        "severity":   "critical",
        "confidence": 91,
        "owasp": "A03:2021", "cwe": "CWE-89"
    },
    "potential_sqli": {
        "prediction": "SQL Injection",
        "severity":   "critical",
        "confidence": 84,
        "owasp": "A03:2021", "cwe": "CWE-89"
    },
    "reflected_xss_indicator": {
        "prediction": "Cross-Site Scripting (XSS)",
        "severity":   "high",
        "confidence": 87,
        "owasp": "A03:2021", "cwe": "CWE-79"
    },
    "cookie_missing_httponly": {
        "prediction": "Insecure Cookie Configuration",
        "severity":   "medium",
        "confidence": 96,
        "owasp": "A07:2021", "cwe": "CWE-1004"
    },
    "cookie_missing_secure": {
        "prediction": "Insecure Cookie Configuration",
        "severity":   "medium",
        "confidence": 95,
        "owasp": "A07:2021", "cwe": "CWE-614"
    },
    "cookie_missing_samesite": {
        "prediction": "Missing SameSite Cookie Flag",
        "severity":   "low",
        "confidence": 97,
        "owasp": "A07:2021", "cwe": "CWE-1275"
    },
    "missing_security_headers": {
        "prediction": "Missing Security Headers",
        "severity":   "medium",
        "confidence": 99,
        "owasp": "A05:2021", "cwe": "CWE-693"
    },
    "critical_missing_headers": {
        "prediction": "Critical Security Headers Missing",
        "severity":   "high",
        "confidence": 99,
        "owasp": "A05:2021", "cwe": "CWE-693"
    },
    "information_disclosure": {
        "prediction": "Information Disclosure",
        "severity":   "medium",
        "confidence": 80,
        "owasp": "A05:2021", "cwe": "CWE-200"
    },
    "server_banner_exposed": {
        "prediction": "Server Version Disclosure",
        "severity":   "low",
        "confidence": 98,
        "owasp": "A05:2021", "cwe": "CWE-200"
    },
    "technology_exposed": {
        "prediction": "Technology Stack Disclosure",
        "severity":   "low",
        "confidence": 95,
        "owasp": "A05:2021", "cwe": "CWE-200"
    },
    "sensitive_path_accessible": {
        "prediction": "Broken Access Control",
        "severity":   "high",
        "confidence": 76,
        "owasp": "A01:2021", "cwe": "CWE-284"
    },
    "file_upload_present": {
        "prediction": "File Upload Endpoint Detected",
        "severity":   "medium",
        "confidence": 88,
        "owasp": "A04:2021", "cwe": "CWE-434"
    },
    "csp_unsafe_inline": {
        "prediction": "Insecure Content Security Policy",
        "severity":   "medium",
        "confidence": 97,
        "owasp": "A05:2021", "cwe": "CWE-1021"
    },
}

# Indicators that should only produce ONE finding per scan (not per URL)
GLOBAL_INDICATORS = {
    "missing_security_headers",
    "critical_missing_headers",
    "server_banner_exposed",
    "technology_exposed",
    "information_disclosure",
    "csp_unsafe_inline",
}


class VerificationAgent:
    def __init__(self, db: AsyncSession, scan_id: int, scan_results: List[Dict]):
        self.db           = db
        self.scan_id      = scan_id
        self.scan_results = scan_results or []
        self.ml_model     = None
        self.model_record = None

    async def run(self) -> List[Dict]:
        logger.info(f"[Verification] scan={self.scan_id} results={len(self.scan_results)}")
        await self._load_model()

        predictions: List[Dict] = []
        # global_seen: indicator already recorded once for this scan
        global_seen: set = set()
        # per_url_seen: (indicator, url) already recorded
        per_url_seen: set = set()

        for result in self.scan_results:
            indicators = result.get("indicators", [])
            evidence   = result.get("evidence", {})
            url        = result.get("url", "")

            for indicator in indicators:
                rule = RULE_BASED.get(indicator)
                if not rule:
                    continue

                # Dedup: global indicators reported once per scan
                if indicator in GLOBAL_INDICATORS:
                    if indicator in global_seen:
                        continue
                    global_seen.add(indicator)
                else:
                    # Per-url dedup for endpoint-specific findings
                    key = (indicator, url)
                    if key in per_url_seen:
                        continue
                    per_url_seen.add(key)

                confidence = rule["confidence"]

                # Adjust confidence from ML if available
                if self.ml_model:
                    try:
                        feats = self._extract_features(result, evidence)
                        adj   = self._ml_confidence(feats)
                        if adj and 50 <= adj <= 99:
                            # Blend: 60% rule-based, 40% ML
                            confidence = int(confidence * 0.6 + adj * 0.4)
                    except Exception:
                        pass

                pred_data = {
                    "url":        url,
                    "prediction": rule["prediction"],
                    "severity":   rule["severity"],
                    "confidence": confidence,
                    "owasp":      rule["owasp"],
                    "cwe":        rule["cwe"],
                    "evidence":   evidence,
                    "indicator":  indicator,
                    # positive signals passed through for scoring
                    "positive_signals": evidence.get("positive_signals", []),
                }
                predictions.append(pred_data)

                pred = AIPrediction(
                    scan_id       = self.scan_id,
                    ml_model_id   = self.model_record.id if self.model_record else None,
                    prediction    = rule["prediction"],
                    confidence    = confidence,
                    severity      = rule["severity"],
                    owasp_category= rule["owasp"],
                    cwe_id        = rule["cwe"],
                    is_verified   = 1,
                    evidence      = evidence,
                    probability   = {rule["prediction"]: round(confidence / 100, 2)},
                )
                self.db.add(pred)

        try:
            await self.db.flush()
        except Exception as e:
            logger.warning(f"[Verification] flush error: {e}")

        logger.info(f"[Verification] {len(predictions)} unique findings for scan {self.scan_id}")
        return predictions

    async def _load_model(self):
        try:
            rec = (await self.db.execute(
                select(MLModel).where(MLModel.is_active == 1, MLModel.status == "ready")
            )).scalar_one_or_none()
            if rec and rec.file_path and os.path.exists(rec.file_path):
                import joblib
                self.ml_model     = joblib.load(rec.file_path)
                self.model_record = rec
                logger.info(f"[Verification] ML model loaded: {rec.name}")
        except Exception as e:
            logger.warning(f"[Verification] ML model load failed: {e}")

    def _extract_features(self, result: dict, evidence: dict) -> List[float]:
        raw = result.get("raw_response", {})
        return [
            float(raw.get("status_code",    200)),
            float(raw.get("response_time",    0)),
            float(raw.get("content_length",   0)),
            float(len(result.get("indicators", []))),
            float(evidence.get("missing_count",  0)),
            float(1 if evidence.get("has_upload_form")    else 0),
            float(1 if evidence.get("technology_exposed") else 0),
            float(1 if evidence.get("xss_reflected")      else 0),
            float(len(evidence.get("sqli_errors", []))),
            float(1 if evidence.get("publicly_accessible") else 0),
        ]

    def _ml_confidence(self, features: List[float]) -> Optional[int]:
        try:
            import numpy as np
            X     = np.array(features).reshape(1, -1)
            proba = self.ml_model.predict_proba(X)
            if proba is not None and len(proba[0]) > 0:
                return int(float(max(proba[0])) * 100)
        except Exception:
            pass
        return None
