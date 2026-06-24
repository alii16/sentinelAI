"""
Sentinel AI - Verification Agent
Uses Machine Learning to classify scan results and assign confidence scores.
"""
import logging
import os
import json
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import AIPrediction, MLModel, Endpoint

logger = logging.getLogger("sentinel.verification")

# Rule-based fallback classification when no ML model is loaded
RULE_BASED_CLASSIFICATION = {
    "sql_error_response": {
        "prediction": "SQL Injection",
        "severity": "critical",
        "confidence": 88,
        "owasp": "A03:2021",
        "cwe": "CWE-89"
    },
    "potential_sqli": {
        "prediction": "SQL Injection",
        "severity": "critical",
        "confidence": 82,
        "owasp": "A03:2021",
        "cwe": "CWE-89"
    },
    "reflected_xss_indicator": {
        "prediction": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "confidence": 85,
        "owasp": "A03:2021",
        "cwe": "CWE-79"
    },
    "cookie_missing_httponly": {
        "prediction": "Insecure Cookie Configuration",
        "severity": "medium",
        "confidence": 96,
        "owasp": "A07:2021",
        "cwe": "CWE-1004"
    },
    "cookie_missing_secure": {
        "prediction": "Insecure Cookie Configuration",
        "severity": "medium",
        "confidence": 95,
        "owasp": "A07:2021",
        "cwe": "CWE-614"
    },
    "cookie_missing_samesite": {
        "prediction": "Missing SameSite Cookie Flag",
        "severity": "low",
        "confidence": 97,
        "owasp": "A07:2021",
        "cwe": "CWE-1275"
    },
    "missing_security_headers": {
        "prediction": "Missing Security Headers",
        "severity": "medium",
        "confidence": 99,
        "owasp": "A05:2021",
        "cwe": "CWE-693"
    },
    "critical_missing_headers": {
        "prediction": "Critical Security Headers Missing",
        "severity": "high",
        "confidence": 99,
        "owasp": "A05:2021",
        "cwe": "CWE-693"
    },
    "information_disclosure": {
        "prediction": "Information Disclosure",
        "severity": "medium",
        "confidence": 78,
        "owasp": "A02:2021",
        "cwe": "CWE-200"
    },
    "server_banner_exposed": {
        "prediction": "Server Version Disclosure",
        "severity": "low",
        "confidence": 98,
        "owasp": "A05:2021",
        "cwe": "CWE-200"
    },
    "technology_exposed": {
        "prediction": "Technology Stack Disclosure",
        "severity": "low",
        "confidence": 96,
        "owasp": "A05:2021",
        "cwe": "CWE-200"
    },
    "sensitive_path_accessible": {
        "prediction": "Broken Access Control",
        "severity": "high",
        "confidence": 75,
        "owasp": "A01:2021",
        "cwe": "CWE-284"
    },
    "file_upload_present": {
        "prediction": "File Upload Endpoint Detected",
        "severity": "medium",
        "confidence": 90,
        "owasp": "A04:2021",
        "cwe": "CWE-434"
    },
    "csp_unsafe_inline": {
        "prediction": "Insecure Content Security Policy",
        "severity": "medium",
        "confidence": 97,
        "owasp": "A05:2021",
        "cwe": "CWE-1021"
    },
}


class VerificationAgent:
    def __init__(self, db: AsyncSession, scan_id: int, scan_results: List[Dict]):
        self.db = db
        self.scan_id = scan_id
        self.scan_results = scan_results
        self.ml_model = None
        self.model_record = None

    async def run(self) -> List[Dict]:
        """Run ML verification on all scan results."""
        # Try to load active ML model
        logger.info(f"VerificationAgent starting for scan {self.scan_id} with {len(self.scan_results or [])} results")
        await self._load_model()
        logger.info(f"VerificationAgent model loaded: {bool(self.ml_model)}")
        
        predictions = []
        seen = set()  # Deduplicate

        if not self.scan_results:
            logger.info("No scan results to verify; exiting VerificationAgent.run")
            return []

        for result in self.scan_results:
            indicators = result.get("indicators", [])
            evidence = result.get("evidence", {})
            url = result.get("url", "")

            for indicator in indicators:
                if indicator in RULE_BASED_CLASSIFICATION:
                    rule = RULE_BASED_CLASSIFICATION[indicator]
                    dedup_key = f"{rule['prediction']}:{url}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # Try ML model inference
                    confidence = rule["confidence"]
                    if self.ml_model:
                        try:
                            features = self._extract_features(result)
                            ml_confidence = self._predict_with_model(features, rule["prediction"])
                            if ml_confidence:
                                confidence = ml_confidence
                        except Exception as e:
                            logger.debug(f"ML inference failed: {e}")

                    pred_data = {
                        "url": url,
                        "prediction": rule["prediction"],
                        "severity": rule["severity"],
                        "confidence": confidence,
                        "owasp": rule["owasp"],
                        "cwe": rule["cwe"],
                        "evidence": evidence,
                        "indicator": indicator
                    }
                    predictions.append(pred_data)

                    # Persist to DB
                    pred = AIPrediction(
                        scan_id=self.scan_id,
                        ml_model_id=self.model_record.id if self.model_record else None,
                        prediction=rule["prediction"],
                        confidence=confidence,
                        severity=rule["severity"],
                        owasp_category=rule["owasp"],
                        cwe_id=rule["cwe"],
                        is_verified=1,
                        evidence=evidence,
                        probability={rule["prediction"]: confidence / 100}
                    )
                    self.db.add(pred)
                    # Flush periodically to avoid long-running transaction locks when many preds
                    try:
                        await self.db.flush()
                    except Exception:
                        logger.debug("Non-fatal: flush failed while saving prediction; will continue")

        try:
            await self.db.flush()
        except Exception:
            logger.warning("Final flush in VerificationAgent failed")

        logger.info(f"VerificationAgent finished: {len(predictions)} predictions generated for scan {self.scan_id}")
        return predictions

    async def _load_model(self):
        """Load the active ML model from disk."""
        try:
            model_record = (await self.db.execute(
                select(MLModel).where(MLModel.is_active == 1, MLModel.status == "ready")
            )).scalar_one_or_none()
            
            if model_record and model_record.file_path and os.path.exists(model_record.file_path):
                import joblib
                self.ml_model = joblib.load(model_record.file_path)
                self.model_record = model_record
                logger.info(f"Loaded ML model: {model_record.name}")
        except Exception as e:
            logger.warning(f"Could not load ML model: {e}")

    def _extract_features(self, result: dict) -> List[float]:
        """Extract numeric features from scan result for ML inference."""
        raw = result.get("raw_response", {})
        evidence = result.get("evidence", {})
        
        return [
            float(raw.get("status_code", 200)),
            float(raw.get("response_time", 0)),
            float(raw.get("content_length", 0)),
            float(len(result.get("indicators", []))),
            float(evidence.get("missing_count", 0)),
            float(1 if evidence.get("has_upload_form") else 0),
            float(1 if evidence.get("technology_exposed") else 0),
            float(1 if evidence.get("xss_reflected") else 0),
            float(len(evidence.get("sqli_errors", []))),
            float(1 if evidence.get("publicly_accessible") else 0),
        ]

    def _predict_with_model(self, features: List[float], current_prediction: str) -> int | None:
        """Run ML model inference and return adjusted confidence."""
        if not self.ml_model:
            return None
        try:
            import numpy as np
            X = np.array(features).reshape(1, -1)
            proba = self.ml_model.predict_proba(X)
            if proba is not None and len(proba[0]) > 0:
                max_proba = float(max(proba[0]))
                return int(max_proba * 100)
        except Exception:
            pass
        return None
