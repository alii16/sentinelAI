"""Sentinel AI - Attack Planner Agent."""
import logging
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.planner")

# Test categories mapped to endpoint types
STRATEGY_MAP = {
    "login": ["authentication_test", "brute_force_check", "session_fixation"],
    "register": ["input_validation", "sql_injection_check", "xss_check"],
    "upload": ["file_upload_check", "path_traversal"],
    "search": ["sql_injection_check", "xss_check", "nosql_injection"],
    "api": ["authorization_check", "input_validation", "rate_limit_check"],
    "admin": ["authorization_check", "authentication_test"],
    "profile": ["idor_check", "xss_check", "input_validation"],
    "payment": ["input_validation", "idor_check"],
    "forgot": ["rate_limit_check", "information_disclosure"],
    "general": ["security_header_check", "information_disclosure", "config_review"],
}

# OWASP category mapping
OWASP_MAP = {
    "authentication_test": ("A07:2021", "Broken Authentication"),
    "brute_force_check": ("A07:2021", "Broken Authentication"),
    "session_fixation": ("A07:2021", "Broken Authentication"),
    "sql_injection_check": ("A03:2021", "Injection"),
    "xss_check": ("A03:2021", "Injection - XSS"),
    "nosql_injection": ("A03:2021", "Injection"),
    "authorization_check": ("A01:2021", "Broken Access Control"),
    "idor_check": ("A01:2021", "Broken Access Control"),
    "file_upload_check": ("A04:2021", "Insecure Design"),
    "path_traversal": ("A01:2021", "Broken Access Control"),
    "input_validation": ("A03:2021", "Injection"),
    "rate_limit_check": ("A05:2021", "Security Misconfiguration"),
    "information_disclosure": ("A02:2021", "Cryptographic Failures"),
    "security_header_check": ("A05:2021", "Security Misconfiguration"),
    "config_review": ("A05:2021", "Security Misconfiguration"),
}


class AttackPlannerAgent:
    def __init__(self, db: AsyncSession, scan_id: int, endpoint_result: dict):
        self.db = db
        self.scan_id = scan_id
        self.endpoints = endpoint_result.get("endpoints", [])

    async def run(self) -> dict:
        tasks = []
        for ep in self.endpoints[:50]:  # Top 50 endpoints
            url = ep["url"]
            method = ep["method"]
            score = ep["score"]

            # Determine endpoint category
            url_lower = url.lower()
            category = "general"
            for cat in ["login", "register", "upload", "search", "api", "admin", "profile", "payment", "forgot"]:
                if cat in url_lower:
                    category = cat
                    break

            test_types = STRATEGY_MAP.get(category, STRATEGY_MAP["general"])
            
            for test_type in test_types:
                owasp_id, owasp_name = OWASP_MAP.get(test_type, ("A05:2021", "Unknown"))
                tasks.append({
                    "url": url,
                    "method": method,
                    "test_type": test_type,
                    "priority": score,
                    "owasp_id": owasp_id,
                    "owasp_name": owasp_name,
                    "category": category
                })

        # Always add global security header check
        tasks.append({
            "url": "/",
            "method": "GET",
            "test_type": "security_header_check",
            "priority": 80,
            "owasp_id": "A05:2021",
            "owasp_name": "Security Misconfiguration",
            "category": "global"
        })

        # Sort by priority
        tasks.sort(key=lambda x: x["priority"], reverse=True)
        return {"tasks": tasks}
