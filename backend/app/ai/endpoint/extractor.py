"""Sentinel AI - Endpoint Intelligence Agent."""
import logging
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Endpoint

logger = logging.getLogger("sentinel.endpoint")

# Priority rules: patterns that indicate security-sensitive endpoints
PRIORITY_RULES = [
    (99, ["/admin", "/administrator", "/wp-admin", "/dashboard"]),
    (97, ["/login", "/signin", "/auth", "/oauth"]),
    (95, ["/upload", "/file-upload", "/import"]),
    (93, ["/api/", "/api/v", "/rest/"]),
    (88, ["/register", "/signup", "/create-account"]),
    (85, ["/profile", "/account", "/settings", "/user"]),
    (80, ["/search", "/query", "/find"]),
    (75, ["/comment", "/review", "/feedback", "/post"]),
    (70, ["/checkout", "/payment", "/order"]),
    (65, ["/forgot-password", "/reset-password", "/change-password"]),
    (60, ["/download", "/export", "/report"]),
    (40, ["/about", "/contact", "/faq", "/help"]),
    (20, ["/assets", "/static", "/css", "/js", "/images"]),
]


def score_endpoint(url_path: str, method: str = "GET", has_params: bool = False) -> int:
    """Calculate priority score for an endpoint."""
    path = url_path.lower()
    base_score = 30  # Default

    for score, patterns in PRIORITY_RULES:
        for pattern in patterns:
            if pattern in path:
                base_score = max(base_score, score)
                break

    # Bonus for POST/PUT/PATCH (more likely to have input validation issues)
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        base_score = min(99, base_score + 5)

    # Bonus for params
    if has_params:
        base_score = min(99, base_score + 3)

    return base_score


class EndpointAgent:
    def __init__(self, db: AsyncSession, scan_id: int, discovery_result: dict):
        self.db = db
        self.scan_id = scan_id
        self.discovery = discovery_result

    async def run(self) -> dict:
        endpoints_raw = self.discovery.get("endpoints", [])
        pages = self.discovery.get("pages", [])
        
        seen = set()
        endpoint_list = []

        # From discovered endpoints
        for ep_path in endpoints_raw:
            if ep_path in seen or not ep_path.startswith("/"):
                continue
            seen.add(ep_path)
            score = score_endpoint(ep_path)
            endpoint_list.append({"url": ep_path, "method": "GET", "type": "page", "score": score})

        # From form actions
        forms_data = self.discovery.get("pages", [])
        for page in pages:
            for form in page.get("forms", []):
                action = form.get("action", "")
                if action and action not in seen:
                    seen.add(action)
                    method = form.get("method", "POST")
                    score = score_endpoint(action, method, True)
                    endpoint_list.append({"url": action, "method": method, "type": "form", "score": score})

        # Sort by priority
        endpoint_list.sort(key=lambda x: x["score"], reverse=True)

        # Persist top 500
        for ep in endpoint_list[:500]:
            e = Endpoint(
                scan_id=self.scan_id,
                url=ep["url"][:2000],
                method=ep["method"],
                endpoint_type=ep["type"],
                priority_score=ep["score"],
                has_params=1 if "?" in ep["url"] else 0,
            )
            self.db.add(e)
        
        await self.db.flush()

        return {
            "endpoints_found": len(endpoint_list),
            "endpoints": endpoint_list[:100]  # Top 100 for scanner
        }
