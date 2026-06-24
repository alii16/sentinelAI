"""Sentinel AI - Technology Fingerprint Agent."""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Technology

logger = logging.getLogger("sentinel.technology")

TECH_CATEGORIES = {
    "Laravel": "framework", "CodeIgniter": "framework", "Django": "framework",
    "Flask": "framework", "Express": "framework", "Spring Boot": "framework",
    "ASP.NET": "framework", "Ruby on Rails": "framework",
    "WordPress": "cms", "Drupal": "cms", "Joomla": "cms",
    "React": "library", "Vue": "library", "Angular": "library",
    "NextJS": "library", "Nuxt": "library", "TailwindCSS": "library",
    "Bootstrap": "library", "jQuery": "library",
    "Apache": "server", "Nginx": "server", "IIS": "server", "LiteSpeed": "server",
    "PHP": "language", "NodeJS": "language", "Python": "language",
    "Cloudflare": "cdn", "Fastly": "cdn",
    "MySQL": "database", "PostgreSQL": "database", "MongoDB": "database",
}


class TechnologyAgent:
    def __init__(self, db: AsyncSession, scan_id: int, discovery_result: dict):
        self.db = db
        self.scan_id = scan_id
        self.discovery = discovery_result

    async def run(self):
        techs = self.discovery.get("technologies", {})
        headers = self.discovery.get("headers", {})

        # Infer from headers
        self._detect_from_headers(headers, techs)

        # Cap confidence at 99
        for tech, confidence in techs.items():
            techs[tech] = min(99, confidence)

        # Persist
        for tech_name, confidence in techs.items():
            if confidence >= 20:
                t = Technology(
                    scan_id=self.scan_id,
                    name=tech_name,
                    category=TECH_CATEGORIES.get(tech_name, "other"),
                    confidence=confidence,
                    source="html+headers"
                )
                self.db.add(t)
        await self.db.flush()
        return techs

    def _detect_from_headers(self, headers: dict, techs: dict):
        server = headers.get("server", "").lower()
        if "apache" in server:
            techs["Apache"] = max(techs.get("Apache", 0), 95)
        if "nginx" in server:
            techs["Nginx"] = max(techs.get("Nginx", 0), 95)
        if "litespeed" in server:
            techs["LiteSpeed"] = max(techs.get("LiteSpeed", 0), 95)

        powered = headers.get("x-powered-by", "").lower()
        if "php" in powered:
            techs["PHP"] = max(techs.get("PHP", 0), 90)
        if "express" in powered:
            techs["Express"] = max(techs.get("Express", 0), 90)
        if "asp.net" in powered:
            techs["ASP.NET"] = max(techs.get("ASP.NET", 0), 90)

        if "cf-ray" in headers:
            techs["Cloudflare"] = max(techs.get("Cloudflare", 0), 99)
