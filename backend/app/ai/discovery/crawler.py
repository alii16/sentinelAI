"""
Sentinel AI - Discovery Agent
Crawls website, finds pages, forms, endpoints, assets.
"""
import asyncio
import logging
from urllib.parse import urljoin, urlparse, urlencode
from typing import Set, List, Dict, Any
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Page, Form, ScanLog

logger = logging.getLogger("sentinel.discovery")

# Technology fingerprint signatures
TECH_SIGNATURES = {
    "headers": {
        "x-powered-by": {
            "PHP": ["PHP"], "ASP.NET": ["ASP.NET"], "Express": ["Express"],
        },
        "server": {
            "Apache": ["Apache"], "Nginx": ["nginx"], "IIS": ["IIS", "Microsoft-IIS"],
            "LiteSpeed": ["LiteSpeed"],
        },
        "x-generator": {"WordPress": ["WordPress"]},
        "x-drupal-cache": {"Drupal": [""]},
        "cf-ray": {"Cloudflare": [""]},
    },
    "html_meta": {
        "WordPress": ['<meta name="generator" content="WordPress'],
        "Drupal": ['<meta name="generator" content="Drupal'],
        "Joomla": ['<meta name="generator" content="Joomla'],
    },
    "html_body": {
        "Laravel": [
            "laravel_session", "XSRF-TOKEN", "laravel",
        ],
        "CodeIgniter": ["ci_session"],
        "WordPress": ["/wp-content/", "/wp-includes/"],
        "React": ["__REACT_ROOT", "react-root", "_reactRootContainer"],
        "Vue": ["__vue__", "data-v-", "v-app"],
        "Angular": ["ng-version", "ng-app", "_nghost"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.bundle"],
        "TailwindCSS": ["tailwind"],
    }
}

ENDPOINT_PATTERNS = [
    "/login", "/signin", "/register", "/signup", "/admin", "/dashboard",
    "/profile", "/account", "/upload", "/search", "/api/", "/api/v1/",
    "/logout", "/forgot-password", "/reset-password", "/user/", "/users/",
    "/comment", "/post", "/contact", "/checkout", "/cart",
]


class DiscoveryAgent:
    """Crawls a website and discovers all pages, forms, endpoints."""

    def __init__(self, db: AsyncSession, scan_id: int, base_url: str, max_depth: int = 5, max_pages: int = 1000):
        self.db = db
        self.scan_id = scan_id
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.scheme = urlparse(base_url).scheme
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.queue: List[tuple] = [(base_url, 0)]
        self.pages_data: List[Dict] = []
        self.forms_data: List[Dict] = []
        self.endpoints: Set[str] = set()
        self.technologies: Dict[str, int] = {}
        self.headers_seen: Dict[str, str] = {}
        self.cookies_seen: Dict[str, Dict] = {}
        self.assets_data: List[Dict[str, str]] = []
        self.internal_links: Set[str] = set()
        self.external_links: Set[str] = set()
        self.api_endpoints: Set[str] = set()

    async def run(self) -> Dict[str, Any]:
        """Run the discovery agent."""
        logger.info(f"[Discovery] Starting crawl: {self.base_url}")
        
        # Try to fetch robots.txt
        await self._fetch_robots()
        
        # Crawl
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(15.0),
            verify=False,
            headers={"User-Agent": "SentinelAI/1.0 Security Auditor (authorized-testing)"}
        ) as client:
            while self.queue and len(self.visited) < self.max_pages:
                url, depth = self.queue.pop(0)
                norm_url = self._normalize_url(url)
                if norm_url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(norm_url)
                await self._crawl_page(client, url, depth)
                await asyncio.sleep(0.05)  # Small delay between requests

        # Detect endpoints from known patterns
        for ep in ENDPOINT_PATTERNS:
            full_ep = f"{self.base_url}{ep}"
            if full_ep not in self.visited:
                self.endpoints.add(ep)

        # Persist to DB
        await self._save_pages()

        return {
            "pages_found": len(self.pages_data),
            "forms_found": len(self.forms_data),
            "forms": self.forms_data,
            "assets": self.assets_data,
            "javascript_files": [a["url"] for a in self.assets_data if a.get("type") == "javascript"],
            "css_files": [a["url"] for a in self.assets_data if a.get("type") == "css"],
            "internal_links": list(self.internal_links),
            "external_links": list(self.external_links),
            "api_endpoints": list(self.api_endpoints),
            "endpoints": list(self.endpoints),
            "technologies": self.technologies,
            "headers": self.headers_seen,
            "cookies": self.cookies_seen,
            "pages": self.pages_data,
        }

    async def _crawl_page(self, client: httpx.AsyncClient, url: str, depth: int):
        """Fetch and parse a single page."""
        import time
        start = time.time()
        try:
            response = await client.get(url)
            elapsed = int((time.time() - start) * 1000)

            # Capture headers and cookies
            for k, v in response.headers.items():
                self.headers_seen[k.lower()] = v
            for name, value in response.cookies.items():
                self.cookies_seen[name] = {"value": value}

            page_data = {
                "url": url, "status_code": response.status_code,
                "response_time": elapsed, "content_type": response.headers.get("content-type", ""),
                "content_length": len(response.content), "depth": depth,
                "title": "", "has_form": False, "has_login": False, "has_upload": False,
                "forms": [], "assets": [], "internal_links": [], "external_links": [],
                "api_endpoints": [], "javascript_files": [], "css_files": []
            }

            content_type = response.headers.get("content-type", "")
            if "html" in content_type:
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Title
                title_tag = soup.find("title")
                page_data["title"] = title_tag.get_text(strip=True) if title_tag else ""

                # Detect technologies
                self._detect_tech_from_html(response.text, response.headers)

                # Find links
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.scheme not in ["http", "https"]:
                        continue
                    if parsed.netloc == self.domain:
                        self.internal_links.add(full_url)
                        if depth < self.max_depth and full_url not in self.visited:
                            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            if clean not in self.visited:
                                self.queue.append((clean, depth + 1))
                    else:
                        self.external_links.add(full_url)
                    page_data["internal_links"].append(full_url) if parsed.netloc == self.domain else page_data["external_links"].append(full_url)

                # Find forms
                forms = soup.find_all("form")
                page_data["has_form"] = len(forms) > 0
                for form in forms:
                    form_data = self._parse_form(form, url)
                    page_data["forms"].append(form_data)
                    page_data["has_login"] = page_data["has_login"] or form_data.get("has_password", False)
                    page_data["has_upload"] = page_data["has_upload"] or form_data.get("has_file", False)
                    self.forms_data.append(form_data)

                # Find assets and endpoints in HTML
                self._extract_assets(soup, url, page_data)
                self._extract_endpoints_from_js(response.text, url, page_data)

            self.pages_data.append(page_data)
            self.endpoints.add(urlparse(url).path)

        except httpx.TimeoutException:
            logger.warning(f"Timeout: {url}")
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")

    def _parse_form(self, form, page_url: str) -> Dict:
        """Parse an HTML form."""
        action = form.get("action", "")
        if action:
            action = urljoin(page_url, action)
        method = form.get("method", "POST").upper()
        inputs = form.find_all(["input", "textarea", "select"])
        
        has_password = any(i.get("type") == "password" for i in inputs)
        has_file = any(i.get("type") == "file" for i in inputs)
        has_hidden = any(i.get("type") == "hidden" for i in inputs)
        
        form_type = "general"
        if has_password and any(i.get("type") == "text" or i.get("name", "").lower() in ["email","username"] for i in inputs):
            form_type = "login"
        elif has_file:
            form_type = "upload"
        elif any(i.get("name","").lower() in ["q","query","search","keyword"] for i in inputs):
            form_type = "search"
        elif "register" in (action or "").lower() or "signup" in (action or "").lower():
            form_type = "register"
        elif "forgot" in (action or "").lower():
            form_type = "forgot"
        
        return {
            "action": action, "method": method,
            "has_password": has_password, "has_file": has_file,
            "has_hidden": has_hidden, "input_count": len(inputs),
            "form_type": form_type, "raw_html": str(form)[:2000]
        }

    def _detect_tech_from_html(self, html: str, headers):
        """Detect technologies from HTML content and headers."""
        # From headers
        for header_name, tech_map in TECH_SIGNATURES["headers"].items():
            header_val = headers.get(header_name, "").lower()
            for tech, patterns in tech_map.items():
                if any(p.lower() in header_val for p in patterns if p):
                    self.technologies[tech] = min(99, self.technologies.get(tech, 0) + 30)
                elif not patterns or patterns == [""]:
                    if header_val:
                        self.technologies[tech] = min(99, self.technologies.get(tech, 0) + 90)

        # From HTML body
        for tech, patterns in TECH_SIGNATURES["html_body"].items():
            for p in patterns:
                if p.lower() in html.lower():
                    self.technologies[tech] = min(99, self.technologies.get(tech, 0) + 25)

        # From meta tags
        for tech, patterns in TECH_SIGNATURES["html_meta"].items():
            for p in patterns:
                if p.lower() in html.lower():
                    self.technologies[tech] = min(99, self.technologies.get(tech, 0) + 85)

    def _extract_assets(self, soup, page_url: str, page_data: dict):
        """Extract asset URLs from page HTML."""
        for tag, attr, kind in [
            ("img", "src", "asset"),
            ("script", "src", "javascript"),
            ("link", "href", "css"),
        ]:
            for element in soup.find_all(tag):
                path = element.get(attr)
                if not path:
                    continue
                full_url = urljoin(page_url, path)
                if kind == "asset":
                    self.assets_data.append({"url": full_url, "type": tag})
                    page_data["assets"].append(full_url)
                elif kind == "javascript":
                    self.assets_data.append({"url": full_url, "type": "javascript"})
                    page_data["javascript_files"].append(full_url)
                elif kind == "css":
                    rel = element.get("rel", [])
                    if "stylesheet" in rel or tag == "link":
                        self.assets_data.append({"url": full_url, "type": "css"})
                        page_data["css_files"].append(full_url)

    def _extract_endpoints_from_js(self, html: str, page_url: str, page_data: dict):
        """Find API endpoints mentioned in inline JavaScript."""
        import re
        patterns = [
            r'fetch\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
            r'axios\.\w+\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
            r'url:\s*[\'\"]([/][^\'\"]+)[\'\"]',
            r'href\s*=\s*[\'\"]([/][^\'\"]+)[\'\"]',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                ep = match.group(1)
                if ep.startswith("/") and len(ep) < 200:
                    self.api_endpoints.add(ep)
                    page_data["api_endpoints"].append(ep)

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()

    async def _fetch_robots(self):
        """Fetch robots.txt."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(f"{self.base_url}/robots.txt")
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                self.endpoints.add(path)
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            await self._fetch_sitemap(client, sitemap_url)
        except Exception:
            pass

    async def _fetch_sitemap(self, client, sitemap_url: str):
        """Fetch and parse sitemap.xml."""
        try:
            r = await client.get(sitemap_url)
            if r.status_code == 200:
                import re
                urls = re.findall(r'<loc>(.*?)</loc>', r.text)
                for u in urls[:100]:
                    if self.domain in u:
                        self.queue.append((u, 1))
        except Exception:
            pass

    async def _save_pages(self):
        """Persist discovered pages and forms to the database."""
        for pdata in self.pages_data[:self.max_pages]:
            page = Page(
                scan_id=self.scan_id,
                url=pdata["url"][:2000],
                title=pdata.get("title", "")[:500],
                status_code=pdata.get("status_code"),
                response_time=pdata.get("response_time"),
                content_type=pdata.get("content_type", "")[:200],
                content_length=pdata.get("content_length"),
                depth=pdata.get("depth", 0),
                has_form=1 if pdata.get("has_form") else 0,
                has_login=1 if pdata.get("has_login") else 0,
                has_upload=1 if pdata.get("has_upload") else 0,
            )
            self.db.add(page)
            await self.db.flush()

            for fdata in pdata.get("forms", []):
                form = Form(
                    page_id=page.id, scan_id=self.scan_id,
                    action=(fdata.get("action") or "")[:1000],
                    method=fdata.get("method", "POST"),
                    has_password=1 if fdata.get("has_password") else 0,
                    has_file=1 if fdata.get("has_file") else 0,
                    has_hidden=1 if fdata.get("has_hidden") else 0,
                    input_count=fdata.get("input_count", 0),
                    form_type=fdata.get("form_type", "general"),
                    raw_html=fdata.get("raw_html", "")
                )
                self.db.add(form)
        
        await self.db.flush()
