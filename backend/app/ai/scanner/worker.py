"""
Sentinel AI - Scanner Agent
Passive/observational security testing - collects indicators for AI verification.
Deduplication-aware: global checks (headers, config) run ONCE per scan, not per endpoint.
"""
import asyncio
import logging
import time
from typing import Dict, List, Callable, Optional
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.scanner")

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

SQLI_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate", "odbc driver", "ora-",
    "microsoft ole db provider", "syntax error",
]

XSS_TEST_PAYLOAD   = "<script>sentinelxsstest</script>"
XSS_REFLECTED_CHECK = "sentinelxsstest"

INFO_DISCLOSURE_PATTERNS = [
    "stack trace", "exception in thread", "fatal error",
    "parse error", "database error", "connection refused",
    "traceback (most recent call last)", "debug mode",
    "private key", "app_secret", "db_password",
]

MAX_WORKERS    = 5
REQUEST_DELAY  = 0.15


class ScannerAgent:
    def __init__(self, db: AsyncSession, scan_id: int, strategy: dict, timeout_ms: int = 10000):
        self.db           = db
        self.scan_id      = scan_id
        self.tasks        = strategy.get("tasks", [])
        self.timeout      = timeout_ms / 1000
        self.results: List[Dict] = []
        self.base_url     = ""
        # Global-check dedup: run each global test type ONCE only
        self._global_done: set = set()

    # ── Global test types (run once, not per-endpoint) ───────────
    GLOBAL_TESTS = {
        "security_header_check",
        "config_review",
        "information_disclosure",
    }

    async def run(self, progress_callback: Optional[Callable] = None) -> List[Dict]:
        from sqlalchemy import select
        from app.models.models import Scan, Website

        scan = (await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )).scalar_one_or_none()
        if scan:
            website = (await self.db.execute(
                select(Website).where(Website.id == scan.website_id)
            )).scalar_one_or_none()
            if website:
                self.base_url = website.url.rstrip("/")

        total = len(self.tasks)
        if total == 0:
            return []

        semaphore = asyncio.Semaphore(MAX_WORKERS)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(self.timeout),
            verify=False,
            headers={"User-Agent": "SentinelAI/1.0 Security-Audit (authorized)"}
        ) as client:
            for i, task in enumerate(self.tasks):
                test_type = task.get("test_type", "")

                # Skip global tests if already done once
                if test_type in self.GLOBAL_TESTS:
                    if test_type in self._global_done:
                        if progress_callback:
                            progress_callback(int((i + 1) / total * 100))
                        continue
                    self._global_done.add(test_type)

                async with semaphore:
                    result = await self._run_task(client, task)
                    if result:
                        self.results.append(result)
                    await asyncio.sleep(REQUEST_DELAY)
                    if progress_callback:
                        try:
                            progress_callback(int((i + 1) / total * 100))
                        except Exception:
                            pass

        return self.results

    async def _run_task(self, client: httpx.AsyncClient, task: dict) -> Optional[Dict]:
        test_type = task.get("test_type")
        url_path  = task.get("url", "/")
        method    = task.get("method", "GET")

        full_url = url_path if url_path.startswith("http") else f"{self.base_url}{url_path}"

        result = {
            "url": full_url, "url_path": url_path,
            "method": method, "test_type": test_type,
            "owasp_id": task.get("owasp_id"),
            "owasp_name": task.get("owasp_name"),
            "priority": task.get("priority", 50),
            "indicators": [], "evidence": {},
            "raw_response": {}
        }

        try:
            start     = time.time()
            base_resp = await client.request(method, full_url)
            elapsed   = int((time.time() - start) * 1000)

            result["raw_response"] = {
                "status_code":    base_resp.status_code,
                "response_time":  elapsed,
                "content_length": len(base_resp.content),
                "headers":        dict(base_resp.headers),
                "content_type":   base_resp.headers.get("content-type", ""),
            }

            dispatch = {
                "security_header_check": self._check_security_headers,
                "information_disclosure": self._check_info_disclosure,
                "authentication_test":    self._check_authentication,
                "authorization_check":    self._check_authorization,
                "file_upload_check":      self._check_file_upload,
                "config_review":          self._check_configuration,
            }

            if test_type in dispatch:
                dispatch[test_type](base_resp, result)
            elif test_type == "sql_injection_check":
                await self._check_sqli(client, full_url, method, result)
            elif test_type == "xss_check":
                await self._check_xss(client, full_url, method, result)
            else:
                self._collect_generic_evidence(base_resp, result)

            # Bonus indicators for well-configured sites
            self._check_positive_signals(base_resp, result)

        except httpx.TimeoutException:
            result["indicators"].append("timeout")
        except Exception as e:
            result["indicators"].append(f"error:{str(e)[:80]}")

        return result

    # ── Security checks ──────────────────────────────────────────

    def _check_security_headers(self, response: httpx.Response, result: dict):
        missing = []
        present = []
        for h in SECURITY_HEADERS:
            (present if h in response.headers else missing).append(h)

        result["evidence"]["missing_security_headers"] = missing
        result["evidence"]["present_security_headers"] = present
        result["evidence"]["missing_count"]   = len(missing)
        result["evidence"]["present_count"]   = len(present)
        result["evidence"]["total_expected"]  = len(SECURITY_HEADERS)

        if missing:
            result["indicators"].append("missing_security_headers")
        # Only flag as critical if MOST headers are missing (>=5 out of 7)
        if len(missing) >= 5:
            result["indicators"].append("critical_missing_headers")

    def _check_info_disclosure(self, response: httpx.Response, result: dict):
        body   = response.text.lower()
        found  = [p for p in INFO_DISCLOSURE_PATTERNS if p in body]
        server = response.headers.get("server", "")
        if found:
            result["evidence"]["disclosure_patterns"] = found
            result["indicators"].append("information_disclosure")
        if server and any(c.isdigit() for c in server):
            # Server header exposes version number
            result["evidence"]["server_banner"] = server
            result["indicators"].append("server_banner_exposed")

    async def _check_sqli(self, client, url: str, method: str, result: dict):
        try:
            test_url = url + ("&" if "?" in url else "?") + "id=%27&q=%27"
            resp     = await client.get(test_url)
            body     = resp.text.lower()
            found    = [ind for ind in SQLI_INDICATORS if ind in body]
            if found:
                result["evidence"]["sqli_errors"] = found
                result["indicators"].append("sql_error_response")
                result["indicators"].append("potential_sqli")
        except Exception:
            pass

    async def _check_xss(self, client, url: str, method: str, result: dict):
        try:
            import urllib.parse
            encoded  = urllib.parse.quote(XSS_TEST_PAYLOAD)
            test_url = url + ("&" if "?" in url else "?") + f"q={encoded}"
            resp     = await client.get(test_url)
            if XSS_REFLECTED_CHECK in resp.text:
                result["evidence"]["xss_reflected"] = True
                result["indicators"].append("reflected_xss_indicator")
        except Exception:
            pass

    def _check_authentication(self, response: httpx.Response, result: dict):
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            if "httponly" not in cookie_lower:
                result["indicators"].append("cookie_missing_httponly")
            if "secure" not in cookie_lower:
                result["indicators"].append("cookie_missing_secure")
            if "samesite" not in cookie_lower:
                result["indicators"].append("cookie_missing_samesite")
            result["evidence"]["set_cookie"] = set_cookie[:200]

    def _check_authorization(self, response: httpx.Response, result: dict):
        url_path = result.get("url_path", "").lower()
        sensitive = ["/admin", "/dashboard", "/panel", "/manage", "/cpanel"]
        if response.status_code == 200 and any(p in url_path for p in sensitive):
            result["evidence"]["publicly_accessible"] = True
            result["indicators"].append("sensitive_path_accessible")

    def _check_file_upload(self, response: httpx.Response, result: dict):
        body = response.text.lower()
        if "file" in body and ("upload" in body or "choose" in body):
            result["evidence"]["has_upload_form"] = True
            result["indicators"].append("file_upload_present")

    def _check_configuration(self, response: httpx.Response, result: dict):
        powered = response.headers.get("x-powered-by", "")
        if powered:
            result["evidence"]["technology_exposed"] = powered
            result["indicators"].append("technology_exposed")
        csp = response.headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            result["indicators"].append("csp_unsafe_inline")

    def _check_positive_signals(self, response: httpx.Response, result: dict):
        """Collect positive security signals — used by scoring to give credit."""
        headers = response.headers
        positives = []
        if "strict-transport-security" in headers:
            positives.append("has_hsts")
        if "content-security-policy" in headers:
            positives.append("has_csp")
        if str(response.url).startswith("https://"):
            positives.append("uses_https")
        if response.status_code not in (500, 503):
            positives.append("server_stable")
        if positives:
            result["evidence"]["positive_signals"] = positives

    def _collect_generic_evidence(self, response: httpx.Response, result: dict):
        result["evidence"]["status_code"]   = response.status_code
        result["evidence"]["response_time"] = result["raw_response"].get("response_time", 0)
