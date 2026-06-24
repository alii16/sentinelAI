"""
Sentinel AI - Scanner Agent
Executes the attack plan and collects evidence for AI verification.
All tests are passive/observational - collecting indicators rather than exploiting.
"""
import asyncio
import logging
import time
import hashlib
from typing import Dict, List, Any, Callable, Optional
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.scanner")

# Security headers that should be present
SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options",
    "x-xss-protection", "referrer-policy",
    "permissions-policy", "cache-control",
]

# SQL Injection test indicators (observe responses, not exploit)
SQLI_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate", "odbc driver", "ora-",
    "microsoft ole db provider", "syntax error",
]

# XSS test indicators
XSS_TEST_PAYLOAD = "<script>sentinel_xss_test</script>"
XSS_REFLECTED_CHECK = "sentinel_xss_test"

# Common information disclosure patterns
INFO_DISCLOSURE_PATTERNS = [
    "stack trace", "exception in thread", "fatal error",
    "parse error", "database error", "connection refused",
    "debug", "traceback", "environment variables",
    "private key", "secret", "password",
]

MAX_WORKERS = 5
REQUEST_DELAY = 0.1  # seconds between requests


class ScannerAgent:
    def __init__(self, db: AsyncSession, scan_id: int, strategy: dict, timeout_ms: int = 10000):
        self.db = db
        self.scan_id = scan_id
        self.tasks = strategy.get("tasks", [])
        self.timeout = timeout_ms / 1000
        self.results: List[Dict] = []
        self.base_url = ""

    async def run(self, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Run all scanner tasks."""
        total = len(self.tasks)
        if total == 0:
            return []

        # Determine base URL from first task
        # (It will be set from the website URL in orchestrator)
        from sqlalchemy import select
        from app.models.models import Scan, Website
        scan = (await self.db.execute(select(Scan).where(Scan.id == self.scan_id))).scalar_one_or_none()
        if scan:
            website = (await self.db.execute(select(Website).where(Website.id == scan.website_id))).scalar_one_or_none()
            if website:
                self.base_url = website.url.rstrip("/")

        semaphore = asyncio.Semaphore(MAX_WORKERS)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(self.timeout),
            verify=False,
            headers={"User-Agent": "SentinelAI/1.0 (authorized-security-audit)"}
        ) as client:
            for i, task in enumerate(self.tasks):
                async with semaphore:
                    result = await self._run_task(client, task)
                    if result:
                        self.results.append(result)
                    await asyncio.sleep(REQUEST_DELAY)
                    if progress_callback:
                        pct = int((i + 1) / total * 100)
                        try:
                            progress_callback(pct)
                        except Exception:
                            pass

        return self.results

    async def _run_task(self, client: httpx.AsyncClient, task: dict) -> Optional[Dict]:
        """Execute a single scan task."""
        test_type = task.get("test_type")
        url_path = task.get("url", "/")
        method = task.get("method", "GET")
        
        if not url_path.startswith("http"):
            full_url = f"{self.base_url}{url_path}"
        else:
            full_url = url_path

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
            # BASE REQUEST - always fetch the endpoint first
            start = time.time()
            base_resp = await client.request(method, full_url)
            elapsed = int((time.time() - start) * 1000)

            result["raw_response"] = {
                "status_code": base_resp.status_code,
                "response_time": elapsed,
                "content_length": len(base_resp.content),
                "headers": dict(base_resp.headers),
                "content_type": base_resp.headers.get("content-type", ""),
            }

            # Run specific test
            if test_type == "security_header_check":
                self._check_security_headers(base_resp, result)
            elif test_type == "information_disclosure":
                self._check_info_disclosure(base_resp, result)
            elif test_type == "sql_injection_check":
                await self._check_sqli(client, full_url, method, result)
            elif test_type == "xss_check":
                await self._check_xss(client, full_url, method, result)
            elif test_type == "authentication_test":
                self._check_authentication(base_resp, result)
            elif test_type == "authorization_check":
                self._check_authorization(base_resp, result)
            elif test_type == "file_upload_check":
                self._check_file_upload(base_resp, result)
            elif test_type == "config_review":
                self._check_configuration(base_resp, result)
            else:
                # Generic - just collect evidence
                self._collect_generic_evidence(base_resp, result)

        except httpx.TimeoutException:
            result["indicators"].append("timeout")
        except Exception as e:
            result["indicators"].append(f"error:{str(e)[:100]}")

        return result

    def _check_security_headers(self, response: httpx.Response, result: dict):
        missing = []
        present = []
        for header in SECURITY_HEADERS:
            if header in response.headers:
                present.append(header)
            else:
                missing.append(header)
        
        result["evidence"]["missing_security_headers"] = missing
        result["evidence"]["present_security_headers"] = present
        result["evidence"]["missing_count"] = len(missing)
        
        if missing:
            result["indicators"].append("missing_security_headers")
            if len(missing) >= 4:
                result["indicators"].append("critical_missing_headers")

    def _check_info_disclosure(self, response: httpx.Response, result: dict):
        body = response.text.lower()
        found = [p for p in INFO_DISCLOSURE_PATTERNS if p in body]
        if found:
            result["evidence"]["disclosure_patterns"] = found
            result["indicators"].append("information_disclosure")

        # Check for common exposed files
        server = response.headers.get("server", "")
        if server:
            result["evidence"]["server_banner"] = server
            result["indicators"].append("server_banner_exposed")

    async def _check_sqli(self, client: httpx.AsyncClient, url: str, method: str, result: dict):
        """Test for SQL injection by observing error responses."""
        test_payloads = ["'", "''", "' OR '1'='1"]
        
        for payload in test_payloads[:1]:  # Minimal testing
            try:
                # Add to URL as param
                test_url = url + ("&" if "?" in url else "?") + f"id={payload}&q={payload}"
                resp = await client.get(test_url)
                body = resp.text.lower()
                
                found_errors = [indicator for indicator in SQLI_INDICATORS if indicator in body]
                if found_errors:
                    result["evidence"]["sqli_errors"] = found_errors
                    result["indicators"].append("sql_error_response")
                    result["indicators"].append("potential_sqli")
                    break
            except Exception:
                pass

    async def _check_xss(self, client: httpx.AsyncClient, url: str, method: str, result: dict):
        """Test for reflected XSS by observing if payload is reflected."""
        try:
            test_url = url + ("&" if "?" in url else "?") + f"q={XSS_TEST_PAYLOAD}&search={XSS_TEST_PAYLOAD}"
            resp = await client.get(test_url)
            
            if XSS_REFLECTED_CHECK in resp.text:
                result["evidence"]["xss_reflected"] = True
                result["indicators"].append("reflected_xss_indicator")
        except Exception:
            pass

    def _check_authentication(self, response: httpx.Response, result: dict):
        """Check authentication security indicators."""
        # Check for secure cookie flags
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                result["indicators"].append("cookie_missing_httponly")
            if "secure" not in set_cookie.lower():
                result["indicators"].append("cookie_missing_secure")
            if "samesite" not in set_cookie.lower():
                result["indicators"].append("cookie_missing_samesite")
            result["evidence"]["set_cookie"] = set_cookie[:200]

        # Check for CSRF protection
        # (absence of CSRF tokens in login forms is checked at form level)

    def _check_authorization(self, response: httpx.Response, result: dict):
        """Check access control indicators."""
        if response.status_code == 200:
            result["evidence"]["publicly_accessible"] = True
            # Admin or sensitive paths accessible without auth might be an issue
            if any(p in result.get("url_path", "").lower() for p in ["/admin", "/dashboard", "/user"]):
                result["indicators"].append("sensitive_path_accessible")

    def _check_file_upload(self, response: httpx.Response, result: dict):
        """Check file upload endpoint security."""
        body = response.text.lower()
        result["evidence"]["has_upload_form"] = "file" in body or "upload" in body
        if result["evidence"]["has_upload_form"]:
            result["indicators"].append("file_upload_present")

    def _check_configuration(self, response: httpx.Response, result: dict):
        """Check for configuration issues."""
        # Check for common misconfiguration indicators
        headers = dict(response.headers)
        
        if response.headers.get("x-powered-by"):
            result["evidence"]["technology_exposed"] = response.headers.get("x-powered-by")
            result["indicators"].append("technology_exposed")

        csp = response.headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            result["indicators"].append("csp_unsafe_inline")

    def _collect_generic_evidence(self, response: httpx.Response, result: dict):
        """Collect generic evidence for AI analysis."""
        result["evidence"]["status_code"] = response.status_code
        result["evidence"]["response_time"] = result["raw_response"].get("response_time", 0)
