from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import logging, time

logger = logging.getLogger("sentinel.http")

class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        elapsed = int((time.time() - start) * 1000)
        logger.info(f"{request.method} {request.url.path} → {response.status_code} ({elapsed}ms)")
        return response
