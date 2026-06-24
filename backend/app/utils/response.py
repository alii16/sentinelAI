"""Sentinel AI - Standard response helpers."""
from fastapi.responses import JSONResponse
from typing import Any


def ok(data: Any = None, status_code: int = 200, message: str = "OK"):
    return JSONResponse(
        status_code=status_code,
        content={"success": True, "message": message, "data": data}
    )


def fail(message: str, status_code: int = 400, errors: Any = None):
    body = {"success": False, "message": message}
    if errors is not None:
        body["errors"] = errors
    return JSONResponse(status_code=status_code, content=body)
