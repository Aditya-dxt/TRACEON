"""FastAPI entry point for the Traceon backend."""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import cors_origins
from .models import ErrorResponse, HealthResponse

logger = logging.getLogger(__name__)

app = FastAPI(title="Traceon API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    response = ErrorResponse(
        error="Request validation failed",
        code="VALIDATION_ERROR",
    )
    return JSONResponse(status_code=422, content=response.model_dump())


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    response = ErrorResponse(error=detail, code="HTTP_ERROR")
    return JSONResponse(
        status_code=exc.status_code,
        content=response.model_dump(),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled API error",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    response = ErrorResponse(
        error="Internal server error",
        code="INTERNAL_SERVER_ERROR",
    )
    return JSONResponse(status_code=500, content=response.model_dump())


@app.get("/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")
