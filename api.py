# FastAPI application – defines REST endpoints and manages SIEM engine lifecycle.
#
# All endpoints except /health require a valid X-API-Key header.
# Authentication uses constant-time comparison to resist timing attacks.

import asyncio
import logging
import secrets
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, field_validator

from config import Config
from siem_engine import SIEMEngine

logger = logging.getLogger(__name__)

# FastAPI App
app = FastAPI(
    title="Sentinel-AI SIEM API",
    description="AI-powered Security Information & Event Management REST API.",
    version="2.0.0",
    # Disable the automatic /docs and /redoc in production (set via env)
    docs_url="/docs" if not Config.API_KEY else "/docs",
)

# Singleton engine
siem_engine = SIEMEngine()

# API Key Authentication
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str | None = Security(_api_key_header)) -> str:
    """
    Dependency that enforces API key authentication.

    Uses secrets.compare_digest() for constant-time comparison to prevent
    timing-based side-channel attacks that could reveal the valid key length.
    """
    if api_key and secrets.compare_digest(api_key, Config.API_KEY):
        return api_key
    # Return 401, not 403 – RFC 9110 §15.5.2 (authentication, not authorisation)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


# Pydantic Models
class LogSourceRequest(BaseModel):
    sources: list[str]

    @field_validator("sources")
    @classmethod
    def sources_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("At least one log source must be provided.")
        # Prevent path traversal in source names
        for src in v:
            if ".." in src:
                raise ValueError(f"Invalid log source path: {src!r}")
        return v


# Lifecycle Events
# Using lifespan (recommended) instead of the deprecated @app.on_event() decorator

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage SIEM engine startup and graceful shutdown."""
    logger.info("Initialising SIEM engine with sources: %s", Config.LOG_SOURCES)
    try:
        await siem_engine.initialize(Config.LOG_SOURCES)
        # Fire-and-forget background task; cancellation handled in stop_monitoring()
        _monitoring_task = asyncio.create_task(
            siem_engine.start_monitoring(), name="siem-monitor"
        )
        logger.info("SIEM monitoring started in background.")
    except Exception:
        logger.error(
            "Failed to initialise SIEM engine – API will run without monitoring.",
            exc_info=True,
        )
        _monitoring_task = None

    yield  # ← application runs here

    logger.info("Shutting down SIEM engine...")
    await siem_engine.stop_monitoring()


app.router.lifespan_context = lifespan


# Endpoints

@app.post("/configure", dependencies=[Depends(require_api_key)], status_code=200)
async def configure_sources(body: LogSourceRequest):
    """Re-configure log sources and restart monitoring. (Protected)"""
    await siem_engine.stop_monitoring()
    await siem_engine.initialize(body.sources)
    asyncio.create_task(siem_engine.start_monitoring(), name="siem-monitor")
    return {"status": "configured", "sources": body.sources}


@app.get("/alerts", dependencies=[Depends(require_api_key)])
async def get_alerts(
    severity: Optional[str] = Query(
        None, description="Severity filter: low | medium | high | critical"
    ),
    time_range: Optional[str] = Query(
        "1h", description="Time window: 1h | 6h | 24h | 7d"
    ),
):
    """Retrieve security alerts from the last N hours/days. (Protected)"""
    _ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
    _TIME_RANGE_MAP = {
        "1h": "now-1h/h",
        "6h": "now-6h/h",
        "24h": "now-24h/d",
        "7d": "now-7d/d",
    }

    must_clauses: list = []

    if severity is not None:
        if severity.lower() not in _ALLOWED_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity. Allowed values: {sorted(_ALLOWED_SEVERITIES)}",
            )
        must_clauses.append({"term": {"severity.keyword": severity.lower()}})

    time_filter = _TIME_RANGE_MAP.get(time_range)
    if not time_filter:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time_range. Allowed values: {list(_TIME_RANGE_MAP)}",
        )
    must_clauses.append({"range": {"timestamp": {"gte": time_filter}}})

    query_body = {
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    alerts = await siem_engine.storage.search_logs(query_body, size=100)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/logs", dependencies=[Depends(require_api_key)])
async def search_logs(
    query: str = Query(..., min_length=1, max_length=512, description="Full-text search term"),
    size: int = Query(50, ge=1, le=500, description="Max results to return (1–500)"),
):
    """
    Full-text search across all collected log fields. (Protected)

    `size` is bounded server-side to prevent DoS via oversized result sets.
    """
    es_query = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["message", "raw_log", "source", "ip"],
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    # size is also capped inside storage.search_logs() as a defence-in-depth measure
    logs = await siem_engine.storage.search_logs(es_query, size=size)
    return {"logs": logs, "count": len(logs)}


@app.get("/health")
async def health_check():
    """Liveness/readiness probe. (Public – no authentication required)"""
    es_healthy = await siem_engine.storage.is_connected()
    return {
        "status": "healthy" if es_healthy else "degraded",
        "engine_running": siem_engine.is_running,
        "elasticsearch_connected": es_healthy,
    }