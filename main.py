# Application entry point for direct (non-Docker) execution.
# In containerised deployments the standard command is:
#   uvicorn api:app --host 0.0.0.0 --port 8000
# This script provides an equivalent local-dev shortcut with structured logging
# and OS-signal handling for graceful shutdown.

from __future__ import annotations

import logging
import logging.config
import signal
import sys

import uvicorn

# Logging configuration
_LOG_CONFIG: dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console"],
    },
    # Suppress chatty third-party loggers
    "loggers": {
        "elastic_transport": {"level": "WARNING"},
        "aiohttp": {"level": "WARNING"},
        "uvicorn.access": {"level": "WARNING"},
    },
}

logging.config.dictConfig(_LOG_CONFIG)
logger = logging.getLogger(__name__)


def _configure_uvicorn() -> uvicorn.Config:
    """Build a production-appropriate Uvicorn configuration."""
    return uvicorn.Config(
        app="api:app",
        host="0.0.0.0",
        port=8000,
        # Use multiple workers in production; 1 is fine for development
        workers=1,
        # Structured JSON access logs (parseable by Elasticsearch/Splunk)
        log_config=_LOG_CONFIG,
        # Forward OS signals to the FastAPI lifespan for clean shutdown
        timeout_graceful_shutdown=30,
    )


def main() -> None:
    logger.info("=" * 60)
    logger.info("  Sentinel-AI SIEM Engine — starting up")
    logger.info("=" * 60)

    config = _configure_uvicorn()
    server = uvicorn.Server(config)

    # Register SIGTERM handler so `docker stop` / `kill -15` shuts down cleanly
    def _sigterm_handler(signum, frame):  # noqa: ANN001
        logger.info("SIGTERM received — initiating graceful shutdown.")
        server.should_exit = True

    signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — shutting down.")
    finally:
        logger.info("Server has stopped.")


if __name__ == "__main__":
    main()