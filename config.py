# config.py  –  Central configuration. All secrets sourced from environment.
#
# Required environment variables (must be set in .env or container env):
#   API_KEY          – Bearer token for the REST API
#   ES_PASSWORD      – Elasticsearch password
#   SPLUNK_HEC_TOKEN – Splunk HTTP Event Collector token
#
# Optional:
#   GEMINI_API_KEY   – Only required when LLM_PROVIDER=gemini
#   OLLAMA_URL       – Only required when LLM_PROVIDER=ollama
import os
import logging
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional; env vars may be injected directly by the container runtime

logger = logging.getLogger(__name__)


def _require_env(key: str) -> str:
    """Return an environment variable or abort immediately with a clear error."""
    value = os.getenv(key)
    if not value:
        logger.critical(
            "FATAL: Required environment variable '%s' is not set. "
            "Set it in your .env file or container environment. Aborting.", key
        )
        sys.exit(1)
    return value


class Config:
    # ── Elasticsearch ─────────────────────────────────────────────────────────
    ES_HOST: str = os.getenv("ES_HOST", "localhost")
    ES_PORT: int = int(os.getenv("ES_PORT", "9200"))
    ES_USER: str = os.getenv("ES_USER", "elastic")
    ES_PASSWORD: str = os.getenv("ES_PASSWORD", "")   # Set in .env / container env
    ES_INDEX_NAME: str = os.getenv("ES_INDEX_NAME", "siem_logs")
    ES_USE_TLS: bool = os.getenv("ES_USE_TLS", "false").lower() == "true"

    # ── Log Sources ───────────────────────────────────────────────────────────
    _default_sources: str = (
        "test_logs.txt" if os.name == "nt" else "/var/log/syslog,/var/log/auth.log"
    )
    LOG_SOURCES: list = [
        src.strip()
        for src in os.getenv("LOG_SOURCES", _default_sources).split(",")
        if src.strip()
    ]

    # ── Anomaly Detection ─────────────────────────────────────────────────────
    ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "-0.5"))
    TRAINING_DAYS: int = int(os.getenv("TRAINING_DAYS", "7"))
    # Isolation Forest contamination – fraction of expected anomalies (0.01–0.5)
    ANOMALY_CONTAMINATION: float = float(os.getenv("ANOMALY_CONTAMINATION", "0.1"))

    # ── Alerting ──────────────────────────────────────────────────────────────
    ALERT_WEBHOOK: str | None = os.getenv("ALERT_WEBHOOK")
    ALERT_EMAIL: str | None = os.getenv("ALERT_EMAIL")

    # ── Splunk HEC ────────────────────────────────────────────────────────────
    # Token is a UUID issued by Splunk's Settings → Data Inputs → HTTP Event Collector.
    # NEVER commit this token to source control.
    SPLUNK_HEC_URL: str = os.getenv(
        "SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event"
    )
    SPLUNK_HEC_TOKEN: str = os.getenv("SPLUNK_HEC_TOKEN", "")

    # ── LLM Provider ─────────────────────────────────────────────────────────
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "local").lower()
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral")
    GEMINI_API_KEY: str | None = os.getenv("GEMINI_API_KEY")   # Never expose in URLs/logs

    # ── API Security ──────────────────────────────────────────────────────────
    # Generate with:  python -c "import secrets; print(secrets.token_hex(32))"
    # This value is REQUIRED; the application will refuse to start without it.
    API_KEY: str = os.getenv("API_KEY", "")
    # Enforce at startup – validation moved here so errors surface early,
    # not on the first authenticated request.
    if not API_KEY:
        logger.critical(
            "FATAL: API_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
        sys.exit(1)

    # ── Search Limits (DoS prevention) ───────────────────────────────────────
    MAX_SEARCH_RESULTS: int = int(os.getenv("MAX_SEARCH_RESULTS", "500"))

    # ── Pipeline Tuning ───────────────────────────────────────────────────────
    # Number of log lines buffered before a batch is flushed through the pipeline.
    # Lower values reduce latency; higher values increase throughput.
    LOG_BATCH_SIZE: int = int(os.getenv("LOG_BATCH_SIZE", "100"))
