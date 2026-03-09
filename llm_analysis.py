# Backends:
#   local   – VADER sentiment + keyword heuristics (zero external deps, always available)
#   ollama  – Local Ollama instance (privacy-preserving)
#   gemini  – Google Gemini API (requires GEMINI_API_KEY)

import asyncio
import json
import logging
from typing import Any

import aiohttp
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

from config import Config

logger = logging.getLogger(__name__)

# Constants
_SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["critical", "fatal", "panic", "crash", "segmentation fault"],
    "high":     ["error", "fail", "denied", "blocked", "attack", "exception", "unauthorized"],
    "medium":   ["warning", "unusual", "suspicious", "timeout", "refused", "non-fatal"],
    "low":      ["info", "debug", "normal", "success", "accepted", "connected"],
}

_SUMMARY_MAX_LEN = 100
_LLM_TIMEOUT_SECONDS = 8          # Don't let a slow LLM stall the pipeline
_MAX_LOG_MESSAGE_LEN = 4096       # Truncate before sending externally (data-minimisation)


class LLMAnalyzer:
    """
    Analyses a raw log message and returns a structured dict:
      { severity, sentiment, key_entities, summary, recommendation }

    Falls back gracefully to heuristics if any external provider is
    unavailable or returns an unexpected response.
    """

    def __init__(self) -> None:
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        # Configuration sourced exclusively from Config – never hardcoded here
        self.provider: str = Config.LLM_PROVIDER
        self._ollama_url: str = Config.OLLAMA_URL
        self._ollama_model: str = Config.OLLAMA_MODEL
        # NOTE: The API key is stored as a private attribute and is NEVER
        # interpolated into URLs or written to logs.
        self._gemini_api_key: str | None = Config.GEMINI_API_KEY

    # Public API

    async def analyze_log_context(self, log_message: str) -> dict[str, Any]:
        """Analyse a log message; returns a severity/sentiment dict."""
        # Sanitise input length before any processing or external transmission
        safe_message = log_message[:_MAX_LOG_MESSAGE_LEN]

        # 1. Fast heuristics – always executed (CPU-bound, offloaded to thread)
        base_analysis: dict[str, Any] = await asyncio.to_thread(
            self._heuristic_analysis, safe_message
        )

        # 2. Optional LLM enrichment
        llm_analysis: dict[str, Any] = {}
        if self.provider == "ollama":
            llm_analysis = await self._query_ollama(safe_message)
        elif self.provider == "gemini" and self._gemini_api_key:
            llm_analysis = await self._query_gemini(safe_message)

        # LLM overrides heuristics only for fields it explicitly provides
        if llm_analysis:
            base_analysis.update(llm_analysis)

        return base_analysis

    # Heuristic Analysis

    def _heuristic_analysis(self, log_message: str) -> dict[str, Any]:
        """Pure-Python, deterministic rule-based analysis. Never raises."""
        try:
            sentiment = self._compute_sentiment(log_message)
            severity = self._compute_severity(log_message)
            summary = (
                log_message[: _SUMMARY_MAX_LEN - 3] + "..."
                if len(log_message) > _SUMMARY_MAX_LEN
                else log_message
            )
            return {
                "sentiment": sentiment,
                "severity": severity,
                "key_entities": self.extract_entities(log_message),
                "summary": summary,
                "recommendation": "Monitor for recurrence.",
            }
        except Exception:
            logger.exception("Heuristic analysis raised an unexpected error")
            return {"severity": "unknown", "summary": "", "recommendation": ""}

    def _compute_sentiment(self, text: str) -> dict[str, Any]:
        scores = self.sentiment_analyzer.polarity_scores(text)
        if scores["compound"] >= 0.05:
            return {"label": "POSITIVE", "score": scores["pos"]}
        if scores["compound"] <= -0.05:
            return {"label": "NEGATIVE", "score": scores["neg"]}
        return {"label": "NEUTRAL", "score": scores["neu"]}

    @staticmethod
    def _compute_severity(text: str) -> str:
        lower = text.lower()
        for level, keywords in _SEVERITY_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return level
        return "low"

    # LLM Backends

    async def _query_ollama(self, log_message: str) -> dict[str, Any]:
        """Query a local Ollama instance. Returns {} on any failure."""
        prompt = self._build_analysis_prompt(log_message)
        payload = {
            "model": self._ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        try:
            timeout = aiohttp.ClientTimeout(total=_LLM_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self._ollama_url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return self._parse_llm_json(result.get("response", "{}"))
                    logger.warning("Ollama returned HTTP %s", response.status)
        except asyncio.TimeoutError:
            logger.warning("Ollama query timed out after %ss", _LLM_TIMEOUT_SECONDS)
        except Exception:
            logger.warning("Ollama query failed", exc_info=True)
        return {}

    async def _query_gemini(self, log_message: str) -> dict[str, Any]:
        """Query Google Gemini API.
        
        SECURITY NOTE: The API key is sent in a POST body header via the
        `x-goog-api-key` header, NOT as a URL query parameter, to prevent
        it appearing in server access logs, proxy logs, or browser history.
        """
        endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
        headers = {
            # Key transmitted as a request header, not as a URL parameter
            "x-goog-api-key": self._gemini_api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "contents": [{"parts": [{"text": self._build_analysis_prompt(log_message)}]}]
        }
        try:
            timeout = aiohttp.ClientTimeout(total=_LLM_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(endpoint, json=payload, headers=headers) as response:
                    if response.status == 200:
                        result = await response.json()
                        raw_text = (
                            result["candidates"][0]["content"]["parts"][0]["text"]
                        )
                        # Strip Markdown fences that Gemini sometimes emits
                        clean = raw_text.replace("```json", "").replace("```", "").strip()
                        return self._parse_llm_json(clean)
                    # Do NOT log the response body – it may echo the prompt/key
                    logger.error("Gemini API returned HTTP %s", response.status)
        except asyncio.TimeoutError:
            logger.warning("Gemini query timed out after %ss", _LLM_TIMEOUT_SECONDS)
        except Exception:
            logger.warning("Gemini query failed", exc_info=True)
        return {}

    # Helpers

    @staticmethod
    def _build_analysis_prompt(log_message: str) -> str:
        return (
            f'Analyze this system log: "{log_message}"\n'
            "Return ONLY a JSON object with exactly three keys:\n"
            '  "severity": one of low | medium | high | critical\n'
            '  "summary": a concise one-sentence explanation\n'
            '  "recommendation": a concrete, actionable remediation step\n'
            "Do not include any other text, markdown, or keys."
        )

    @staticmethod
    def _parse_llm_json(raw: str) -> dict[str, Any]:
        """Safely parse LLM JSON output; returns {} on parse failure."""
        try:
            parsed = json.loads(raw)
            # Whitelist only the keys we expect – discard anything else
            allowed_keys = {"severity", "summary", "recommendation"}
            return {k: v for k, v in parsed.items() if k in allowed_keys}
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse LLM response as JSON")
            return {}

    def extract_entities(self, text: str) -> list[str]:
        """Extract security-relevant entities (IPs, file paths, usernames)."""
        entities: list[str] = []
        for word in text.split():
            if self.is_ip_like(word):
                entities.append(f"IP:{word}")
            elif "/" in word or "\\" in word:
                entities.append(f"FILE:{word}")
            elif word.startswith("user:") or "username" in word.lower():
                entities.append(f"USER:{word}")
        return entities

    @staticmethod
    def is_ip_like(s: str) -> bool:
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False