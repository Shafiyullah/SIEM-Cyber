# Async Splunk HTTP Event Collector (HEC) sender.
#
# Key design decisions:
#   • A single persistent aiohttp.ClientSession is reused across calls to avoid
#     the overhead of creating a new TCP connection per batch.
#   • All failures are logged and swallowed so a Splunk outage never stalls the
#     main SIEM processing pipeline.
#   • The Authorization header is injected at session creation time; it is never
#     written to application logs or embedded in URLs.

import asyncio
import json
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_HEC_TIMEOUT_SECONDS = 5
_MAX_RETRIES = 2


class SplunkHECSender:
    """
    Async HEC client.  Instantiate once per application; call close() on shutdown.

    Usage:
        sender = SplunkHECSender(hec_url=..., hec_token=..., index="main")
        await sender.send_logs(log_list)
        await sender.send_alert(alert_dict)
        await sender.close()
    """

    def __init__(self, hec_url: str, hec_token: str, index: str = "main") -> None:
        if not hec_url or not hec_token:
            logger.warning(
                "SplunkHECSender initialised without HEC URL/Token. "
                "Log forwarding to Splunk is DISABLED."
            )
        self._hec_url = hec_url
        self._index = index
        # The token is stored privately and only ever written to the
        # Authorization request header; never to logs or URLs.
        self._auth_header = f"Splunk {hec_token}" if hec_token else ""
        self._session: aiohttp.ClientSession | None = None
        self._enabled: bool = bool(hec_url and hec_token)

    # Public API 

    async def send_logs(self, logs: list[dict[str, Any]]) -> None:
        """Forward a batch of structured log dicts to Splunk HEC."""
        if not self._enabled or not logs:
            return
        payload = self._build_payload(logs)
        await self._post_with_retry(payload)

    async def send_alert(self, alert: dict[str, Any]) -> None:
        """Forward a single high-priority alert dict to Splunk HEC."""
        await self.send_logs([alert])

    async def close(self) -> None:
        """Release the underlying connection pool."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # Private Helpers 

    def _build_payload(self, logs: list[dict[str, Any]]) -> str:
        """
        Serialise logs into Splunk's newline-delimited JSON event format.
        Each line is a self-contained HEC event envelope.
        """
        lines: list[str] = []
        for log in logs:
            envelope = {
                "index": self._index,
                "sourcetype": "_json",
                "event": log,
            }
            lines.append(json.dumps(envelope, default=str))
        return "\n".join(lines)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return (or lazily create) a persistent aiohttp session."""
        if self._session is None or self._session.closed:
            headers = {
                # Authorization via header – never via URL query parameter
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def _post_with_retry(self, payload: str) -> None:
        """POST the payload with up to _MAX_RETRIES attempts on transient failures."""
        session = await self._get_session()
        timeout = aiohttp.ClientTimeout(total=_HEC_TIMEOUT_SECONDS)
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with session.post(
                    self._hec_url, data=payload, timeout=timeout
                ) as response:
                    if response.status == 200:
                        logger.debug("Sent %d event(s) to Splunk (attempt %d)", payload.count("\n") + 1, attempt)
                        return
                    body = await response.text()
                    logger.error(
                        "Splunk HEC returned HTTP %s (attempt %d): %s",
                        response.status, attempt, body[:200],
                    )
            except asyncio.TimeoutError:
                logger.warning(
                    "Splunk HEC timed out after %ds (attempt %d/%d).",
                    _HEC_TIMEOUT_SECONDS, attempt, _MAX_RETRIES,
                )
            except aiohttp.ClientError as exc:
                logger.warning(
                    "Splunk HEC network error (attempt %d/%d): %s",
                    attempt, _MAX_RETRIES, exc,
                )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(1.0 * attempt)   # simple linear back-off
