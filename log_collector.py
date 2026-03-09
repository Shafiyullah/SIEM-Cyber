# Async tail-style log ingestion from local filesystem sources.
#
# Design notes:
#   • Uses aiofiles for non-blocking disk reads so the main event loop never
#     stalls on slow storage.
#   • Yields structured dicts (not raw strings) so the pipeline always operates
#     on a consistent schema regardless of the upstream log format.
#   • Supports JSON-formatted logs natively; falls back to a Common Log Format
#     heuristic parser, then to a plain message passthrough.

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

import aiofiles
import asyncio

logger = logging.getLogger(__name__)

# Compiled patterns — evaluated once at import time
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Max raw line length accepted — prevents pathological log lines from consuming
# unbounded memory in the batch buffer.
_MAX_LINE_BYTES = 65_536   # 64 KiB


class LogCollector:
    """
    Async file-following log collector.

    Args:
        log_sources:     List of absolute filesystem paths to tail.
        storage_backend: Storage adapter (injected; only carried for legacy
                         compatibility — the collector itself does not write).
    """

    def __init__(self, log_sources: list[str], storage_backend: Any) -> None:
        self.log_sources = log_sources
        # storage_backend kept for API compatibility; collector delegates writes
        # to SIEMEngine, which owns the pipeline.
        self._storage = storage_backend

    # Public API

    async def collect_from_file(
        self, file_path: str
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Async generator that tails `file_path` and yields one structured log
        dict per line.  Waits (with back-off) if the file does not yet exist.

        Yields a sentinel ``{"error": "ParseError", ...}`` dict for lines that
        cannot be parsed, so the pipeline never silently drops events.
        """
        await self._wait_for_file(file_path)

        logger.info("Begin tailing: %s", file_path)
        try:
            async with aiofiles.open(file_path, mode="r", encoding="utf-8", errors="replace") as fh:
                # Seek to end — we only want new lines, not backfill
                await fh.seek(0, 2)

                while True:
                    raw_line = await fh.readline()
                    if raw_line:
                        # Guard against pathological lines before any processing
                        if len(raw_line) > _MAX_LINE_BYTES:
                            logger.warning(
                                "Line from %s exceeds %d bytes; truncating.",
                                file_path, _MAX_LINE_BYTES,
                            )
                            raw_line = raw_line[:_MAX_LINE_BYTES]
                        yield self._parse_line(raw_line.strip(), file_path)
                    else:
                        # No new data yet — yield control back to the event loop
                        await asyncio.sleep(0.1)
        except Exception:
            logger.error("Fatal error reading %s.", file_path, exc_info=True)

    # Parsing

    def _parse_line(self, line: str, source: str) -> dict[str, Any]:
        """
        Attempt to parse `line` into a structured dict.

        Priority:
          1. JSON object — parse as-is and augment with metadata fields.
          2. Common Log Format heuristic — extract IP and message.
          3. Plain fallback — wrap the entire line as the ``message`` field.

        A ``ParseError`` sentinel is returned (not raised) on failure so
        upstream code can optionally filter or count malformed events.
        """
        try:
            if line.startswith("{"):
                structured = json.loads(line)
            else:
                structured = self._parse_common_format(line)

            structured.setdefault(
                "timestamp",
                datetime.now(tz=timezone.utc).isoformat(),
            )
            structured["source"] = source
            structured["raw_log"] = line
            return structured

        except Exception as exc:
            logger.debug(
                "Could not parse line from %s (%s): %.120r", source, exc, line
            )
            return {
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "source": source,
                "raw_log": line,
                "message": line,
                "error": "ParseError",
            }

    @staticmethod
    def _parse_common_format(line: str) -> dict[str, Any]:
        """
        Heuristic parser for Common Log Format and syslog-alike lines.

        Extracts an IP address from the first token when present.
        All remaining tokens become the ``message`` field.
        """
        parts = line.split()
        if not parts:
            return {"message": line}

        first_token = parts[0]
        if _IPV4_RE.match(first_token):
            return {
                "ip": first_token,
                "message": " ".join(parts[1:]) if len(parts) > 1 else "",
            }

        return {"message": line}

    # Helpers

    @staticmethod
    async def _wait_for_file(file_path: str) -> None:
        """
        Poll until `file_path` exists, using exponential back-off to avoid
        busy-looping.  Caps at 30-second intervals.
        """
        if os.path.exists(file_path):
            return
        delay = 2.0
        while not os.path.exists(file_path):
            logger.warning(
                "Log source not found: %s — retrying in %.0fs.", file_path, delay
            )
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 30.0)
        logger.info("Log source available: %s", file_path)