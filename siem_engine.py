# Processing stages for each log batch:
#   1. Parallel LLM analysis  →  severity + sentiment enrichment
#   2. Isolation Forest       →  anomaly score
#   3. Rule Engine            →  stateful frequency-based alerts
#   4. Storage                →  bulk write to Elasticsearch
#   5. Splunk                 →  fire-and-forget HEC forwarding
#   6. Mitigation             →  fire-and-forget automated response

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from anomaly_detection import AnomalyDetector
from config import Config
from llm_analysis import LLMAnalyzer
from log_collector import LogCollector
from rule_engine import RuleEngine
from sentinel_ai.mitigation import AutomatedMitigator
from sentinel_ai.splunk_integration import SplunkHECSender
from storage import ElasticsearchStorage

logger = logging.getLogger(__name__)

# Severity levels that always trigger automated mitigation
_MITIGATED_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})


class SIEMEngine:
    """
    Top-level orchestrator.  Composes all sub-systems and drives the log
    ingestion → analysis → alerting → response pipeline.

    Typical lifecycle (managed by api.py's lifespan context):
        engine = SIEMEngine()
        await engine.initialize(sources)      # idempotent
        await engine.start_monitoring()       # blocks until cancelled
        await engine.stop_monitoring()        # graceful teardown
    """

    def __init__(self) -> None:
        self.storage = ElasticsearchStorage()
        self.anomaly_detector = AnomalyDetector()
        self.llm_analyzer = LLMAnalyzer()
        self.rule_engine = RuleEngine()
        self.splunk_sender = SplunkHECSender(
            hec_url=Config.SPLUNK_HEC_URL,
            hec_token=Config.SPLUNK_HEC_TOKEN,
        )
        self.mitigator = AutomatedMitigator()

        self.collector: LogCollector | None = None
        self._alert_threshold: float = Config.ANOMALY_THRESHOLD
        self._training_days: int = Config.TRAINING_DAYS
        self._batch_size: int = Config.LOG_BATCH_SIZE
        self._monitoring_tasks: list[asyncio.Task] = []
        self.is_running: bool = False

    # Lifecycle

    async def initialize(self, log_sources: list[str]) -> None:
        """
        Prepare all subsystems.  Safe to call multiple times (e.g., on
        reconfiguration); each call re-trains the anomaly detector.
        """
        logger.info("Initialising SIEM engine with %d source(s).", len(log_sources))
        await self.storage.initialize()
        self.collector = LogCollector(log_sources, self.storage)
        await self._train_anomaly_detector()

    async def start_monitoring(self) -> None:
        """
        Spawn one async task per log source and await their completion.
        Designed to be run as a background task via asyncio.create_task().
        """
        if self.is_running:
            logger.warning("start_monitoring() called while already running; restarting.")
            await self.stop_monitoring()

        if not self.collector:
            raise RuntimeError(
                "SIEMEngine.initialize() must be called before start_monitoring()."
            )

        logger.info("Starting SIEM pipeline monitoring.")
        self.is_running = True
        self._monitoring_tasks = [
            asyncio.create_task(
                self._run_collector(source), name=f"collector:{source}"
            )
            for source in self.collector.log_sources
        ]

        if not self._monitoring_tasks:
            logger.warning("No log sources configured; nothing to monitor.")
            self.is_running = False
            return

        logger.info("Monitoring %d log source(s).", len(self._monitoring_tasks))
        try:
            await asyncio.gather(*self._monitoring_tasks)
        except asyncio.CancelledError:
            logger.info("Monitoring tasks cancelled — shutting down.")

    async def stop_monitoring(self) -> None:
        """Cancel all active collection tasks and release resources."""
        logger.info("Stopping SIEM monitoring.")
        self.is_running = False

        for task in self._monitoring_tasks:
            task.cancel()

        if self._monitoring_tasks:
            await asyncio.gather(*self._monitoring_tasks, return_exceptions=True)
        self._monitoring_tasks.clear()

        await self.splunk_sender.close()
        logger.info("SIEM monitoring stopped.")

    # Pipeline

    async def process_log_batch(self, logs: list[dict[str, Any]]) -> None:
        """
        Run a batch of raw log dicts through the full analysis pipeline.
        All stages are isolated so a failure in one never skips storage.
        """
        if not logs:
            return

        # Stage 1: LLM analysis — run concurrently across all logs in the batch
        logs = await self._enrich_with_llm(logs)

        # Stage 2: Anomaly scoring — synchronous ML inference, defer to thread
        logs = await asyncio.to_thread(self._score_anomalies, logs)

        # Stage 3: Persist to Elasticsearch (primary durable store)
        await self.storage.store_bulk_logs(logs)

        # Stage 4: Forward to Splunk (secondary observability plane — non-blocking)
        asyncio.create_task(
            self.splunk_sender.send_logs(logs), name="splunk:bulk-forward"
        )

        # Stage 5: Evaluate rules and dispatch alerts
        await self._dispatch_alerts(logs)

    async def _enrich_with_llm(
        self, logs: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Concurrently enrich each log with LLM severity/summary/sentiment."""

        async def _analyse_one(log: dict[str, Any]) -> dict[str, Any]:
            try:
                message = log.get("message") or log.get("raw_log", "")
                analysis = await self.llm_analyzer.analyze_log_context(message)
                log["ai_analysis"] = analysis
                log["severity"] = analysis.get("severity", "unknown")
            except Exception:
                logger.warning("LLM enrichment failed for one log.", exc_info=True)
                log.setdefault("severity", "unknown")
            return log

        return list(await asyncio.gather(*(_analyse_one(log) for log in logs)))

    def _score_anomalies(
        self, logs: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Assign anomaly scores in-place.  Returns the same list."""
        if not self.anomaly_detector.is_fitted:
            for log in logs:
                log["anomaly_score"] = 0.0
            return logs

        try:
            scores = self.anomaly_detector.detect_anomalies(logs)
            for log, score in zip(logs, scores):
                log["anomaly_score"] = float(score)
        except Exception:
            logger.error("Anomaly scoring failed; defaulting all scores to 0.", exc_info=True)
            for log in logs:
                log["anomaly_score"] = 0.0

        return logs

    async def _dispatch_alerts(self, logs: list[dict[str, Any]]) -> None:
        """
        Emit anomaly-based and rule-based alerts.
        Splunk forwarding and mitigation are fire-and-forget tasks to avoid
        stalling the ingestion loop if external services are slow.
        """
        for log in logs:
            # Anomaly-based alert
            if log.get("anomaly_score", 0.0) < self._alert_threshold:
                alert = self._build_anomaly_alert(log)
                logger.warning("ANOMALY ALERT | score=%.4f | %s", log["anomaly_score"], alert["message"])
                asyncio.create_task(self.splunk_sender.send_alert(alert), name="splunk:anomaly-alert")
                if alert.get("severity") in _MITIGATED_SEVERITIES:
                    asyncio.create_task(self.mitigator.mitigate(alert), name="mitigate:anomaly")

            # Rule-engine alerts
            rule_alerts = self.rule_engine.evaluate(log)
            for alert in rule_alerts:
                logger.warning("RULE ALERT | rule=%r | %s", alert["rule_name"], alert["message"])
                asyncio.create_task(self.splunk_sender.send_alert(alert), name="splunk:rule-alert")
                asyncio.create_task(self.mitigator.mitigate(alert), name="mitigate:rule")

    # Alert Construction

    def _build_anomaly_alert(self, log: dict[str, Any]) -> dict[str, Any]:
        """Construct a structured, schema-consistent alert dict from an enriched log."""
        return {
            "alert_type": "anomaly",
            "timestamp": log.get("timestamp", ""),
            "severity": log.get("severity", "high"),
            "anomaly_score": log.get("anomaly_score"),
            "source": log.get("source", ""),
            "ip": log.get("ip", ""),
            "message": log.get("message") or log.get("raw_log", ""),
            "ai_summary": log.get("ai_analysis", {}).get("summary", ""),
            "recommendation": self._derive_recommendation(log),
        }

    @staticmethod
    def _derive_recommendation(log: dict[str, Any]) -> str:
        """Return a context-aware remediation hint based on log content and severity."""
        message = (log.get("message") or "").lower()
        severity = log.get("severity", "").lower()

        if any(kw in message for kw in ("denied", "blocked", "unauthorized")):
            return (
                "Investigate potential unauthorised access. Correlate source IP "
                "against threat intelligence feeds and review authentication logs."
            )
        if any(kw in message for kw in ("error", "fail", "exception")):
            return (
                "Check system health dashboards and application logs for the root "
                "cause. Escalate to on-call if the error rate exceeds baseline."
            )
        if severity == "critical":
            return (
                "Immediate triage required. Engage the incident response runbook "
                "and notify the security team."
            )
        return "Monitor for recurrence. Create a trend alert if the pattern persists."

    # Training

    async def _train_anomaly_detector(self) -> None:
        """Load historical logs from Elasticsearch and fit the anomaly model."""
        logger.info(
            "Loading %d days of historical logs for anomaly model training.",
            self._training_days,
        )
        historical = await self._load_historical_logs(self._training_days)
        if not historical:
            logger.warning(
                "No historical logs available; anomaly detector will run unfit "
                "and all scores will be 0.0 until the next restart."
            )
            return

        try:
            # Offload CPU-bound sklearn fit to a thread to keep the event loop free
            await asyncio.to_thread(self.anomaly_detector.fit, historical)
        except Exception:
            logger.error("Anomaly detector training failed.", exc_info=True)

    async def _load_historical_logs(self, days_back: int) -> list[dict[str, Any]]:
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days_back}d/d",
                        "lt": "now/d",
                    }
                }
            }
        }
        return await self.storage.search_logs(query, size=10_000)

    # Collection

    async def _run_collector(self, source: str) -> None:
        """
        Tail a single log source and flush micro-batches through the pipeline.
        Any exception is logged and the source is restarted after a back-off so
        a single bad source never takes down the entire monitoring loop.
        """
        backoff_seconds = 5
        while True:
            try:
                await self._collect_and_batch(source)
            except asyncio.CancelledError:
                logger.info("Collector for %r cancelled cleanly.", source)
                raise
            except Exception:
                logger.error(
                    "Collector for %r crashed; restarting in %ds.",
                    source, backoff_seconds, exc_info=True,
                )
                await asyncio.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, 60)  # exponential cap

    async def _collect_and_batch(self, source: str) -> None:
        """Stream logs from `source` and flush batches of `_batch_size`."""
        assert self.collector is not None
        batch: list[dict[str, Any]] = []

        async for log in self.collector.collect_from_file(source):
            if not log:
                continue
            batch.append(log)
            if len(batch) >= self._batch_size:
                await self.process_log_batch(batch)
                batch.clear()

        # Flush any remaining logs on source EOF
        if batch:
            await self.process_log_batch(batch)