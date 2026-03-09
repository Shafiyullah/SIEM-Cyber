# anomaly_detection.py
#
# ML-based anomaly scoring using Isolation Forest.
# The contamination parameter (expected fraction of anomalies) is configurable
# via the ANOMALY_CONTAMINATION environment variable (see config.py).

import hashlib
import logging
from datetime import datetime
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import Config

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Wraps an Isolation Forest model with feature extraction logic tailored for
    security log data.

    Lifecycle:
        detector = AnomalyDetector()
        detector.fit(historical_logs)           # must be called before detect
        scores = detector.detect_anomalies(new_logs)
    """

    def __init__(self) -> None:
        self.isolation_forest = IsolationForest(
            contamination=Config.ANOMALY_CONTAMINATION,
            random_state=42,
            n_estimators=100,
        )
        self.scaler = StandardScaler()
        self.is_fitted: bool = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def fit(self, logs: list[dict[str, Any]]) -> None:
        """
        Fit the anomaly detector on a list of historical log dicts.
        Silently no-ops if `logs` is empty to avoid sklearn errors.
        """
        if not logs:
            logger.warning("AnomalyDetector.fit() called with empty log list. Skipping.")
            return
        df = self._extract_features(logs)
        if df.empty:
            logger.warning("Feature extraction returned an empty DataFrame. Skipping fit.")
            return
        self.isolation_forest.fit(self.scaler.fit_transform(df.values))
        self.is_fitted = True
        logger.info("AnomalyDetector fitted on %d log records.", len(logs))

    def detect_anomalies(self, logs: list[dict[str, Any]]) -> list[float]:
        """
        Return a list of anomaly scores (one per log).
        Lower (more negative) scores indicate stronger anomalies.

        Raises ValueError if called before fit().
        """
        if not self.is_fitted:
            raise ValueError("AnomalyDetector must be fitted before calling detect_anomalies().")
        if not logs:
            return []
        df = self._extract_features(logs)
        return self.isolation_forest.decision_function(
            self.scaler.transform(df.values)
        ).tolist()

    # ── Feature Engineering ────────────────────────────────────────────────────

    def _extract_features(self, logs: list[dict[str, Any]]) -> pd.DataFrame:
        """
        Convert a list of log dicts into a numeric feature matrix.
        Any missing values are filled with 0 to keep the model stable.
        """
        rows: list[dict[str, Any]] = []

        for log in logs:
            row: dict[str, Any] = {}

            # ── Temporal features ──────────────────────────────────────────────
            ts = log.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                row["hour"] = dt.hour
                row["day_of_week"] = dt.weekday()
                row["is_weekend"] = int(dt.weekday() >= 5)
            except (ValueError, AttributeError):
                row["hour"] = 0
                row["day_of_week"] = 0
                row["is_weekend"] = 0

            # ── Source / IP hash features ──────────────────────────────────────
            # We hash strings into fixed-range integers so the model can learn
            # per-source / per-IP frequency patterns without storing raw strings.
            row["source_hash"] = self._hash_to_int(log.get("source", ""))
            ip = log.get("ip")
            row["ip_hash"] = self._hash_to_int(ip) if ip else 0

            # ── Message features ───────────────────────────────────────────────
            message = log.get("message", "")
            row["message_length"] = len(message)
            row["word_count"] = len(message.split())
            row["has_error"] = int(
                any(kw in message.lower() for kw in ("error", "fail", "exception", "denied"))
            )

            rows.append(row)

        return pd.DataFrame(rows).fillna(0)

    @staticmethod
    def _hash_to_int(value: str) -> int:
        """Stable, bounded hash of a string into an unsigned 32-bit integer."""
        return int(hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()[:8], 16)
