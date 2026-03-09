# Stateful, frequency-based security rule engine.
#
# Design:
#   Rules are evaluated independently.  Each rule tracks a sliding time window
#   of matching events keyed by a grouping field (e.g., IP address, username).
#   When enough events accumulate within the window, an alert is emitted and the
#   window is cleared to prevent duplicate alert storms.
#
# Extending:
#   Add new rules at construction time via add_rule(), or inject them from a
#   YAML/JSON config file for hot-reload without a code change.

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Type alias for rule condition functions
ConditionFn = Callable[[dict[str, Any]], bool]

# Schema for the alert dicts emitted by this engine
_ALERT_SEVERITY = "high"


class RuleEngine:
    """
    Sliding-window, frequency-based alert engine.

    Each rule consists of:
        name            – human-readable identifier (must be unique)
        condition       – ``(log: dict) -> bool`` predicate
        threshold       – minimum number of matching events to trigger
        window_seconds  – time window for counting events
        group_by        – log field used to partition the event counter
                          (e.g., "ip" isolates counts per source IP)
    """

    def __init__(self) -> None:
        # {rule_name: rule_dict}
        self._rules: dict[str, dict[str, Any]] = {}
        # {rule_name: {group_key: deque([unix_timestamps])}}
        self._state: defaultdict[str, defaultdict[str, deque]] = defaultdict(
            lambda: defaultdict(deque)
        )

        self._register_default_rules()

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_rule(
        self,
        *,
        name: str,
        condition: ConditionFn,
        threshold: int,
        window_seconds: int,
        group_by: str = "ip",
    ) -> None:
        """
        Register a new frequency-based detection rule.

        Args:
            name:           Unique rule identifier shown in alert payloads.
            condition:      Predicate that returns True when a log event matches.
            threshold:      Minimum matching events within the window to fire.
            window_seconds: Sliding window duration in seconds.
            group_by:       Log field to partition event counts by (default: "ip").
        """
        if name in self._rules:
            logger.warning("Rule %r already exists; overwriting.", name)
        self._rules[name] = {
            "condition": condition,
            "threshold": threshold,
            "window": window_seconds,
            "group_by": group_by,
        }
        logger.debug("Rule registered: %r (threshold=%d, window=%ds)", name, threshold, window_seconds)

    def evaluate(self, log: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Evaluate a single log against all registered rules.

        Returns a (possibly empty) list of alert dicts for every rule that
        crossed its threshold.  The caller is responsible for routing these
        alerts to storage, Splunk, and the mitigation engine.
        """
        triggered: list[dict[str, Any]] = []
        now = time.monotonic()  # monotonic avoids clock-skew surprises

        for rule_name, rule in self._rules.items():
            try:
                alert = self._evaluate_rule(rule_name, rule, log, now)
                if alert:
                    triggered.append(alert)
            except Exception:
                logger.error(
                    "Rule evaluation crashed for %r — skipping this rule for this log.",
                    rule_name, exc_info=True,
                )

        return triggered

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _evaluate_rule(
        self,
        rule_name: str,
        rule: dict[str, Any],
        log: dict[str, Any],
        now: float,
    ) -> dict[str, Any] | None:
        """
        Run a single rule against one log event.
        Returns an alert dict if the rule fires, otherwise None.
        """
        if not rule["condition"](log):
            return None

        group_key = log.get(rule["group_by"])
        if not group_key:
            # Cannot group — skip rather than conflating all events into one bucket
            return None

        window: deque = self._state[rule_name][group_key]
        window.append(now)

        # Evict timestamps outside the sliding window
        cutoff = now - rule["window"]
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) < rule["threshold"]:
            return None

        # Threshold crossed — build alert and reset the window to prevent storm
        alert = {
            "alert_type": "rule",
            "rule_name": rule_name,
            "severity": _ALERT_SEVERITY,
            "group_by": rule["group_by"],
            "group_value": group_key,
            "event_count": len(window),
            "window_seconds": rule["window"],
            "message": (
                f"Rule '{rule_name}' fired: {len(window)} events "
                f"in {rule['window']}s for {rule['group_by']}={group_key!r}"
            ),
            "source_log": log,
            "timestamp": log.get("timestamp", ""),
        }
        window.clear()
        logger.warning("Rule fired: %r (%s=%r)", rule_name, rule["group_by"], group_key)
        return alert

    def _register_default_rules(self) -> None:
        """Register the built-in detection rules."""

        self.add_rule(
            name="Brute Force Detection",
            condition=lambda log: (
                "failed" in log.get("message", "").lower()
                or "auth failure" in log.get("message", "").lower()
            ),
            threshold=5,          # 5 failures …
            window_seconds=60,    # … in 60 seconds per source IP
            group_by="ip",
        )

        self.add_rule(
            name="Privilege Escalation Attempt",
            condition=lambda log: any(
                kw in log.get("message", "").lower()
                for kw in ("sudo", "su root", "privilege escalation", "chmod 777 /")
            ),
            threshold=1,
            window_seconds=300,
            group_by="user",
        )

        self.add_rule(
            name="Credential Stuffing",
            condition=lambda log: (
                "invalid user" in log.get("message", "").lower()
                or "no such user" in log.get("message", "").lower()
            ),
            threshold=10,
            window_seconds=120,
            group_by="ip",
        )
