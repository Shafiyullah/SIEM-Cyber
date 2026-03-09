# Automated threat-response module: blocks IPs and revokes user sessions in
# response to high-confidence security alerts from the rule engine or anomaly
# detector.
#
# Production wiring:
#   block_ip()          → replace the mock with iptables / WAF API / cloud SG call
#   revoke_user_access()→ replace the mock with AWS IAM / Okta / AD API call
#
# Security design:
#   All inputs are strictly validated before acting to prevent injection attacks
#   if the mock stubs are ever replaced with shell or API calls.

import asyncio
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Compile validation patterns once at module load-time
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{1,64}$")

_HIGH_SEVERITY_LEVELS = {"high", "critical"}


class AutomatedMitigator:
    """
    Mock automated responder.

    In production, swap the body of block_ip() / revoke_user_access() for
    real infrastructure API calls.  The input validation and state-tracking
    logic should remain unchanged.
    """

    def __init__(self) -> None:
        # Track blocked IPs/users in-memory to avoid duplicate actions.
        # In production, persist this to Redis or a DB.
        self._blocked_ips: set[str] = set()
        self._revoked_users: set[str] = set()

    # Public API

    async def mitigate(self, alert: dict[str, Any]) -> None:
        """
        Dispatch the appropriate response based on the alert's content.
        Only acts on HIGH and CRITICAL severity alerts.
        """
        severity = alert.get("severity", "low").lower()
        if severity not in _HIGH_SEVERITY_LEVELS:
            return

        # Support both anomaly-detector alerts and rule-engine alert shapes
        source_log: dict[str, Any] = alert.get("source_log", alert)
        combined_message = (
            f"{alert.get('message', '')} {source_log.get('message', '')}".lower()
        )
        rule_name: str = alert.get("rule_name", "").lower()
        ip_address: str | None = source_log.get("ip")
        username: str | None = source_log.get("user")

        # Rule-engine originated alerts
        if rule_name:
            if "brute force" in rule_name and ip_address:
                await self.block_ip(ip_address, reason="Repeated authentication failures.")
            if "privilege escalation" in rule_name and username:
                await self.revoke_user_access(username, reason="Privilege escalation rule triggered.")
            return

        # Anomaly / LLM-originated alerts
        if ip_address and any(kw in combined_message for kw in ("unauthorized", "denied", "attack")):
            await self.block_ip(ip_address, reason="High-anomaly score / unauthorized action.")
        if username and any(kw in combined_message for kw in ("privilege", "escalation", "sudo")):
            await self.revoke_user_access(username, reason="Potential privilege escalation detected.")

    async def block_ip(self, ip_address: str, *, reason: str) -> None:
        """
        (Mock) Add an IP address to the network blocklist.

        INPUT VALIDATION: ip_address is verified as a proper IPv4 address before
        any action is taken.  This prevents command injection if this stub is
        ever replaced with a shell command or SDK call.
        """
        if not _IPV4_RE.match(ip_address):
            logger.error(
                "Mitigator: Rejected invalid IP address %r (possible injection attempt).",
                ip_address,
            )
            return

        if ip_address in self._blocked_ips:
            logger.debug("Mitigator: IP %s already blocked; skipping duplicate action.", ip_address)
            return

        logger.warning(
            "[SENTINEL-AI] 🛡️  BLOCKING IP %s | Reason: %s", ip_address, reason
        )
        # BEGIN PRODUCTION STUB
        # Replace this block with a real API call, e.g.:
        #   await firewall_client.deny_ip(ip_address)
        await asyncio.sleep(0.1)   # simulate async I/O
        # END PRODUCTION STUB
        self._blocked_ips.add(ip_address)
        logger.info(
            "[SENTINEL-AI] IP %s successfully added to blocklist.", ip_address
        )

    async def revoke_user_access(self, username: str, *, reason: str) -> None:
        """
        (Mock) Terminate all active sessions and detach IAM policies for a user.

        INPUT VALIDATION: username is validated against an allowlist regex before
        any action is taken.
        """
        if not _USERNAME_RE.match(username):
            logger.error(
                "Mitigator: Rejected invalid username %r (possible injection attempt).",
                username,
            )
            return

        if username in self._revoked_users:
            logger.debug("Mitigator: %s already revoked; skipping duplicate action.", username)
            return

        logger.warning(
            "[SENTINEL-AI] 🔐 REVOKING ACCESS for user '%s' | Reason: %s",
            username, reason,
        )
        # BEGIN PRODUCTION STUB
        # Replace this block with a real API call, e.g.:
        #   await iam_client.detach_all_policies(username)
        #   await session_store.invalidate_sessions(username)
        await asyncio.sleep(0.1)   # simulate async I/O
        # END PRODUCTION STUB
        self._revoked_users.add(username)
        logger.info(
            "[SENTINEL-AI] User '%s' sessions terminated and policies detached.", username
        )
