"""
Stub Datadog provider used for on-prem installations and automated tests.

The real Datadog integration was removed to avoid cloud-only dependencies.
This lightweight implementation keeps the public surface that the rest of the
codebase (and tests) expect without performing any external calls.
"""

import dataclasses
import hashlib
import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope


@dataclasses.dataclass
class DatadogProviderAuthConfig:
    api_key: str = dataclasses.field(
        default="stub",
        metadata={
            "required": False,
            "description": "Datadog API key (not used in stub implementation)",
            "sensitive": False,
        },
    )
    app_key: str = dataclasses.field(
        default="stub",
        metadata={
            "required": False,
            "description": "Datadog APP key (not used in stub implementation)",
            "sensitive": False,
        },
    )


class DatadogProvider(BaseProvider):
    """
    Minimal Datadog provider replacement.
    """

    PROVIDER_DISPLAY_NAME: ClassVar[str] = "Datadog (stub)"
    PROVIDER_DESCRIPTION: ClassVar[str] = (
        "Lightweight Datadog provider maintained for compatibility in on-prem setups."
    )
    PROVIDER_TAGS: ClassVar[List[str]] = ["alert"]
    PROVIDER_CATEGORY: ClassVar[List[str]] = ["Monitoring"]
    PROVIDER_SCOPES: ClassVar[List[ProviderScope]] = [
        ProviderScope(
            name="default",
            description="Validate basic configuration",
            mandatory=False,
        )
    ]
    PROVIDER_METHODS: ClassVar[List[Any]] = []
    WEBHOOK_INSTALLATION_REQUIRED: ClassVar[bool] = False
    FINGERPRINT_FIELDS: ClassVar[List[str]] = ["monitor_id", "title"]

    def __init__(
        self,
        context_manager: ContextManager,
        provider_id: str,
        config: ProviderConfig,
    ) -> None:
        super().__init__(context_manager, provider_id, config)

    def dispose(self) -> None:
        """No resources to dispose."""

    def validate_config(self) -> None:
        """Store the configuration dataclass for potential future use."""
        self.authentication_config = DatadogProviderAuthConfig(
            **(self.config.authentication or {})
        )

    def validate_scopes(self) -> Dict[str, bool]:
        """Always succeed; the stub does not reach external services."""
        return {"default": True}

    @staticmethod
    def parse_event_raw_body(raw_body: bytes | dict) -> dict:
        """Support both JSON byte payloads and already parsed dicts."""
        if isinstance(raw_body, (bytes, bytearray)):
            return json.loads(raw_body.decode("utf-8"))
        return raw_body

    @classmethod
    def simulate_alert(cls, **kwargs: Any) -> dict:
        """Generate a deterministic-but-randomised alert payload."""
        now = datetime.utcnow()
        monitor_id = kwargs.get("monitor_id") or str(
            random.randint(10**9, 10**10 - 1)
        )
        scopes = kwargs.get("scopes") or [
            f"service-{random.randint(1, 3)}",
            f"team-{random.randint(1, 2)}",
        ]
        payload = {
            "id": kwargs.get(
                "id",
                hashlib.sha256(f"{monitor_id}-{now.timestamp()}".encode()).hexdigest(),
            ),
            "title": kwargs.get("title", "Datadog Stub Alert"),
            "message": kwargs.get("message", "Generated stub alert for testing."),
            "tags": kwargs.get(
                "tags",
                "environment:production,team:infra,service:api",
            ),
            "priority": kwargs.get("priority", random.choice(["P1", "P2", "P3"])),
            "monitor_id": monitor_id,
            "scopes": scopes,
            "status": kwargs.get("status", random.choice(["Alert", "Warn", "OK"])),
            "alert_transition": kwargs.get(
                "alert_transition", random.choice(["Triggered", "Recovered"])
            ),
            "last_updated": int(now.timestamp() * 1000),
        }
        return payload

    @staticmethod
    def _map_status(status: str | None) -> AlertStatus:
        mapping = {
            "Alert": AlertStatus.FIRING,
            "Triggered": AlertStatus.FIRING,
            "Warn": AlertStatus.SUPPRESSED,
            "Muted": AlertStatus.SUPPRESSED,
            "Recovered": AlertStatus.RESOLVED,
            "OK": AlertStatus.RESOLVED,
        }
        return mapping.get(status, AlertStatus.FIRING)

    @classmethod
    def _format_alert(
        cls,
        event: dict | list[dict],
        provider_instance: "BaseProvider" = None,
    ) -> AlertDto | list[AlertDto]:
        if isinstance(event, list):
            return [cls._format_alert(item, provider_instance) for item in event]

        now_iso = datetime.now(timezone.utc).isoformat()
        status = cls._map_status(
            event.get("alert_transition") or event.get("status")
        )

        alert = AlertDto(
            id=event.get("id") or str(uuid.uuid4()),
            name=event.get("title") or "Datadog Stub Alert",
            status=status,
            lastReceived=event.get("last_received", now_iso),
            source=["datadog"],
            message=event.get("message", ""),
            description=event.get("message", ""),
            groups=event.get("scopes") or ["*"],
            severity=AlertSeverity.CRITICAL,
            service=event.get("service", "datadog-stub"),
            url=event.get("url"),
            tags=event.get("tags", ""),
            monitor_id=event.get("monitor_id"),
            extra_details={
                "priority": event.get("priority"),
                "last_updated": event.get("last_updated"),
            },
        )
        alert.fingerprint = BaseProvider.get_alert_fingerprint(
            alert, cls.FINGERPRINT_FIELDS
        )
        return alert

