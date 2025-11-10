"""
Stub S3 provider used for workflow sync tests in on-prem installations.

This module provides just enough functionality for the workflow sync feature
and associated unit tests, without relying on AWS libraries.
"""

import dataclasses
from typing import Any, ClassVar, Dict, List

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope


@dataclasses.dataclass
class S3ProviderAuthConfig:
    bucket: str = dataclasses.field(
        default="keep-workflows",
        metadata={
            "required": True,
            "description": "S3 bucket name",
            "sensitive": False,
        },
    )
    access_key: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "AWS access key (unused in stub)",
            "sensitive": True,
        },
    )
    secret_key: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "AWS secret key (unused in stub)",
            "sensitive": True,
        },
    )
    region: str = dataclasses.field(
        default="us-east-1",
        metadata={
            "required": False,
            "description": "AWS region (unused in stub)",
            "sensitive": False,
        },
    )


class S3Provider(BaseProvider):
    """Minimal S3 provider replacement."""

    PROVIDER_DISPLAY_NAME: ClassVar[str] = "S3 (stub)"
    PROVIDER_DESCRIPTION: ClassVar[str] = (
        "Stub S3 provider that returns preconfigured data. "
        "Used for workflow synchronization tests."
    )
    PROVIDER_TAGS: ClassVar[List[str]] = ["data"]
    PROVIDER_CATEGORY: ClassVar[List[str]] = ["Storage"]
    PROVIDER_SCOPES: ClassVar[List[ProviderScope]] = [
        ProviderScope(
            name="default",
            description="Validate basic configuration",
            mandatory=False,
        )
    ]
    PROVIDER_METHODS: ClassVar[List[Any]] = []
    WEBHOOK_INSTALLATION_REQUIRED: ClassVar[bool] = False

    def __init__(
        self,
        context_manager: ContextManager,
        provider_id: str,
        config: ProviderConfig,
    ) -> None:
        super().__init__(context_manager, provider_id, config)

    def dispose(self) -> None:
        """Nothing to clean up."""

    def validate_config(self) -> None:
        self.authentication_config = S3ProviderAuthConfig(
            **(self.config.authentication or {})
        )

    def validate_scopes(self) -> Dict[str, bool]:
        """Always succeed; this stub does not talk to AWS."""
        return {"default": True}

    def _query(self, **kwargs: Any) -> List[str]:
        """
        In production this would fetch objects from S3.
        Tests patch this method, so returning an empty list is sufficient.
        """
        return []

