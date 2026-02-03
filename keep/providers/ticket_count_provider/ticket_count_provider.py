import dataclasses

import pydantic

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig
from keep.validation.fields import HttpOrHttpsUrl


@pydantic.dataclasses.dataclass
class TicketCountProviderAuthConfig:
    """Configuration for the Ticket Count provider."""

    count_url: HttpOrHttpsUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "URL used to get count of service now tickets per team",
            "sensitive": False,
            "hint": "http://example.ticketcount.com/ or https://example.ticketcount.com/ or http://localhost:8080/",
        }
    )


class TicketCountProvider(BaseProvider):
    """Expose a manual ticket creation link for Ticket Count."""

    PROVIDER_CATEGORY = ["Ticketing"]
    PROVIDER_TAGS = []
    PROVIDER_DISPLAY_NAME = "Ticket Count"

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def validate_config(self):
        self.authentication_config = TicketCountProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        """Nothing to clean up."""
        return
