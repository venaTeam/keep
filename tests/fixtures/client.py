import hashlib
import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from keep.common.core.dependencies import SINGLE_TENANT_UUID, get_event_producer
from keep.common.core.messaging import EventProducer
from keep.common.models.db.tenant import TenantApiKey
from keep.common.event_management.process_event_task import process_event


class MockEventProducer(EventProducer):
    async def produce(self, event: dict, **kwargs):
        # Run process_event synchronously for tests
        process_event(
            ctx={},  # Empty context for tests
            tenant_id=kwargs.get("tenant_id"),
            provider_type=kwargs.get("provider_type"),
            provider_id=kwargs.get("provider_id"),
            fingerprint=kwargs.get("fingerprint"),
            api_key_name=kwargs.get("api_key_name"),
            trace_id=kwargs.get("trace_id"),
            event=event,
            provider_name=kwargs.get("provider_name"),
        )
        return "mock-task-id"


@pytest.fixture
def test_app(monkeypatch, request, db_session):
    # Store original setup_logging function
    import keep.common.logging

    original_setup_logging = keep.common.logging.setup_logging

    # Replace with no-op function to prevent threading issues
    keep.common.logging.setup_logging = lambda: None

    try:
        monkeypatch.setenv("KEEP_USE_LIMITER", "false")
        # Check if request.param is a dict or a string
        if isinstance(request.param, dict):
            # Set environment variables based on the provided dictionary
            for key, value in request.param.items():
                monkeypatch.setenv(key, str(value))
        else:
            # Old behavior for string parameters
            auth_type = request.param
            monkeypatch.setenv("AUTH_TYPE", auth_type)
            monkeypatch.setenv("KEEP_JWT_SECRET", "somesecret")

            if auth_type == "MULTI_TENANT":
                monkeypatch.setenv("AUTH0_DOMAIN", "https://auth0domain.com")

        # Clear and reload modules to ensure environment changes are reflected
        for module in list(sys.modules):
            if module.startswith("keep.api.routes"):
                del sys.modules[module]

            # Bug in db patching
            elif module.startswith("keep.providers.providers_service"):
                importlib.reload(sys.modules[module])

        if "keep.api.api" in sys.modules:
            importlib.reload(sys.modules["keep.api.api"])

        if "keep.api.config" in sys.modules:
            importlib.reload(sys.modules["keep.api.config"])

        # Import and return the app instance
        from keep.api.api import get_app
        from keep.common.core.init import provision_resources

        provision_resources()
        app = get_app()
        return app
    finally:
        # Restore the original setup_logging function
        keep.common.logging.setup_logging = original_setup_logging


# Fixture for TestClient using the test_app fixture
@pytest.fixture
def client(test_app, db_session, monkeypatch):
    # Your existing environment setup
    monkeypatch.setenv("PUSHER_DISABLED", "true")
    monkeypatch.setenv("KEEP_DEBUG_TASKS", "true")
    monkeypatch.setenv("LOGGING_LEVEL", "DEBUG")
    monkeypatch.setenv("SQLALCHEMY_WARN_20", "1")
    # Force defaults to ensure we hit the producer path logic
    monkeypatch.setenv("MESSAGING_TYPE", "REDIS")
    monkeypatch.setenv("REDIS", "false") # Logic in alerts.py: if REDIS or ... we want to HIT the producer path? 
    # Wait, the logic in alerts.py is:
    # messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
    # if REDIS or messaging_type == "KAFKA": use producer
    # else: use local threadpool creation directly.
    
    # We want to USE the producer, so get_event_producer is called, so our override works.
    # So we need conditions to satisfy `if REDIS or messaging_type == "KAFKA"`.
    # Since mocked producer is nice, let's force REDIS=true so it enters the block.
    # But wait, we don't want it to actually connect to Redis.
    # dependency override happens BEFORE the block.
    # So if we override get_event_producer, app will use MockEventProducer.
    # AND we need to enter the `if` block.
    # So we set REDIS="true" via monkeypatch.
    monkeypatch.setenv("REDIS", "true")

    # Override the dependency
    test_app.dependency_overrides[get_event_producer] = lambda: MockEventProducer()

    with TestClient(test_app) as client:
        yield client
    
    # Clean up overrides
    test_app.dependency_overrides = {}


# Common setup for tests
def setup_api_key(
    db_session, api_key_value, tenant_id=SINGLE_TENANT_UUID, role="admin"
):
    hash_api_key = hashlib.sha256(api_key_value.encode()).hexdigest()
    db_session.add(
        TenantApiKey(
            tenant_id=tenant_id,
            reference_id="test_api_key",
            key_hash=hash_api_key,
            created_by="admin@keephq",
            role=role,
        )
    )
    db_session.commit()
