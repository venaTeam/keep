import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keep.api.core.dependencies import get_event_producer
from keep.api.core.messaging import KafkaEventProducer, RedisEventProducer
from keep.common.models.alert import AlertDto, AlertSeverity, AlertStatus


@pytest.fixture
def mock_kafka_producer():
    with patch("keep.api.core.messaging.AIOKafkaProducer") as mock:
        producer_instance = AsyncMock()
        mock.return_value = producer_instance
        yield producer_instance

@pytest.fixture
def mock_arq_pool():
    pool = MagicMock()
    # enqueue_job returns a Job instance, which has a job_id attribute
    job_mock = MagicMock()
    job_mock.job_id = "job_id_123"
    pool.enqueue_job = AsyncMock(return_value=job_mock)
    return pool

@pytest.mark.asyncio
async def test_get_event_producer_kafka():
    # Mock environment to return KAFKA
    with patch.dict(os.environ, {"MESSAGING_TYPE": "KAFKA"}):
        # We need to reset the global instance for the test
        with patch("keep.api.core.dependencies._kafka_producer_instance", None):
            with patch("keep.api.core.dependencies.KafkaEventProducer") as MockProducer:
                producer = await get_event_producer()
                assert producer is not None
                MockProducer.assert_called_once()
                # Ensure it returns the mock instance
                assert producer == MockProducer.return_value

@pytest.mark.asyncio
async def test_get_event_producer_redis(mock_arq_pool):
    # Mock environment to return REDIS
    with patch.dict(os.environ, {"MESSAGING_TYPE": "REDIS"}):
        with patch("keep.api.core.dependencies.get_pool", new_callable=AsyncMock) as mock_get_pool:
            mock_get_pool.return_value = mock_arq_pool
            producer = await get_event_producer()
            assert isinstance(producer, RedisEventProducer)
            mock_get_pool.assert_called_once()

@pytest.mark.asyncio
async def test_kafka_producer_serialization(mock_kafka_producer):
    # Test that Pydantic models are serialized correctly
    producer = KafkaEventProducer()
    # Mock the internal producer
    producer.producer = mock_kafka_producer
    
    alert = AlertDto(
        id="test-id",
        name="test-alert",
        status=AlertStatus.FIRING,
        severity=AlertSeverity.INFO,
        lastReceived="2023-01-01T00:00:00.000Z",
        source=["test"]
    )
    
    # Payload with Pydantic model
    event_payload = {"alert": alert}
    
    await producer.produce(event=event_payload, trace_id="trace-123")
    
    # Verify send_and_wait was called
    mock_kafka_producer.send_and_wait.assert_called_once()
    
    # Verify the argument passed to send_and_wait
    args, _ = mock_kafka_producer.send_and_wait.call_args
    topic, val = args
    
    # Decode the JSON
    data = json.loads(val.decode("utf-8"))
    
    # Check that alert was serialized to a dict
    assert data["event"]["alert"]["id"] == "test-id"
    assert data["event"]["alert"]["status"] == "firing"
    assert data["trace_id"] == "trace-123"

@pytest.mark.asyncio
async def test_redis_producer_flow(mock_arq_pool):
    producer = RedisEventProducer(mock_arq_pool)
    event_payload = {"some": "data"}
    
    await producer.produce(event=event_payload, trace_id="trace-456", provider_type="test")
    
    mock_arq_pool.enqueue_job.assert_called_once()
    call_args = mock_arq_pool.enqueue_job.call_args
    # Arguments are passed positionally to enqueue_job
    # (function_name, tenant_id, provider_type, provider_id, fingerprint, api_key_name, trace_id, event)
    args = call_args[0]
    assert args[0] == "process_event_in_worker"
    # trace_id is the 7th argument (index 6)
    assert args[6] == "trace-456"
