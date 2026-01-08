import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from keep.event_handler.core.kafka_consumer import KafkaEventConsumer

@pytest.mark.asyncio
async def test_consume_loop_success_commits():
    """
    Verify that if process_event_wrapper succeeds, commit() is called.
    """
    mock_msg = MagicMock()
    mock_msg.value = json.dumps({"trace_id": "test-trace", "tenant_id": "test-tenant", "event": {"data": "test"}}).encode("utf-8")

    # Mock AIOKafkaConsumer
    mock_consumer_cls = AsyncMock()
    mock_consumer_instance = mock_consumer_cls.return_value
    # Async iterator for the consumer
    mock_consumer_instance.__aiter__.return_value = [mock_msg]
    mock_consumer_instance.commit = AsyncMock()

    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_wrapper", new_callable=AsyncMock) as mock_process:
            consumer = KafkaEventConsumer()
            consumer._running = True
            
            # Run the consume loop explicitly
            # It should process one message and then stop because the iterator runs out
            await consumer._consume_loop()

            # Assertions
            mock_process.assert_awaited_once()
            mock_consumer_instance.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_consume_loop_retries_and_crashes():
    """
    Verify that if process_event_wrapper fails continuously:
    1. It retries 3 times.
    2. It does NOT commit.
    3. It raises the exception (crashes).
    """
    mock_msg = MagicMock()
    mock_msg.value = json.dumps({"trace_id": "fail-trace", "tenant_id": "test-tenant", "event": {"data": "fail"}}).encode("utf-8")

    mock_consumer_cls = AsyncMock()
    mock_consumer_instance = mock_consumer_cls.return_value
    mock_consumer_instance.__aiter__.return_value = [mock_msg]
    mock_consumer_instance.commit = AsyncMock()

    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_wrapper", new_callable=AsyncMock) as mock_process:
            # Configure process_event_wrapper to always fail
            mock_process.side_effect = Exception("Processing Error")

            consumer = KafkaEventConsumer()
            consumer._running = True

            # Expect the loop to crash with the exception
            with pytest.raises(Exception, match="Processing Error"):
                await consumer._consume_loop()

            # Assertions
            # Should count 3 attempts (initial + 2 retries? Or 3 full attempts? Logic says 3 attempts)
            assert mock_process.call_count == 3
            # Should NOT commit
            mock_consumer_instance.commit.assert_not_awaited()
