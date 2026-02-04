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
    mock_msg.value = json.dumps({
        "trace_id": "test-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "test"}
    }).encode("utf-8")
    mock_msg.partition = 0
    mock_msg.offset = 100

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
    mock_msg.value = json.dumps({
        "trace_id": "fail-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "fail"}
    }).encode("utf-8")
    mock_msg.partition = 0
    mock_msg.offset = 100

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


@pytest.mark.asyncio
async def test_consumer_health_status():
    """
    Verify that get_health_status returns correct status information.
    """
    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer"):
        consumer = KafkaEventConsumer()
        
        # Before start
        status = consumer.get_health_status()
        assert status["running"] is False
        assert status["messages_processed"] == 0
        assert status["messages_failed"] == 0
        assert status["last_error"] is None
        
        # Check config is included
        assert "consumer_config" in status
        assert status["consumer_config"]["topic"] == "keep-events"
        assert status["consumer_config"]["group_id"] == "keep-event-handler"


@pytest.mark.asyncio
async def test_consumer_configuration_defaults():
    """
    Verify that consumer configuration has correct default values.
    """
    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer") as mock_consumer_class:
        consumer = KafkaEventConsumer()
        
        # Verify the consumer was created with correct timeout defaults
        call_kwargs = mock_consumer_class.call_args.kwargs
        
        # Default timeout values for long-running processing
        assert call_kwargs["max_poll_interval_ms"] == 600000  # 10 minutes
        assert call_kwargs["session_timeout_ms"] == 60000     # 1 minute
        assert call_kwargs["heartbeat_interval_ms"] == 3000   # 3 seconds
        assert call_kwargs["max_poll_records"] == 1           # One at a time
        
        # Verify auto commit is disabled (manual commit for safety)
        assert call_kwargs["enable_auto_commit"] is False


@pytest.mark.asyncio
async def test_consumer_configuration_custom():
    """
    Verify that consumer configuration can be customized via environment variables.
    """
    custom_config = {
        "KAFKA_MAX_POLL_INTERVAL_MS": "900000",  # 15 minutes
        "KAFKA_SESSION_TIMEOUT_MS": "120000",    # 2 minutes
        "KAFKA_HEARTBEAT_INTERVAL_MS": "5000",   # 5 seconds
        "KAFKA_MAX_POLL_RECORDS": "5",
    }
    
    with patch("keep.event_handler.core.kafka_consumer.config") as mock_config:
        # Set up config mock to return custom values
        def config_side_effect(key, default=None, cast=None):
            if key in custom_config:
                return custom_config[key]
            return default
        
        mock_config.side_effect = config_side_effect
        
        with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer") as mock_consumer_class:
            consumer = KafkaEventConsumer()
            
            # Verify custom configuration was applied
            call_kwargs = mock_consumer_class.call_args.kwargs
            
            assert call_kwargs["max_poll_interval_ms"] == 900000
            assert call_kwargs["session_timeout_ms"] == 120000
            assert call_kwargs["heartbeat_interval_ms"] == 5000
            assert call_kwargs["max_poll_records"] == 5


@pytest.mark.asyncio
async def test_consume_loop_updates_metrics_on_success():
    """
    Verify that successful message processing updates health metrics.
    """
    mock_msg = MagicMock()
    mock_msg.value = json.dumps({
        "trace_id": "test-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "test"}
    }).encode("utf-8")
    mock_msg.partition = 0
    mock_msg.offset = 100

    mock_consumer_instance = AsyncMock()
    mock_consumer_instance.__aiter__.return_value = [mock_msg]
    mock_consumer_instance.commit = AsyncMock()

    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_wrapper", new_callable=AsyncMock):
            consumer = KafkaEventConsumer()
            consumer._running = True
            
            # Run consume loop
            await consumer._consume_loop()
            
            # Check metrics were updated
            assert consumer._messages_processed == 1
            assert consumer._messages_failed == 0
            assert consumer._last_message_time is not None
            assert consumer._last_processing_duration_ms is not None
            assert consumer._last_processing_duration_ms >= 0


@pytest.mark.asyncio  
async def test_consume_loop_updates_metrics_on_failure():
    """
    Verify that failed message processing updates error metrics.
    """
    mock_msg = MagicMock()
    mock_msg.value = json.dumps({
        "trace_id": "fail-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "fail"}
    }).encode("utf-8")
    mock_msg.partition = 0
    mock_msg.offset = 100

    mock_consumer_instance = AsyncMock()
    mock_consumer_instance.__aiter__.return_value = [mock_msg]
    mock_consumer_instance.commit = AsyncMock()

    with patch("keep.event_handler.core.kafka_consumer.AIOKafkaConsumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_wrapper", new_callable=AsyncMock) as mock_process:
            mock_process.side_effect = Exception("Test failure")
            
            consumer = KafkaEventConsumer()
            consumer._running = True
            
            # Run consume loop - should raise
            with pytest.raises(Exception):
                await consumer._consume_loop()
            
            # Check error metrics were updated
            assert consumer._messages_failed == 1
            assert consumer._last_error == "Test failure"
