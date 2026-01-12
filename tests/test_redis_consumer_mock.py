from unittest.mock import AsyncMock, patch
import pytest
from keep.event_handler.core.redis_consumer import RedisEventConsumer

@pytest.mark.asyncio
async def test_redis_consumer_start_stop():
    # Mock Bootstrap
    with patch("keep.event_handler.core.redis_consumer.Bootstrap") as MockBootstrap:
        mock_bootstrap_instance = AsyncMock()
        # MockBootstrap.get_instance needs to be an AsyncMock itself, so calling it returns a coroutine
        # that resolves to mock_bootstrap_instance
        get_instance_mock = AsyncMock(return_value=mock_bootstrap_instance)
        MockBootstrap.get_instance = get_instance_mock
        
        # Test Start
        consumer = RedisEventConsumer()
        await consumer.start()
        
        # Verify Bootstrap.get_instance called
        get_instance_mock.assert_called_once()
        
        # Verify run_arq_worker called
        mock_bootstrap_instance.run_arq_worker.assert_called_with("worker-service")
        
        # Test Stop
        await consumer.stop()
