import asyncio
import logging
from datetime import datetime
from typing import Optional

from keep.event_handler.core.bootstrap import Bootstrap
from keep.event_handler.core.kafka_consumer import EventConsumer
from keep.event_handler.api.routes.v1.metrics import CONSUMER_RUNNING


class RedisEventConsumer(EventConsumer):
    """Redis/ARQ-based event consumer."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._worker_task: Optional[asyncio.Task] = None
        self._worker_id = "worker-service"
        self._running = False
        self._started_at: Optional[datetime] = None

    async def start(self):
        self.logger.info("Starting Redis Consumer (ARQ Worker)")
        bootstrap = await Bootstrap.get_instance()
        loop = asyncio.get_running_loop()
        self._worker_task = loop.create_task(bootstrap.run_arq_worker(self._worker_id))
        self._running = True
        self._started_at = datetime.utcnow()
        CONSUMER_RUNNING.set(1)

    async def stop(self):
        self.logger.info("Stopping Redis Consumer")
        self._running = False
        CONSUMER_RUNNING.set(0)
        if self._worker_task:
            if not self._worker_task.done():
                self._worker_task.cancel()
                try:
                    await self._worker_task
                except asyncio.CancelledError:
                    pass
        self.logger.info("Redis Consumer stopped")

    def get_health_status(self) -> dict:
        """Return health status for monitoring."""
        return {
            "running": self._running,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "worker_id": self._worker_id,
            "task_done": self._worker_task.done() if self._worker_task else None,
        }
