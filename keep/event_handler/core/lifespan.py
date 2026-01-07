import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from keep.common.core.config import config


from keep.event_handler.core.bootstrap import Bootstrap

logger = logging.getLogger(__name__)




@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Event Handler Service")
    
    bootstrap = await Bootstrap.get_instance()
    
    # Initialize DB and other resources
    await bootstrap.run_on_starting()

    messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
    consumer = None
    worker_task = None

    if messaging_type == "KAFKA":
        from keep.event_handler.core.kafka_consumer import KafkaEventConsumer

        logger.info("MESSAGING_TYPE is KAFKA - starting Kafka Consumer")
        consumer = KafkaEventConsumer()
        await consumer.start()

    else:
        # Default to REDIS / ARQ
        logger.info(f"MESSAGING_TYPE is {messaging_type} - starting ARQ Worker")
        worker_id = "worker-service"
        # Create background task for the worker
        loop = asyncio.get_running_loop()
        print(f"DEBUG: Creating worker task for {worker_id}")
        # Delegate worker run to bootstrap
        worker_task = loop.create_task(bootstrap.run_arq_worker(worker_id))
        print("DEBUG: Worker task created")

    yield

    # Shutdown
    logger.info("Shutting down Event Handler Service")

    if consumer:
        await consumer.stop()

    if worker_task:
        if not worker_task.done():
            worker_task.cancel()
            try:
                await worker_task
            except asyncio.CancelledError:
                pass

    logger.info("Event Handler Service stopped")
