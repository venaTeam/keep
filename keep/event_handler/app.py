import asyncio
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager

from dotenv import find_dotenv, load_dotenv
from fastapi import FastAPI
from fastapi.responses import JSONResponse

import keep.api.logging
import keep.api.observability
from keep.event_handler.worker import get_arq_worker, safe_run_worker
from keep.api.consts import (
    KEEP_ARQ_QUEUE_BASIC,
    KEEP_ARQ_TASK_POOL,
    KEEP_ARQ_TASK_POOL_ALL,
    KEEP_ARQ_TASK_POOL_BASIC_PROCESSING,
)
from keep.api.core.config import config
from keep.workflowmanager.workflowmanager import WorkflowManager

# Load environment variables
load_dotenv(find_dotenv())
keep.api.logging.setup_logging()
logger = logging.getLogger(__name__)


def determine_queue_name():
    """Determine the queue name based on task pool configuration"""
    if not KEEP_ARQ_TASK_POOL:
        return KEEP_ARQ_TASK_POOL_ALL

    elif KEEP_ARQ_TASK_POOL in [
        KEEP_ARQ_TASK_POOL_ALL,
        KEEP_ARQ_TASK_POOL_BASIC_PROCESSING,
    ]:
        return KEEP_ARQ_QUEUE_BASIC
    else:
        raise ValueError(f"Invalid task pool: {KEEP_ARQ_TASK_POOL}")


async def run_arq_worker(worker_id, number_of_errors_before_restart=0):
    """Run an ARQ worker"""
    print(f"DEBUG: run_arq_worker started for {worker_id}")
    logger.info(f"Starting ARQ Worker {worker_id} (PID: {os.getpid()})")

    try:
        queue_name = determine_queue_name()
    except ValueError as e:
        logger.exception(f"Invalid task pool configuration: {e}")
        sys.exit(1)

    if not queue_name:
        logger.info("No task pools configured to run - exiting")
        sys.exit(1)

    # Apply debug patches if needed
    if config("LOG_LEVEL", default="INFO") == "DEBUG":
        logger.info("Applying ARQ debug patches")
        try:
            module_name = __name__.rsplit(".", 1)[0] if "." in __name__ else ""
            import_path = (
                f"{module_name}.arq_worker_debug_patch"
                if module_name
                else "arq_worker_debug_patch"
            )

            debug_module = __import__(
                import_path, fromlist=["apply_arq_debug_patches", "patch_process_event"]
            )
            debug_module.apply_arq_debug_patches()
            debug_module.patch_process_event()
            logger.info("ARQ debug patches applied")
        except ImportError:
            logger.warning(
                "Could not import ARQ debug patches, continuing without them"
            )

    # Start the workflow manager
    print("DEBUG: Starting Workflow Manager")
    logger.info("Starting Workflow Manager")
    wf_manager = WorkflowManager.get_instance()
    await wf_manager.start()
    print("DEBUG: Workflow Manager started")
    logger.info("Workflow Manager started")

    # Get and run the ARQ worker
    print(f"DEBUG: Getting ARQ worker for queue {queue_name}")
    worker = get_arq_worker(queue_name)
    print("DEBUG: Starting safe_run_worker")
    await safe_run_worker(
        worker, number_of_errors_before_restart=number_of_errors_before_restart
    )
    logger.info(f"ARQ Worker {worker_id} finished")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Event Handler Service")
    # Initialize DB and other resources (similar to API startup)
    from keep.api.config import on_starting
    try:
        print("DEBUG: Calling on_starting")
        # Run sync on_starting in a separate thread to avoid "loop already running" issues with Alembic/SQLAlchemy
        await asyncio.to_thread(on_starting)
        print("DEBUG: on_starting finished")
    except Exception as e:
        logger.exception("Failed to run on_starting")
        print(f"DEBUG: on_starting failed: {e}")

    messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
    consumer = None
    worker_task = None

    if messaging_type == "KAFKA":
        from keep.event_handler.messaging import KafkaEventConsumer
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
        worker_task = loop.create_task(run_arq_worker(worker_id))
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


app = FastAPI(
    title="Keep ARQ Worker",
    description="Microservice for handling background tasks and events",
    lifespan=lifespan
)

if config("KEEP_OTEL_ENABLED", default="true", cast=bool):
    keep.api.observability.setup(app)


@app.get("/health")
def health_check():
    return JSONResponse(
        content={"status": "ok"},
        status_code=200,
    )


@app.get("/")
def get_status():
    return JSONResponse(
        content="ARQ Worker Running\n",
        status_code=200,
        headers={"Content-Type": "text/plain"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
