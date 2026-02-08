"""
Dedicated Kafka Consumer Entry Point.

This module provides a standalone entry point for running the Kafka consumer
as a dedicated process, rather than as a background task inside an HTTP server.

This is the recommended approach for production deployments as it:
1. Avoids gunicorn worker timeout issues
2. Runs the consumer in the main thread where it can properly handle signals
3. Prevents event loop starvation from HTTP request handling
4. Allows independent scaling of consumers vs HTTP handlers

Usage:
    python -m keep.event_handler.consumer_main

Environment Variables:
    MESSAGING_TYPE: Must be "KAFKA" to use this entry point
    KAFKA_BOOTSTRAP_SERVERS: Kafka broker addresses
    KAFKA_TOPIC: Topic to consume from (default: keep-events)
    KAFKA_CONSUMER_GROUP: Consumer group ID (default: keep-event-handler)
    
    # OTEL Metrics (optional - push metrics to collector)
    METRIC_OTEL_ENABLED: Set to "true" to enable OTEL metrics export
    OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint (e.g., http://otel-collector:4318)
    OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: Specific metrics endpoint (overrides base)
    OTEL_METRICS_EXPORT_INTERVAL_MS: Export interval in ms (default: 10000)
"""

import asyncio
import logging
import signal
import sys

from dotenv import find_dotenv, load_dotenv

import keep.common.logging
from keep.common.core.config import config

# Load environment variables early
load_dotenv(find_dotenv())
keep.common.logging.setup_logging()
logger = logging.getLogger(__name__)


class ConsumerRunner:
    """
    Manages the lifecycle of a dedicated Kafka consumer process.
    
    This class handles:
    - Initialization of required services (DB, workflow manager, etc.)
    - Starting and stopping the Kafka consumer
    - Graceful shutdown on signals
    """
    
    def __init__(self):
        self.consumer = None
        self._shutdown_event = asyncio.Event()
        self._running = False
    
    async def initialize(self):
        """Initialize required services before starting consumer."""
        from keep.event_handler.core.bootstrap import Bootstrap
        from keep.common.core.otel_metrics import setup_otel_metrics
        
        logger.info("Initializing consumer services...")
        
        # Initialize OTEL metrics (push to collector)
        otel_enabled = setup_otel_metrics(service_name="keep-event-handler-consumer")
        if otel_enabled:
            logger.info("OTEL metrics export enabled - metrics will be pushed to collector")
        else:
            logger.info("OTEL metrics export disabled - set METRIC_OTEL_ENABLED=true to enable")
        
        bootstrap = await Bootstrap.get_instance()
        await bootstrap.run_on_starting()
        logger.info("Consumer services initialized successfully")
    
    async def start_consumer(self):
        """Start the Kafka consumer and run until shutdown."""
        messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
        
        if messaging_type != "KAFKA":
            logger.error(
                f"consumer_main.py is designed for Kafka consumers only. "
                f"MESSAGING_TYPE is '{messaging_type}'. Use Redis consumer via main.py instead."
            )
            sys.exit(1)
        
        from keep.event_handler.core.kafka_consumer import KafkaEventConsumer
        
        logger.info("Starting dedicated Kafka consumer process")
        self.consumer = KafkaEventConsumer()
        
        try:
            await self.consumer.start()
            self._running = True
            
            # Wait for shutdown signal
            logger.info("Kafka consumer running. Waiting for shutdown signal...")
            await self._shutdown_event.wait()
            
        finally:
            logger.info("Shutting down Kafka consumer...")
            if self.consumer:
                await self.consumer.stop()
            self._running = False
            logger.info("Kafka consumer shut down complete")
    
    def request_shutdown(self):
        """Request graceful shutdown of the consumer."""
        logger.info("Shutdown requested")
        self._shutdown_event.set()
    
    def is_running(self) -> bool:
        """Check if consumer is currently running."""
        return self._running


def setup_signal_handlers(runner: ConsumerRunner, loop: asyncio.AbstractEventLoop):
    """Setup signal handlers for graceful shutdown."""
    
    def signal_handler(sig):
        logger.info(f"Received signal {sig.name}, initiating shutdown...")
        loop.call_soon_threadsafe(runner.request_shutdown)
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
    
    logger.info("Signal handlers configured (SIGTERM, SIGINT)")


async def run_consumer():
    """Main async entry point for the consumer."""
    runner = ConsumerRunner()
    
    # Setup signal handlers
    loop = asyncio.get_running_loop()
    setup_signal_handlers(runner, loop)
    
    try:
        # Initialize services
        await runner.initialize()
        
        # Start consumer and run until shutdown
        await runner.start_consumer()
        
    except Exception as e:
        logger.exception(f"Consumer crashed with error: {e}")
        sys.exit(1)


def main():
    """Synchronous entry point."""
    logger.info("=" * 60)
    logger.info("Starting Keep Event Handler - Dedicated Consumer Mode")
    logger.info("=" * 60)
    
    # Check messaging type before starting
    messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
    if messaging_type != "KAFKA":
        logger.error(
            f"This entry point is for Kafka consumers only. "
            f"Current MESSAGING_TYPE: {messaging_type}"
        )
        logger.error("Set MESSAGING_TYPE=KAFKA or use the standard entry point.")
        sys.exit(1)
    
    try:
        asyncio.run(run_consumer())
    except KeyboardInterrupt:
        logger.info("Consumer interrupted by user")
    except Exception as e:
        logger.exception(f"Consumer failed: {e}")
        sys.exit(1)
    
    logger.info("Consumer process exited")


if __name__ == "__main__":
    main()
