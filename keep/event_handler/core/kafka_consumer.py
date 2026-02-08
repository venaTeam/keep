import abc
import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Optional

from aiokafka import AIOKafkaConsumer

from keep.common.consts import MAX_PROCESSING_RETRIES
from keep.common.core.config import config
from keep.event_handler.controllers.event_controller import process_event_wrapper
from keep.event_handler.models.event_dto import EventDTO
from keep.event_handler.api.routes.v1.metrics import (
    MESSAGES_PROCESSED,
    MESSAGES_PROCESSING_TIME,
    CONSUMER_RUNNING,
)
from keep.common.core.otel_metrics import (
    record_event_in,
    record_event_processed,
    record_event_error,
    set_consumer_running,
)


class EventConsumer(abc.ABC):
    @abc.abstractmethod
    async def start(self):
        pass

    @abc.abstractmethod
    async def stop(self):
        pass

    @abc.abstractmethod
    def get_health_status(self) -> dict:
        """Return health status for monitoring."""
        pass


class KafkaEventConsumer(EventConsumer):
    """
    Async Kafka consumer using aiokafka.
    
    Key configuration options (via environment variables):
    - KAFKA_BOOTSTRAP_SERVERS: Broker addresses (default: localhost:9092)
    - KAFKA_TOPIC: Topic to consume (default: keep-events)
    - KAFKA_CONSUMER_GROUP: Consumer group ID (default: keep-event-handler)
    - KAFKA_MAX_POLL_INTERVAL_MS: Max time between polls (default: 600000 = 10 min)
    - KAFKA_SESSION_TIMEOUT_MS: Session timeout (default: 60000 = 1 min)
    - KAFKA_HEARTBEAT_INTERVAL_MS: Heartbeat frequency (default: 3000 = 3 sec)
    - KAFKA_MAX_POLL_RECORDS: Max records per poll (default: 1)
    
    The default values are tuned for long-running message processing scenarios
    to prevent rebalance timeouts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Parse bootstrap servers (can be JSON array or comma-separated string)
        bootstrap_servers = config(
            "KAFKA_BOOTSTRAP_SERVERS", default="localhost:9092"
        )
        try:
            self.bootstrap_servers = json.loads(bootstrap_servers)
            if not isinstance(self.bootstrap_servers, list):
                self.bootstrap_servers = str(self.bootstrap_servers).split(",")
        except json.JSONDecodeError:
            self.bootstrap_servers = bootstrap_servers.split(",")
        
        self.topic = config("KAFKA_TOPIC", default="keep-events")
        self.group_id = config("KAFKA_CONSUMER_GROUP", default="keep-event-handler")

        # SASL config
        self.security_protocol = config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT")
        self.sasl_mechanism = config("KAFKA_SASL_MECHANISM", default="PLAIN")
        self.sasl_plain_username = config("KAFKA_SASL_USERNAME", default=None)
        self.sasl_plain_password = config("KAFKA_SASL_PASSWORD", default=None)

        # SSL config
        self.ssl_cafile = config("KAFKA_SSL_CAFILE", default=None)
        self.ssl_certfile = config("KAFKA_SSL_CERTFILE", default=None)
        self.ssl_keyfile = config("KAFKA_SSL_KEYFILE", default=None)

        # Timeout configuration - tuned for long-running processing
        # These values prevent max_poll_interval_ms errors during long processing
        self.max_poll_interval_ms = int(
            config("KAFKA_MAX_POLL_INTERVAL_MS", default=600000)  # 10 minutes
        )
        self.session_timeout_ms = int(
            config("KAFKA_SESSION_TIMEOUT_MS", default=60000)  # 1 minute
        )
        self.heartbeat_interval_ms = int(
            config("KAFKA_HEARTBEAT_INTERVAL_MS", default=3000)  # 3 seconds
        )
        self.max_poll_records = int(
            config("KAFKA_MAX_POLL_RECORDS", default=1)  # Process one at a time
        )

        self.logger.info(
            "Kafka consumer configuration",
            extra={
                "bootstrap_servers": self.bootstrap_servers,
                "topic": self.topic,
                "group_id": self.group_id,
                "max_poll_interval_ms": self.max_poll_interval_ms,
                "session_timeout_ms": self.session_timeout_ms,
                "heartbeat_interval_ms": self.heartbeat_interval_ms,
                "max_poll_records": self.max_poll_records,
                "security_protocol": self.security_protocol,
            }
        )

        ssl_context = None
        if self.security_protocol in ["SSL", "SASL_SSL"]:
            import ssl
            ssl_context = ssl.create_default_context(cafile=self.ssl_cafile)
            if self.ssl_certfile and self.ssl_keyfile:
                ssl_context.load_cert_chain(
                    certfile=self.ssl_certfile, keyfile=self.ssl_keyfile
                )

        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            enable_auto_commit=False,
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            ssl_context=ssl_context,
            api_version="auto",
            # Timeout configuration to prevent rebalance during long processing
            max_poll_interval_ms=self.max_poll_interval_ms,
            session_timeout_ms=self.session_timeout_ms,
            heartbeat_interval_ms=self.heartbeat_interval_ms,
            max_poll_records=self.max_poll_records,
        )
        
        self._running = False
        self._task: Optional[asyncio.Task] = None
        
        # Health monitoring state
        self._last_message_time: Optional[datetime] = None
        self._messages_processed = 0
        self._messages_failed = 0
        self._last_error: Optional[str] = None
        self._last_processing_duration_ms: Optional[float] = None
        self._started_at: Optional[datetime] = None

    async def start(self):
        """Start the Kafka consumer."""
        if self._running:
            return

        self.logger.info(f"Starting Kafka Consumer on topic {self.topic}")
        await self.consumer.start()
        self._running = True
        self._started_at = datetime.utcnow()
        CONSUMER_RUNNING.set(1)
        set_consumer_running(True)  # OTEL gauge

        # Create a background task to consume messages
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._consume_loop())
        self.logger.info("Kafka Consumer started successfully")

    async def stop(self):
        """Stop the Kafka consumer gracefully."""
        if not self._running:
            return

        self.logger.info("Stopping Kafka Consumer")
        self._running = False
        CONSUMER_RUNNING.set(0)
        set_consumer_running(False)  # OTEL gauge
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        await self.consumer.stop()
        self.logger.info(
            "Kafka Consumer stopped",
            extra={
                "messages_processed": self._messages_processed,
                "messages_failed": self._messages_failed,
            }
        )

    def get_health_status(self) -> dict:
        """
        Return health status for monitoring and health checks.
        
        Can be used by:
        - Kubernetes liveness/readiness probes
        - Monitoring dashboards
        - Alerting systems
        """
        return {
            "running": self._running,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "last_message_time": self._last_message_time.isoformat() if self._last_message_time else None,
            "messages_processed": self._messages_processed,
            "messages_failed": self._messages_failed,
            "last_error": self._last_error,
            "last_processing_duration_ms": self._last_processing_duration_ms,
            "consumer_config": {
                "topic": self.topic,
                "group_id": self.group_id,
                "max_poll_interval_ms": self.max_poll_interval_ms,
            }
        }

    async def _consume_loop(self):
        """
        Main consume loop.
        
        Key improvements for stability:
        1. Cooperative yields (asyncio.sleep(0)) to prevent event loop starvation
        2. Detailed logging and metrics for monitoring
        3. Processing time tracking to detect slow messages
        """
        self.logger.info("Starting consume loop")
        
        try:
            async for msg in self.consumer:
                if not self._running:
                    self.logger.info("Consumer stopped, exiting loop")
                    break

                # Cooperative yield - allows other async tasks (like heartbeats) to run
                await asyncio.sleep(0)
                
                trace_id = None
                processing_start = time.time()
                
                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                    trace_id = payload.get("trace_id", "unknown")
                    
                    self.logger.info(
                        "Received event from Kafka",
                        extra={
                            "trace_id": trace_id,
                            "partition": msg.partition,
                            "offset": msg.offset,
                        }
                    )
                    
                    # Record event received (OTEL - pushed to collector if enabled)
                    record_event_in()

                    # Construct DTO
                    event_dto = EventDTO(
                        tenant_id=payload.get("tenant_id"),
                        trace_id=trace_id,
                        event=payload.get("event"),
                        provider_type=payload.get("provider_type"),
                        provider_id=payload.get("provider_id"),
                        fingerprint=payload.get("fingerprint"),
                        api_key_name=payload.get("api_key_name"),
                        provider_name=payload.get("provider_name"),
                    )

                    # Process with retries
                    for attempt in range(MAX_PROCESSING_RETRIES):
                        try:
                            # Cooperative yield before each processing attempt
                            # This allows heartbeats to be sent even during long processing
                            await asyncio.sleep(0)
                            
                            await process_event_wrapper(
                                ctx={},
                                event_dto=event_dto,
                            )
                            # Success - break retry loop
                            break
                            
                        except Exception as e:
                            self.logger.warning(
                                "Error processing Kafka message",
                                extra={
                                    "trace_id": trace_id,
                                    "attempt": attempt + 1,
                                    "max_attempts": MAX_PROCESSING_RETRIES,
                                    "error": str(e),
                                }
                            )
                            if attempt == MAX_PROCESSING_RETRIES - 1:
                                # Last attempt failed
                                raise e
                            # Wait before retry (this also yields control)
                            await asyncio.sleep(1)

                    # Commit offset after successful processing
                    await self.consumer.commit()
                    
                    # Update internal metrics
                    processing_duration_ms = (time.time() - processing_start) * 1000
                    processing_duration_sec = processing_duration_ms / 1000
                    self._messages_processed += 1
                    self._last_message_time = datetime.utcnow()
                    self._last_processing_duration_ms = processing_duration_ms
                    
                    # Record Prometheus metrics
                    MESSAGES_PROCESSED.labels(status="success").inc()
                    MESSAGES_PROCESSING_TIME.observe(processing_duration_sec)
                    
                    # Record OTEL Keep metrics (pushed to collector if enabled)
                    record_event_processed()
                    
                    self.logger.info(
                        "Successfully processed and committed message",
                        extra={
                            "trace_id": trace_id,
                            "processing_duration_ms": round(processing_duration_ms, 2),
                            "total_processed": self._messages_processed,
                        }
                    )
                    
                    # Warn if processing took a long time
                    if processing_duration_ms > 30000:  # 30 seconds
                        self.logger.warning(
                            "Slow message processing detected",
                            extra={
                                "trace_id": trace_id,
                                "processing_duration_ms": round(processing_duration_ms, 2),
                                "threshold_ms": 30000,
                            }
                        )

                except Exception as e:
                    # Critical: Do NOT commit. Log exception.
                    processing_duration_ms = (time.time() - processing_start) * 1000
                    processing_duration_sec = processing_duration_ms / 1000
                    self._messages_failed += 1
                    self._last_error = str(e)
                    
                    # Record Prometheus failure metrics
                    MESSAGES_PROCESSED.labels(status="failed").inc()
                    MESSAGES_PROCESSING_TIME.observe(processing_duration_sec)
                    
                    # Record OTEL Keep failure metrics (pushed to collector if enabled)
                    record_event_error()
                    
                    self.logger.exception(
                        "Error processing Kafka message - NOT committing",
                        extra={
                            "trace_id": trace_id,
                            "processing_duration_ms": round(processing_duration_ms, 2),
                            "total_failed": self._messages_failed,
                            "error": str(e),
                        }
                    )
                    
                    # CRITICAL: Crash the loop so the pod restarts
                    # This prevents silent message loss
                    raise e

        except asyncio.CancelledError:
            self.logger.info("Consume loop cancelled")
            raise
            
        except Exception as e:
            self.logger.exception(
                "Kafka consumer loop crashed",
                extra={
                    "error": str(e),
                    "messages_processed": self._messages_processed,
                    "messages_failed": self._messages_failed,
                }
            )
            self._running = False
            self._last_error = str(e)
            raise e
