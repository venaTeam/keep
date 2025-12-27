import abc
import asyncio
import json
import logging
from typing import Optional

from aiokafka import AIOKafkaConsumer

from keep.api.core.config import config
from keep.api.tasks.process_event_task import process_event

class EventConsumer(abc.ABC):
    @abc.abstractmethod
    async def start(self):
        pass

    @abc.abstractmethod
    async def stop(self):
        pass


class KafkaEventConsumer(EventConsumer):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.bootstrap_servers = config("KAFKA_BOOTSTRAP_SERVERS", default="localhost:9092")
        self.topic = "keep-events"
        self.group_id = "keep-event-handler"
        
        # SASL config
        self.security_protocol = config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT")
        self.sasl_mechanism = config("KAFKA_SASL_MECHANISM", default="PLAIN")
        # Handle None vs empty string vs missing config
        self.sasl_plain_username = config("KAFKA_SASL_USERNAME", default=None)
        self.sasl_plain_password = config("KAFKA_SASL_PASSWORD", default=None)

        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            # auto_offset_reset="earliest", # or latest? Default is latest.
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            api_version="auto"
        )
        self._running = False
        self._task = None

    async def start(self):
        if self._running:
            return
        
        self.logger.info(f"Starting Kafka Consumer on topic {self.topic}")
        await self.consumer.start()
        self._running = True
        
        # Create a background task to consume messages
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._consume_loop())

    async def stop(self):
        if not self._running:
            return

        self.logger.info("Stopping Kafka Consumer")
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        await self.consumer.stop()
        self.logger.info("Kafka Consumer stopped")

    async def _consume_loop(self):
        try:
            async for msg in self.consumer:
                if not self._running:
                    break
                
                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                    self.logger.info(f"Received event from Kafka: {payload.get('trace_id')}")
                    
                    # Extract arguments matching process_event's expectation
                    event = payload.get("event")
                    tenant_id = payload.get("tenant_id")
                    provider_type = payload.get("provider_type")
                    provider_id = payload.get("provider_id")
                    fingerprint = payload.get("fingerprint")
                    api_key_name = payload.get("api_key_name")
                    trace_id = payload.get("trace_id")
                    provider_name = payload.get("provider_name")
                    
                    self.logger.info(f"Processing event in Kafka Consumer: {trace_id}")
                    # Run logic in loop/thread since process_event is sync
                    # We pass an empty dict as ctx since we are not in ARQ
                    await asyncio.to_thread(
                        process_event,
                        {}, # ctx
                        tenant_id,
                        provider_type,
                        provider_id,
                        fingerprint,
                        api_key_name,
                        trace_id,
                        event,
                        provider_name=provider_name
                    )
                    self.logger.info(f"Finished processing event: {trace_id}")

                except Exception as e:
                    self.logger.exception(f"Error processing Kafka message: {e}")

        except Exception as e:
            self.logger.exception(f"Kafka consumer loop crashed: {e}")
