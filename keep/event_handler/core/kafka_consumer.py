import abc
import asyncio
import json
import logging

from aiokafka import AIOKafkaConsumer

from keep.api.core.config import config
from keep.event_handler.controllers.event_controller import process_event_wrapper


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
        # Handle None vs empty string vs missing config
        self.sasl_plain_username = config("KAFKA_SASL_USERNAME", default=None)
        self.sasl_plain_password = config("KAFKA_SASL_PASSWORD", default=None)

        # SSL config
        self.ssl_cafile = config("KAFKA_SSL_CAFILE", default=None)
        self.ssl_certfile = config("KAFKA_SSL_CERTFILE", default=None)
        self.ssl_keyfile = config("KAFKA_SSL_KEYFILE", default=None)

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
            # auto_offset_reset="earliest", # or latest? Default is latest.
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            ssl_context=ssl_context,
            api_version="auto",
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
                    self.logger.debug(
                        f"Received event from Kafka: {payload.get('trace_id')}"
                    )

                    # Extract arguments matching process_event's expectation
                    event = payload.get("event")
                    tenant_id = payload.get("tenant_id")
                    provider_type = payload.get("provider_type")
                    provider_id = payload.get("provider_id")
                    fingerprint = payload.get("fingerprint")
                    api_key_name = payload.get("api_key_name")
                    trace_id = payload.get("trace_id")
                    provider_name = payload.get("provider_name")

                    # Run logic via controller
                    # We pass an empty dict as ctx since we are not in ARQ
                    await process_event_wrapper(
                        ctx={}, 
                        tenant_id=tenant_id,
                        provider_type=provider_type,
                        provider_id=provider_id,
                        fingerprint=fingerprint,
                        api_key_name=api_key_name,
                        trace_id=trace_id,
                        event=event,
                        provider_name=provider_name,
                    )

                except Exception as e:
                    self.logger.exception(f"Error processing Kafka message: {e}")

        except Exception as e:
            self.logger.exception(f"Kafka consumer loop crashed: {e}")
