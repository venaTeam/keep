import abc
import json
import logging

from aiokafka import AIOKafkaProducer
from arq import ArqRedis

from keep.api.consts import KEEP_ARQ_QUEUE_BASIC
from keep.api.core.config import config


class EventProducer(abc.ABC):
    @abc.abstractmethod
    async def produce(self, event: dict, **kwargs):
        pass


class RedisEventProducer(EventProducer):
    def __init__(self, arq_pool: ArqRedis):
        self.arq_pool = arq_pool
        self.logger = logging.getLogger(__name__)

    async def produce(self, event: dict, **kwargs):
        trace_id = kwargs.get("trace_id")
        self.logger.info(f"Producing event to Redis ARQ: {trace_id}")
        # Extract arguments expected by the worker
        tenant_id = kwargs.get("tenant_id")
        provider_type = kwargs.get("provider_type")
        provider_id = kwargs.get("provider_id")
        fingerprint = kwargs.get("fingerprint")
        api_key_name = kwargs.get("api_key_name")
        provider_name = kwargs.get("provider_name")

        # Enqueue job matching the signature in alerts.py
        job = await self.arq_pool.enqueue_job(
            "process_event_in_worker",
            tenant_id,
            provider_type,
            provider_id,
            fingerprint,
            api_key_name,
            trace_id,
            event,
            _queue_name=KEEP_ARQ_QUEUE_BASIC,
            provider_name=provider_name,
        )
        self.logger.info(f"Successfully produced event to Redis ARQ: {trace_id}")
        return job.job_id


class KafkaEventProducer(EventProducer):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.bootstrap_servers = config(
            "KAFKA_BOOTSTRAP_SERVERS", default="localhost:9092"
        )
        self.topic = "keep-events"

        # SASL config
        self.security_protocol = config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT")
        self.sasl_mechanism = config("KAFKA_SASL_MECHANISM", default="PLAIN")
        self.sasl_plain_username = config("KAFKA_SASL_USERNAME", default=None)
        self.sasl_plain_password = config("KAFKA_SASL_PASSWORD", default=None)

        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            api_version="auto",
        )
        self._started = False

    async def _ensure_started(self):
        if not self._started:
            await self.producer.start()
            self._started = True

    async def produce(self, event: dict, **kwargs):
        trace_id = kwargs.get("trace_id")
        self.logger.info(f"Producing event to Kafka: {trace_id}")
        await self._ensure_started()

        # Enrich event with metadata that ARQ passed as args
        # We put everything in the payload for Kafka
        payload = {
            "event": event,
            "tenant_id": kwargs.get("tenant_id"),
            "provider_type": kwargs.get("provider_type"),
            "provider_id": kwargs.get("provider_id"),
            "fingerprint": kwargs.get("fingerprint"),
            "api_key_name": kwargs.get("api_key_name"),
            "trace_id": trace_id,
            "provider_name": kwargs.get("provider_name"),
        }

        try:
            # Serialize payload, handling Pydantic models (like AlertDto) and other objects
            val = json.dumps(
                payload, default=lambda o: o.dict() if hasattr(o, "dict") else str(o)
            ).encode("utf-8")
            await self.producer.send_and_wait(self.topic, val)
            self.logger.info(f"Successfully produced event to Kafka: {trace_id}")
            return "kafka-async-task"
        except Exception as e:
            self.logger.exception("Failed to produce event to Kafka")
            raise e

    async def close(self):
        if self._started:
            await self.producer.stop()
            self._started = False
