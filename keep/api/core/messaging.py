import abc
import json
import logging

from aiokafka import AIOKafkaProducer
from arq import ArqRedis

from keep.common.consts import KEEP_ARQ_QUEUE_BASIC
from keep.common.core.config import config


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
        self.dlq_topic = config("KAFKA_DLQ_TOPIC", default="keep-events-dlq")
        self.max_retries = int(config("KAFKA_MAX_RETRIES", default="3"))

        # SASL config
        self.security_protocol = config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT")
        self.sasl_mechanism = config("KAFKA_SASL_MECHANISM", default="PLAIN")
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
            # If user didn't provide CA file, we rely on system CAs or strict verification off?
            # Typically for self-signed or internal CAs, user provides cafile.
            # We don't force check_hostname=False unless requested, but standard is often strict.
            if not self.ssl_cafile and not self.ssl_certfile:
                # Fallback or specific logic if needed. For now standard default context.
                pass

        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            ssl_context=ssl_context,
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
            
            # Simple retry loop
            for attempt in range(self.max_retries):
                try:
                    await self.producer.send_and_wait(self.topic, val)
                    self.logger.info(f"Successfully produced event to Kafka topic {self.topic}: {trace_id}")
                    return "kafka-async-task"
                except Exception as e:
                    self.logger.warning(f"Failed to produce to Kafka main topic {self.topic} (attempt {attempt+1}/{self.max_retries}): {e}")
            
            # If we exit the loop, all attempts failed. Send to DLQ.
            self.logger.warning(f"All {self.max_retries} attempts to main topic {self.topic} failed. Sending to DLQ {self.dlq_topic}")
            try:
                await self.producer.send_and_wait(self.dlq_topic, val)
                self.logger.info(f"Successfully produced event to DLQ topic {self.dlq_topic}: {trace_id}")
                return "kafka-async-task-dlq"
            except Exception as dlq_e:
                self.logger.exception(f"Failed to produce event to Kafka DLQ topic {self.dlq_topic}: {trace_id}")
                raise dlq_e

        except Exception as e:
            self.logger.exception("Failed to build or produce event to Kafka or DLQ")
            raise e

    async def close(self):
        if self._started:
            await self.producer.stop()
            self._started = False
