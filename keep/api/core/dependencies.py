import logging

from keep.api.core.messaging import (
    EventProducer,
    KafkaEventProducer,
    RedisEventProducer,
)
from keep.common.arq_pool import get_pool
from keep.common.core.config import config

logger = logging.getLogger(__name__)

# Global producer instance for reuse
_kafka_producer_instance = None


async def get_event_producer() -> EventProducer:
    messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()

    if messaging_type == "REDIS":
        arq_pool = await get_pool()
        return RedisEventProducer(arq_pool)

    elif messaging_type == "KAFKA":
        global _kafka_producer_instance
        if _kafka_producer_instance is None:
            _kafka_producer_instance = KafkaEventProducer()
        return _kafka_producer_instance

    else:
        logger.warning(f"Unknown MESSAGING_TYPE: {messaging_type}, defaulting to REDIS")
        arq_pool = await get_pool()
        return RedisEventProducer(arq_pool)
