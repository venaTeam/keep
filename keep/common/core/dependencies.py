import logging
import os

from fastapi import Request
from fastapi.datastructures import FormData
from pusher import Pusher

from keep.common.arq_pool import get_pool
from keep.common.core.config import config
from keep.common.core.messaging import (
    EventProducer,
    KafkaEventProducer,
    RedisEventProducer,
)

logger = logging.getLogger(__name__)

# Global producer instance for reuse
_kafka_producer_instance = None

# Just a fake random tenant id
SINGLE_TENANT_UUID = "keep"
SINGLE_TENANT_EMAIL = "admin@keephq"

PUSHER_ROOT_CA = config("PUSHER_ROOT_CA", default=None)

if PUSHER_ROOT_CA:
    logger.warning("Patching PUSHER root certificate")
    from pusher import requests as pusher_requests

    pusher_requests.CERT_PATH = PUSHER_ROOT_CA


async def extract_generic_body(request: Request) -> dict | bytes | FormData:
    """
    Extracts the body of the request based on the content type.

    Args:
        request (Request): The request object.

    Returns:
        dict | bytes | FormData: The body of the request.
    """
    content_type = request.headers.get("Content-Type")
    if content_type == "application/x-www-form-urlencoded":
        return await request.form()
    elif isinstance(content_type, str) and content_type.startswith(
        "multipart/form-data"
    ):
        return await request.form()
    else:
        try:
            logger.debug("Parsing body as json")
            body = await request.json()
            logger.debug("Parsed body as json")
            return body
        except Exception:
            logger.debug("Failed to parse body as json, returning raw body")
            return await request.body()


def get_pusher_client() -> Pusher | None:
    logger.debug("Getting pusher client")
    pusher_disabled = os.environ.get("PUSHER_DISABLED", "false") == "true"
    pusher_host = os.environ.get("PUSHER_HOST")
    pusher_app_id = os.environ.get("PUSHER_APP_ID")
    pusher_app_key = os.environ.get("PUSHER_APP_KEY")
    pusher_app_secret = os.environ.get("PUSHER_APP_SECRET")
    if (
        pusher_disabled
        or pusher_app_id is None
        or pusher_app_key is None
        or pusher_app_secret is None
    ):
        logger.debug("Pusher is disabled or missing environment variables")
        return None

    # TODO: defaults on open source no docker
    pusher = Pusher(
        host=pusher_host,
        port=(
            int(os.environ.get("PUSHER_PORT"))
            if os.environ.get("PUSHER_PORT")
            else None
        ),
        app_id=pusher_app_id,
        key=pusher_app_key,
        secret=pusher_app_secret,
        ssl=False if os.environ.get("PUSHER_USE_SSL", False) is False else True,
        cluster=os.environ.get("PUSHER_CLUSTER"),
    )
    logging.debug("Pusher client initialized")
    return pusher


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
