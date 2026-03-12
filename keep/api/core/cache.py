"""
Redis cache module for Keep API.

Provides a thin caching layer over Redis. All values are stored as JSON objects
using orjson for fast serialization. Designed for ~4000 alerts/min scale.

Graceful fallback: if Redis is unavailable, every operation returns None / no-ops
so the API continues to serve from the database.
"""

import hashlib
import logging
from typing import Any, Optional

import orjson

from keep.common.core.config import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton Redis client
# ---------------------------------------------------------------------------
_redis_client = None
_redis_init_attempted = False

CACHE_KEY_PREFIX = "keep:cache"


def get_redis_client():
    """
    Return a singleton redis.Redis client (sync).
    Returns None if REDIS is not enabled or connection fails.
    """
    global _redis_client, _redis_init_attempted

    if _redis_init_attempted:
        return _redis_client

    _redis_init_attempted = True

    redis_enabled = config("REDIS_CACHE", default="true") == "true"
    if not redis_enabled:
        logger.info("Redis cache disabled (REDIS_CACHE != 'true')")
        return None

    try:
        import redis as redis_lib

        host = config("REDIS_HOST", default="localhost")
        port = config("REDIS_PORT", cast=int, default=6379)
        password = config("REDIS_PASSWORD", default=None)
        username = config("REDIS_USERNAME", default=None)

        _redis_client = redis_lib.Redis(
            host=host,
            port=port,
            username=username,
            password=password,
            decode_responses=False,  # we handle bytes via orjson
            socket_connect_timeout=3,
            socket_timeout=2,
            retry_on_timeout=True,
        )
        # Quick connectivity check
        _redis_client.ping()
        logger.info(
            "Redis cache client connected",
            extra={"host": host, "port": port},
        )
    except Exception as e:
        logger.warning(
            "Redis cache unavailable, falling back to DB",
            extra={"error": str(e)},
        )
        _redis_client = None

    return _redis_client


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _default_serializer(obj):
    """Fallback serializer for types orjson can't handle natively."""
    import datetime
    import enum
    import uuid

    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (uuid.UUID,)):
        return str(obj)
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if hasattr(obj, "dict"):
        return obj.dict()
    return str(obj)


def build_cache_key(prefix: str, tenant_id: str, **params) -> str:
    """
    Build a deterministic cache key.

    Example: keep:cache:alerts:tenant123:ab3f…
    """
    raw = orjson.dumps(params, option=orjson.OPT_SORT_KEYS, default=_default_serializer)
    param_hash = hashlib.md5(raw).hexdigest()[:12]
    logger.info(f"Generated cache key {CACHE_KEY_PREFIX}:{prefix}:{tenant_id}:{param_hash} for raw payload: {raw.decode('utf-8')}")
    return f"{CACHE_KEY_PREFIX}:{prefix}:{tenant_id}:{param_hash}"


# ---------------------------------------------------------------------------
# Core cache operations
# ---------------------------------------------------------------------------

def get_cached(key: str) -> Optional[Any]:
    """
    GET from Redis and deserialise with orjson.
    Returns None on miss or error.
    """
    client = get_redis_client()
    if client is None:
        return None

    try:
        raw = client.get(key)
        if raw is None:
            logger.debug("Cache MISS", extra={"key": key})
            return None
        logger.info("Cache HIT", extra={"key": key})
        return orjson.loads(raw)
    except Exception as e:
        logger.warning("Cache GET error", extra={"key": key, "error": str(e)})
        return None


def get_cached_raw(key: str) -> Optional[bytes]:
    """
    GET from Redis and return raw bytes (already JSON).
    Use this when you want to return a Response directly without
    deserializing and re-serializing.
    Returns None on miss or error.
    """
    client = get_redis_client()
    if client is None:
        return None

    try:
        raw = client.get(key)
        if raw is None:
            logger.debug("Cache MISS", extra={"key": key})
            return None
        logger.info("Cache HIT (raw)", extra={"key": key, "bytes": len(raw)})
        return raw
    except Exception as e:
        logger.warning("Cache GET error", extra={"key": key, "error": str(e)})
        return None


def set_cached(key: str, data: Any, ttl: int) -> None:
    """
    Serialise *data* with orjson and SETEX into Redis.
    *data* must already be JSON-serialisable (dicts, lists, primitives).
    """
    client = get_redis_client()
    if client is None:
        return

    try:
        raw = orjson.dumps(data, default=_default_serializer)
        client.setex(key, ttl, raw)
        logger.debug("Cache SET", extra={"key": key, "ttl": ttl, "bytes": len(raw)})
    except Exception as e:
        logger.warning("Cache SET error", extra={"key": key, "error": str(e)})


def set_cached_raw(key: str, raw_bytes: bytes, ttl: int) -> None:
    """
    Store pre-serialized JSON bytes directly into Redis.
    Use when you already have the final JSON bytes (e.g. from jsonable_encoder + json.dumps).
    """
    client = get_redis_client()
    if client is None:
        return

    try:
        client.setex(key, ttl, raw_bytes)
        logger.debug("Cache SET (raw)", extra={"key": key, "ttl": ttl, "bytes": len(raw_bytes)})
    except Exception as e:
        logger.warning("Cache SET error", extra={"key": key, "error": str(e)})


def invalidate(prefix: str, tenant_id: str) -> None:
    """
    Delete all keys matching  keep:cache:{prefix}:{tenant_id}:*
    Uses SCAN to avoid blocking Redis at scale.
    """
    client = get_redis_client()
    if client is None:
        return

    pattern = f"{CACHE_KEY_PREFIX}:{prefix}:{tenant_id}:*"
    try:
        cursor = 0
        total = 0
        while True:
            cursor, keys = client.scan(cursor, match=pattern, count=200)
            if keys:
                client.delete(*keys)
                total += len(keys)
            if cursor == 0:
                break
        if total:
            logger.info(
                "Cache invalidated",
                extra={"pattern": pattern, "keys_deleted": total},
            )
    except Exception as e:
        logger.warning("Cache invalidation error", extra={"pattern": pattern, "error": str(e)})
