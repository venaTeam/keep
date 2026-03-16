"""
Redis Alert Store — Redis-first alert data layer.

Uses Redis Hashes for individual alert data and Sorted Sets for
time-ordered indexing, so the API Gateway can serve alerts instantly
without querying the database.

Data structures:
  - Hash:  keep:alert:data:{tenant_id}:{fingerprint}  → alert fields + full JSON
  - ZSet:  keep:alerts:latest:{tenant_id}              → score=timestamp, member=fingerprint
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from keep.api.core.cache import get_redis_client

logger = logging.getLogger(__name__)

# Key templates
_ALERT_HASH_KEY = "keep:alert:data:{tenant_id}:{fingerprint}"
_ALERTS_ZSET_KEY = "keep:alerts:latest:{tenant_id}"

# Limits
_MAX_SORTED_SET_SIZE = 10_000
_ALERT_HASH_TTL = 48 * 60 * 60  # 48 hours


def _alert_hash_key(tenant_id: str, fingerprint: str) -> str:
    return _ALERT_HASH_KEY.format(tenant_id=tenant_id, fingerprint=fingerprint)


def _alerts_zset_key(tenant_id: str) -> str:
    return _ALERTS_ZSET_KEY.format(tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Write operations (called by Event Handler after DB save)
# ---------------------------------------------------------------------------

def write_alert_to_redis(tenant_id: str, alert_dto) -> bool:
    """
    Write a single alert to Redis Hash + Sorted Set.

    Args:
        tenant_id: Tenant identifier
        alert_dto: AlertDto instance (has .dict() / .fingerprint / .lastReceived)

    Returns:
        True if written successfully, False otherwise.
    """
    client = get_redis_client()
    if client is None:
        return False

    try:
        fingerprint = alert_dto.fingerprint
        hash_key = _alert_hash_key(tenant_id, fingerprint)
        zset_key = _alerts_zset_key(tenant_id)

        # Serialize the full alert to JSON for the "json" field
        from fastapi.encoders import jsonable_encoder
        alert_dict = jsonable_encoder(alert_dto)
        alert_json = json.dumps(alert_dict)

        # Extract key fields for fast lookups without deserializing the full JSON
        hash_fields = {
            "fingerprint": fingerprint,
            "status": str(getattr(alert_dto, "status", "")),
            "severity": str(getattr(alert_dto, "severity", "")),
            "source": json.dumps(getattr(alert_dto, "source", [])),
            "name": str(getattr(alert_dto, "name", "")),
            "lastReceived": str(getattr(alert_dto, "lastReceived", "")),
            "providerId": str(getattr(alert_dto, "providerId", "")),
            "providerType": str(getattr(alert_dto, "providerType", "")),
            "json": alert_json,
        }

        # Determine the score (timestamp) for the sorted set
        last_received = getattr(alert_dto, "lastReceived", None)
        if last_received:
            if hasattr(last_received, "timestamp"):
                score = last_received.timestamp()
            else:
                score = time.time()
        else:
            score = time.time()

        # Use a pipeline for atomicity and performance
        pipe = client.pipeline(transaction=False)
        pipe.hset(hash_key, mapping=hash_fields)
        pipe.expire(hash_key, _ALERT_HASH_TTL)
        pipe.zadd(zset_key, {fingerprint: score})
        pipe.execute()

        return True
    except Exception:
        logger.exception(
            "Failed to write alert to Redis",
            extra={"tenant_id": tenant_id, "fingerprint": getattr(alert_dto, "fingerprint", "unknown")},
        )
        return False


def write_alerts_batch(tenant_id: str, alert_dtos: list) -> int:
    """
    Write a batch of alerts to Redis using a pipeline.
    Returns the number of alerts successfully written.
    """
    client = get_redis_client()
    if client is None:
        return 0

    try:
        from fastapi.encoders import jsonable_encoder

        zset_key = _alerts_zset_key(tenant_id)
        pipe = client.pipeline(transaction=False)
        count = 0

        for alert_dto in alert_dtos:
            try:
                fingerprint = alert_dto.fingerprint
                hash_key = _alert_hash_key(tenant_id, fingerprint)

                alert_dict = jsonable_encoder(alert_dto)
                alert_json = json.dumps(alert_dict)

                hash_fields = {
                    "fingerprint": fingerprint,
                    "status": str(getattr(alert_dto, "status", "")),
                    "severity": str(getattr(alert_dto, "severity", "")),
                    "source": json.dumps(getattr(alert_dto, "source", [])),
                    "name": str(getattr(alert_dto, "name", "")),
                    "lastReceived": str(getattr(alert_dto, "lastReceived", "")),
                    "providerId": str(getattr(alert_dto, "providerId", "")),
                    "providerType": str(getattr(alert_dto, "providerType", "")),
                    "json": alert_json,
                }

                last_received = getattr(alert_dto, "lastReceived", None)
                if last_received and hasattr(last_received, "timestamp"):
                    score = last_received.timestamp()
                else:
                    score = time.time()

                pipe.hset(hash_key, mapping=hash_fields)
                pipe.expire(hash_key, _ALERT_HASH_TTL)
                pipe.zadd(zset_key, {fingerprint: score})
                count += 1
            except Exception:
                logger.exception(
                    "Failed to serialize alert for Redis batch",
                    extra={"fingerprint": getattr(alert_dto, "fingerprint", "unknown")},
                )

        # Trim the sorted set to keep only the most recent entries
        pipe.zremrangebyrank(zset_key, 0, -(_MAX_SORTED_SET_SIZE + 1))

        pipe.execute()
        logger.debug(
            "Wrote alerts batch to Redis",
            extra={"tenant_id": tenant_id, "count": count},
        )
        return count
    except Exception:
        logger.exception("Failed to write alerts batch to Redis")
        return 0


# ---------------------------------------------------------------------------
# Read operations (called by API Gateway)
# ---------------------------------------------------------------------------

def get_alerts_from_redis(
    tenant_id: str,
    limit: int = 25,
    offset: int = 0,
) -> Optional[Tuple[List[Dict[str, Any]], int]]:
    """
    Read alerts from Redis Sorted Set + Hashes.

    Returns:
        Tuple of (list of alert dicts, total count) or None if Redis unavailable.
    """
    client = get_redis_client()
    if client is None:
        return None

    try:
        zset_key = _alerts_zset_key(tenant_id)

        # Get total count
        total_count = client.zcard(zset_key)
        if total_count == 0:
            return None  # No data in Redis, fall back to DB

        # Get fingerprints for the requested page (newest first)
        start = offset
        end = offset + limit - 1
        fingerprints = client.zrevrange(zset_key, start, end)

        if not fingerprints:
            return ([], total_count)

        # Fetch full alert JSON for each fingerprint using pipeline
        pipe = client.pipeline(transaction=False)
        for fp in fingerprints:
            fp_str = fp.decode("utf-8") if isinstance(fp, bytes) else fp
            hash_key = _alert_hash_key(tenant_id, fp_str)
            pipe.hget(hash_key, "json")

        results = pipe.execute()

        alerts = []
        for raw in results:
            if raw is not None:
                try:
                    alert_dict = json.loads(raw)
                    alerts.append(alert_dict)
                except (json.JSONDecodeError, TypeError):
                    continue

        return (alerts, total_count)
    except Exception:
        logger.exception("Failed to read alerts from Redis")
        return None


def get_alert_by_fingerprint(
    tenant_id: str, fingerprint: str
) -> Optional[Dict[str, Any]]:
    """Read a single alert from Redis by fingerprint."""
    client = get_redis_client()
    if client is None:
        return None

    try:
        hash_key = _alert_hash_key(tenant_id, fingerprint)
        raw = client.hget(hash_key, "json")
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        logger.exception("Failed to read alert from Redis")
        return None


def get_latest_alert_fingerprints(
    tenant_id: str, count: int = 50
) -> List[str]:
    """Get the most recent N alert fingerprints from the sorted set."""
    client = get_redis_client()
    if client is None:
        return []

    try:
        zset_key = _alerts_zset_key(tenant_id)
        fingerprints = client.zrevrange(zset_key, 0, count - 1)
        return [fp.decode("utf-8") if isinstance(fp, bytes) else fp for fp in fingerprints]
    except Exception:
        logger.exception("Failed to get latest fingerprints from Redis")
        return []


def get_alert_count(tenant_id: str) -> Optional[int]:
    """Get the total number of alerts in the sorted set."""
    client = get_redis_client()
    if client is None:
        return None

    try:
        return client.zcard(_alerts_zset_key(tenant_id))
    except Exception:
        logger.exception("Failed to get alert count from Redis")
        return None


# ---------------------------------------------------------------------------
# Hydration (one-time load of existing DB alerts into Redis)
# ---------------------------------------------------------------------------

def write_alert_dicts_batch(tenant_id: str, alert_dicts: list) -> int:
    """
    Write already-serialized alert dicts to Redis (from DB fallback path).
    Each dict should have at least 'fingerprint' and 'lastReceived' fields.
    Returns count of alerts written.
    """
    client = get_redis_client()
    if client is None:
        return 0

    try:
        zset_key = _alerts_zset_key(tenant_id)
        pipe = client.pipeline(transaction=False)
        count = 0

        for alert_dict in alert_dicts:
            try:
                fingerprint = alert_dict.get("fingerprint")
                if not fingerprint:
                    continue

                hash_key = _alert_hash_key(tenant_id, fingerprint)
                alert_json = json.dumps(alert_dict)

                hash_fields = {
                    "fingerprint": fingerprint,
                    "status": str(alert_dict.get("status", "")),
                    "severity": str(alert_dict.get("severity", "")),
                    "source": json.dumps(alert_dict.get("source", [])),
                    "name": str(alert_dict.get("name", "")),
                    "lastReceived": str(alert_dict.get("lastReceived", "")),
                    "providerId": str(alert_dict.get("providerId", "")),
                    "providerType": str(alert_dict.get("providerType", "")),
                    "json": alert_json,
                }

                # Parse timestamp for sorted set score
                last_received = alert_dict.get("lastReceived")
                try:
                    from datetime import datetime
                    if isinstance(last_received, str) and last_received:
                        dt = datetime.fromisoformat(last_received.replace("Z", "+00:00"))
                        score = dt.timestamp()
                    else:
                        score = time.time()
                except Exception:
                    score = time.time()

                pipe.hset(hash_key, mapping=hash_fields)
                pipe.expire(hash_key, _ALERT_HASH_TTL)
                pipe.zadd(zset_key, {fingerprint: score})
                count += 1

                # Execute in batches of 500 to avoid huge pipelines
                if count % 500 == 0:
                    pipe.execute()
                    pipe = client.pipeline(transaction=False)
            except Exception:
                continue

        # Trim sorted set and execute remaining
        pipe.zremrangebyrank(zset_key, 0, -(_MAX_SORTED_SET_SIZE + 1))
        pipe.execute()

        logger.info(
            "Wrote alert dicts batch to Redis",
            extra={"tenant_id": tenant_id, "count": count},
        )
        return count
    except Exception:
        logger.exception("Failed to write alert dicts batch to Redis")
        return 0


def hydrate_redis_from_db(tenant_id: str) -> int:
    """
    One-time hydration: load all existing alerts from DB into Redis.
    Called on API startup so the Redis store is immediately warm.
    Returns the number of alerts hydrated.
    """
    client = get_redis_client()
    if client is None:
        logger.info("Redis not available, skipping hydration")
        return 0

    # Check if already hydrated
    zset_key = _alerts_zset_key(tenant_id)
    existing = client.zcard(zset_key)
    if existing > 0:
        logger.info(
            "Redis already has alerts, skipping hydration",
            extra={"tenant_id": tenant_id, "count": existing},
        )
        return existing

    logger.info("Hydrating Redis with existing DB alerts", extra={"tenant_id": tenant_id})

    try:
        from keep.common.models.query import QueryDto
        from keep.common.core.alerts import query_last_alerts
        from keep.common.core.db import enrich_alerts_with_incidents
        from keep.common.utils.enrichment_helpers import convert_db_alerts_to_dto_alerts

        # Fetch a large batch from DB (up to 10K most recent)
        query = QueryDto(limit=_MAX_SORTED_SET_SIZE, offset=0)
        db_alerts, total_count = query_last_alerts(tenant_id=tenant_id, query=query)
        db_alerts = enrich_alerts_with_incidents(tenant_id, db_alerts)
        enriched = convert_db_alerts_to_dto_alerts(db_alerts, with_incidents=True)

        count = write_alerts_batch(tenant_id, enriched)
        logger.info(
            "Redis hydration complete",
            extra={"tenant_id": tenant_id, "hydrated": count, "db_total": total_count},
        )
        return count
    except Exception:
        logger.exception("Failed to hydrate Redis from DB")
        return 0
