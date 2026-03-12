"""
Server-Sent Events (SSE) broadcaster for real-time notifications.

This module provides an in-memory SSE broadcaster that maintains per-tenant
connection queues and broadcasts events to all connected clients.
"""

import asyncio
import json
import logging
from typing import Any, AsyncGenerator, Dict, List

logger = logging.getLogger(__name__)


class SSEBroadcaster:
    """
    In-memory SSE broadcaster that manages connections per tenant.
    
    Each tenant can have multiple connections (browser tabs, etc.),
    and events are broadcast to all connections for that tenant.
    """
    
    def __init__(self):
        self._connections: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
    
    async def subscribe(self, tenant_id: str) -> AsyncGenerator[str, None]:
        """
        Subscribe to SSE events for a tenant.
        
        Creates a new queue for this connection and yields SSE-formatted
        events as they arrive.
        
        Args:
            tenant_id: The tenant ID to subscribe to
            
        Yields:
            SSE-formatted event strings
        """
        queue: asyncio.Queue = asyncio.Queue()
        
        async with self._lock:
            if tenant_id not in self._connections:
                self._connections[tenant_id] = []
            self._connections[tenant_id].append(queue)
            logger.info(
                "SSE client subscribed",
                extra={
                    "tenant_id": tenant_id,
                    "total_connections": len(self._connections[tenant_id])
                }
            )
        
        try:
            # Send initial connection event
            yield self._format_sse("connected", {"status": "connected"})
            
            while True:
                try:
                    # Wait for events with a timeout to send keepalives
                    event_data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield event_data
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            logger.debug(f"SSE connection cancelled for tenant {tenant_id}")
            raise
        finally:
            async with self._lock:
                if tenant_id in self._connections:
                    try:
                        self._connections[tenant_id].remove(queue)
                        if not self._connections[tenant_id]:
                            del self._connections[tenant_id]
                        logger.info(
                            "SSE client disconnected",
                            extra={
                                "tenant_id": tenant_id,
                                "remaining_connections": len(self._connections.get(tenant_id, []))
                            }
                        )
                    except ValueError:
                        pass
    
    async def notify(self, tenant_id: str, event: str, data: Any) -> None:
        """
        Send an event to all connected clients for a tenant.
        
        Args:
            tenant_id: The tenant ID to notify
            event: The event name/type
            data: The event data (will be JSON serialized)
        """
        async with self._lock:
            connections = self._connections.get(tenant_id, [])
            if not connections:
                logger.debug(
                    "No SSE connections for tenant, skipping notification",
                    extra={"tenant_id": tenant_id, "event": event}
                )
                return
            
            sse_message = self._format_sse(event, data)
            
            for queue in connections:
                try:
                    queue.put_nowait(sse_message)
                except asyncio.QueueFull:
                    logger.warning(
                        "SSE queue full for tenant",
                        extra={"tenant_id": tenant_id, "event": event}
                    )
            
            logger.debug(
                "SSE event broadcast",
                extra={
                    "tenant_id": tenant_id,
                    "event": event,
                    "connections": len(connections)
                }
            )
    
    def _format_sse(self, event: str, data: Any) -> str:
        """
        Format data as an SSE message.
        
        Args:
            event: The event name
            data: The event data
            
        Returns:
            SSE-formatted string
        """
        json_data = json.dumps(data, default=str)
        return f"event: {event}\ndata: {json_data}\n\n"


# Global broadcaster instance
sse_broadcaster = SSEBroadcaster()


def notify_sse(tenant_id: str, event: str, data: Any) -> None:
    """
    Synchronous wrapper to send SSE notifications.
    
    This function can be called from synchronous code and will
    schedule the notification in the event loop.
    
    Args:
        tenant_id: The tenant ID to notify
        event: The event name/type
        data: The event data
    """
    try:
        loop = asyncio.get_running_loop()
        asyncio.run_coroutine_threadsafe(
            sse_broadcaster.notify(tenant_id, event, data),
            loop
        )
    except RuntimeError:
        # No running event loop, try to run directly
        try:
            asyncio.run(sse_broadcaster.notify(tenant_id, event, data))
        except Exception as e:
            logger.warning(
                "Failed to send SSE notification (no event loop)",
                extra={"tenant_id": tenant_id, "event": event, "error": str(e)}
            )
    except Exception as e:
        logger.warning(
            "Failed to send SSE notification",
            extra={"tenant_id": tenant_id, "event": event, "error": str(e)}
        )


async def setup_redis_listener():
    """
    Background task to listen for Redis Pub/Sub messages and broadcast to local SSE connections.
    """
    from keep.common.core.config import config    
    redis_enabled = config("REDIS_CACHE", default="true") == "true"
    if not redis_enabled:
        logger.info("Redis disabled, SSE will only use local events")
        return

    try:
        import redis.asyncio as redis
        
        host = config("REDIS_HOST", default="localhost")
        port = config("REDIS_PORT", cast=int, default=6379)
        password = config("REDIS_PASSWORD", default=None)
        username = config("REDIS_USERNAME", default=None)

        client = redis.Redis(
            host=host,
            port=port,
            username=username,
            password=password,
            decode_responses=True,
        )
        
        if await client.ping():
            logger.info("Redis async client connected for SSE Pub/Sub")
            pubsub = client.pubsub()
            await pubsub.psubscribe("sse:messages:*")
            logger.info("Subscribed to Redis Pub/Sub channel sse:messages:*")

            async for message in pubsub.listen():
                if message["type"] == "pmessage":
                    channel = message["channel"]
                    data = message["data"]
                    
                    try:
                        payload = json.loads(data)
                        tenant_id = channel.split(":")[-1]
                        event = payload.get("event")
                        event_data = payload.get("data", {})
                        
                        if event and tenant_id:
                            # 1. Invalidate caches so REST APIs return fresh data
                            from keep.api.core.cache import invalidate
                            # Replicate the logic from sse_notify to determine prefixes
                            _EVENT_CACHE_MAP = {
                                "poll-alerts": ["alerts", "alert_facets"],
                                "alert-update": ["alerts", "alert_facets"],
                                "incident-change": ["incidents"],
                                "poll-presets": ["presets"],
                            }
                            
                            cache_prefixes = _EVENT_CACHE_MAP.get(event, [])
                            if cache_prefixes:
                                try:
                                    logger.debug(f"Invalidating cache prefixes {cache_prefixes} for tenant {tenant_id} due to {event}")
                                    for prefix in cache_prefixes:
                                        invalidate(prefix, tenant_id)
                                except Exception as inner_e:
                                    logger.warning(f"Failed to invalidate cache for {event}: {inner_e}")

                            # 2. Broadcast the SSE event to connected websockets
                            await sse_broadcaster.notify(tenant_id, event, event_data)
                    except Exception as e:
                        logger.error(f"Failed to process Redis SSE message: {e}")

    except Exception as e:
        logger.error(f"Failed to setup Redis listener: {e}")
