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


import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

# Use a bounded thread pool to avoid spawning infinite threads under extreme alert load
_sse_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="sse_notify")

def _send_sse_http(tenant_id: str, event: str, data: Any):
    try:
        api_url = os.environ.get("KEEP_API_URL", "http://localhost:8080")
        
        # Serialize the data payload first to ensure UUIDs/datetimes don't crash requests JSON encoder
        serialized_data = json.loads(json.dumps(data, default=str))

        requests.post(
            f"{api_url}/sse/notify",
            json={
                "tenant_id": tenant_id,
                "event": event,
                "data": serialized_data
            },
            timeout=5
        )
    except Exception as e:
        logger.warning(
            "Failed to send SSE notification via HTTP",
            extra={"tenant_id": tenant_id, "event": event, "error": str(e)}
        )

def notify_sse(tenant_id: str, event: str, data: Any) -> None:
    """
    Synchronous wrapper to send SSE notifications globally.
    
    This uses a fixed ThreadPoolExecutor to shoot the event via HTTP POST back 
    to the central keep-api, bridging any isolated workers (event-handler, watcher) 
    back to the master WebSocket memory pool without blocking the caller or exhausting threads.
    """
    _sse_executor.submit(_send_sse_http, tenant_id, event, data)
