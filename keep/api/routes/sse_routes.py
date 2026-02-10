"""
Server-Sent Events (SSE) routes for real-time notifications.

This module provides the SSE endpoint that clients connect to for
receiving real-time updates. Supports both authenticated and
no-auth modes.
"""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from keep.common.core.sse import sse_broadcaster
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identitymanagerfactory import IdentityManagerFactory

# Import single tenant constants for noauth mode
from keep.common.core.dependencies import SINGLE_TENANT_UUID, SINGLE_TENANT_EMAIL

logger = logging.getLogger(__name__)
router = APIRouter()


async def get_sse_authenticated_entity(
    request: Request,
    token: Optional[str] = Query(None, description="Authentication token for SSE connection"),
) -> AuthenticatedEntity:
    """
    Get authenticated entity for SSE connections.
    
    This dependency supports both authenticated and no-auth modes:
    - In noauth mode: Returns a default single-tenant entity if no token provided
    - In authenticated mode: Validates the token and returns the authenticated entity
    
    Args:
        request: The FastAPI request object
        token: Optional token passed as query parameter (since EventSource can't send headers)
        
    Returns:
        AuthenticatedEntity for the connection
    """
    auth_type = os.environ.get("AUTH_TYPE", "noauth").lower()
    
    # Check if we're in noauth mode and no token provided
    if auth_type == "noauth" and not token:
        logger.debug("SSE connection in noauth mode without token, using single tenant")
        return AuthenticatedEntity(
            tenant_id=SINGLE_TENANT_UUID,
            email=SINGLE_TENANT_EMAIL,
        )
    
    # If token is provided or we're in authenticated mode, use the identity manager
    if token:
        # Create a mock request with the token in the authorization header
        # so the auth verifier can process it
        request.scope["headers"] = list(request.scope.get("headers", []))
        # Add authorization header if token is provided
        auth_header = (b"authorization", f"Bearer {token}".encode())
        request.scope["headers"].append(auth_header)
    
    # Get the auth verifier and authenticate
    try:
        auth_verifier = IdentityManagerFactory.get_auth_verifier(["read:alert"])
        authenticated_entity = await auth_verifier(request)
        return authenticated_entity
    except Exception as e:
        # If authentication fails in noauth mode, fall back to single tenant
        if auth_type == "noauth":
            logger.debug(f"SSE auth failed in noauth mode, using single tenant: {e}")
            return AuthenticatedEntity(
                tenant_id=SINGLE_TENANT_UUID,
                email=SINGLE_TENANT_EMAIL,
            )
        raise


@router.get("/subscribe")
async def sse_subscribe(
    authenticated_entity: AuthenticatedEntity = Depends(get_sse_authenticated_entity),
) -> StreamingResponse:
    """
    Subscribe to Server-Sent Events for real-time updates.
    
    This endpoint establishes a long-lived SSE connection that receives
    real-time notifications for the authenticated tenant.
    
    Events:
    - connected: Initial connection confirmation
    - poll-alerts: Alerts have been updated
    - incident-change: Incidents have been updated
    - poll-presets: Presets have been updated
    - topology-update: Topology has been updated
    - ai-logs-change: AI logs have been updated
    - incident-comment: New comment on incident
    - alert-update: Alert has been updated
    
    Query Parameters:
        token: Optional authentication token (for authenticated modes)
    
    Returns:
        StreamingResponse with SSE content type
    """
    tenant_id = authenticated_entity.tenant_id
    
    logger.info(
        "SSE subscription started",
        extra={
            "tenant_id": tenant_id,
            "email": authenticated_entity.email,
        }
    )
    
    async def event_generator():
        async for event in sse_broadcaster.subscribe(tenant_id):
            yield event
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )



class SSENotification(BaseModel):
    tenant_id: str
    event: str
    data: dict = {}


@router.post("/notify", status_code=204)
async def sse_notify(
    notification: SSENotification,
    # authenticated_entity: AuthenticatedEntity = Depends(get_sse_authenticated_entity),
) -> None:
    """
    Internal endpoint to trigger SSE notifications from other services (e.g. event handler).
    """
    logger.info(
        "Received SSE notification request via API",
        extra={
            "tenant_id": notification.tenant_id,
            "event": notification.event,
        }
    )
    await sse_broadcaster.notify(
        notification.tenant_id,
        notification.event,
        notification.data
    )
