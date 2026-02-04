from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from keep.event_handler.core.lifespan import get_consumer

router = APIRouter()


@router.get("/health")
def health_check():
    """Basic health check endpoint."""
    return JSONResponse(
        content={"status": "ok"},
        status_code=200,
    )


@router.get("/health/detailed")
def detailed_health_check():
    """
    Detailed health check including consumer status.
    
    Returns consumer health metrics useful for:
    - Kubernetes liveness/readiness probes
    - Monitoring dashboards
    - Debugging consumption issues
    """
    consumer = get_consumer()
    
    if consumer is None:
        return JSONResponse(
            content={
                "status": "unhealthy",
                "reason": "Consumer not initialized",
            },
            status_code=503,
        )
    
    health_status = consumer.get_health_status()
    
    # Determine overall health
    is_healthy = health_status.get("running", False)
    
    return JSONResponse(
        content={
            "status": "healthy" if is_healthy else "unhealthy",
            "consumer": health_status,
        },
        status_code=200 if is_healthy else 503,
    )


@router.get("/health/ready")
def readiness_check():
    """
    Readiness probe for Kubernetes.
    
    Returns 200 if consumer is running and ready to process messages.
    Returns 503 if consumer is not ready (still initializing or stopped).
    """
    consumer = get_consumer()
    
    if consumer is None:
        return JSONResponse(
            content={"ready": False, "reason": "Consumer not initialized"},
            status_code=503,
        )
    
    health_status = consumer.get_health_status()
    is_running = health_status.get("running", False)
    
    if is_running:
        return JSONResponse(
            content={"ready": True},
            status_code=200,
        )
    else:
        return JSONResponse(
            content={"ready": False, "reason": "Consumer not running"},
            status_code=503,
        )


@router.get("/")
def get_status():
    """Root status endpoint."""
    return JSONResponse(
        content="Event Handler Service Running\n",
        status_code=200,
        headers={"Content-Type": "text/plain"},
    )
