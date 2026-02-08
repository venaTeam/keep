import os
from fastapi import APIRouter, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    generate_latest,
    multiprocess,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
)

router = APIRouter()

# Define consumer metrics
# These are module-level so they persist across requests
MESSAGES_PROCESSED = Counter(
    "keep_event_handler_messages_processed_total",
    "Total number of messages processed by the event handler",
    ["status"],  # success, failed
)

MESSAGES_PROCESSING_TIME = Histogram(
    "keep_event_handler_message_processing_seconds",
    "Time spent processing each message",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
)

CONSUMER_RUNNING = Gauge(
    "keep_event_handler_consumer_running",
    "Whether the consumer is currently running (1) or stopped (0)",
)


@router.get("/metrics")
def get_metrics():
    """
    Expose Prometheus metrics.
    
    Handles both multiprocess mode (gunicorn) and single process mode (uvicorn/consumer_main).
    """
    # Check if we're running in multiprocess mode
    prometheus_multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    
    if prometheus_multiproc_dir:
        # Multiprocess mode - collect from all workers
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        data = generate_latest(registry)
    else:
        # Single process mode - use default registry
        data = generate_latest(REGISTRY)
    
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
