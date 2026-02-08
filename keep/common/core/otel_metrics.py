"""
OpenTelemetry metrics configuration for standalone processes.

This module provides OTEL metrics setup for processes that don't run FastAPI,
such as the dedicated Kafka consumer (consumer_main.py).

Metrics are pushed to an OTEL collector via HTTP POST.

Key Keep Application Metrics Exported:
- keep_events_in_total: Total events received
- keep_events_processed_total: Total events processed successfully
- keep_events_error_total: Total events with errors
- keep_alert_ingestion_total: Total alerts ingested
- keep_alert_deduplication_total: Total deduplicated events
- keep_workflows_executions_total: Total workflow executions
- keep_incident_opened_total: Total incidents opened
"""

import logging
import os
from typing import Optional

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

logger = logging.getLogger(__name__)

# Global meter instance
_meter: Optional[metrics.Meter] = None
_is_initialized = False

# OTEL metric instruments (lazily initialized)
# Keep Application Metrics - these mirror prometheus_client metrics in keep/common/core/metrics.py
class KeepOtelMetrics:
    """Container for Keep application OTEL metrics."""
    
    # Event processing
    events_in_counter = None
    events_processed_counter = None
    events_error_counter = None
    
    # Alert ingestion
    alert_ingestion_counter = None
    alert_ingestion_error_counter = None
    alert_enrichment_histogram = None
    
    # Deduplication
    deduplication_counter = None
    deduplication_histogram = None
    
    # Rules engine
    rules_engine_histogram = None
    
    # Workflows
    workflow_executions_counter = None
    workflow_errors_counter = None
    workflow_duration_histogram = None
    
    # Incidents
    incidents_opened_counter = None
    
    # Consumer state
    consumer_running_value = 0


# Singleton metrics instance
_metrics = KeepOtelMetrics()


def setup_otel_metrics(service_name: str = "keep-event-handler-consumer") -> bool:
    """
    Initialize OpenTelemetry metrics with HTTP exporter.
    
    Environment Variables:
        OTEL_EXPORTER_OTLP_ENDPOINT: Base OTLP endpoint (e.g., http://otel-collector:4318)
        OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: Specific metrics endpoint (overrides base)
        METRIC_OTEL_ENABLED: Set to "true" to enable metrics export
        OTEL_METRICS_EXPORT_INTERVAL_MS: Export interval in milliseconds (default: 10000)
    
    Returns:
        True if OTEL metrics were successfully configured, False otherwise.
    """
    global _meter, _metrics, _is_initialized
    
    if _is_initialized:
        logger.debug("OTEL metrics already initialized")
        return True
    
    metrics_enabled = os.environ.get("METRIC_OTEL_ENABLED", "false").lower() == "true"
    otlp_endpoint = os.environ.get(
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    )
    
    if not metrics_enabled:
        logger.info("OTEL metrics disabled (METRIC_OTEL_ENABLED != 'true')")
        return False
    
    if not otlp_endpoint:
        logger.warning(
            "OTEL metrics enabled but no endpoint configured. "
            "Set OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
        )
        return False
    
    try:
        # Import HTTP exporter (preferred for simplicity)
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        
        # Build metrics endpoint URL
        # If the URL already ends with 'metrics' (custom path), use it as-is
        # Otherwise, append the standard OTLP path /v1/metrics
        if otlp_endpoint.rstrip('/').endswith('metrics'):
            # Custom endpoint like: collector.com/otlp/http/metrics
            metrics_endpoint = otlp_endpoint.rstrip('/')
        else:
            # Standard OTLP base endpoint like: http://collector:4318
            metrics_endpoint = f"{otlp_endpoint.rstrip('/')}/v1/metrics"
        
        logger.info(f"Configuring OTEL metrics export to: {metrics_endpoint}")
        
        # Create resource with service information
        resource = Resource.create(
            attributes={
                ResourceAttributes.SERVICE_NAME: service_name,
                ResourceAttributes.SERVICE_INSTANCE_ID: f"consumer-{os.getpid()}",
            }
        )
        
        # Configure export interval
        export_interval_ms = int(os.environ.get("OTEL_METRICS_EXPORT_INTERVAL_MS", "10000"))
        
        # Create exporter and reader
        exporter = OTLPMetricExporter(endpoint=metrics_endpoint)
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=export_interval_ms,
        )
        
        # Create and set meter provider
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)
        
        # Get meter for Keep metrics
        _meter = metrics.get_meter("keep.event_handler", version="1.0.0")
        
        # Initialize Keep application metrics
        _init_keep_metrics()
        
        _is_initialized = True
        
        logger.info(
            "OTEL metrics configured successfully",
            extra={
                "endpoint": metrics_endpoint,
                "export_interval_ms": export_interval_ms,
                "service_name": service_name,
            }
        )
        return True
        
    except ImportError as e:
        logger.error(f"Failed to import OTEL HTTP exporter: {e}")
        return False
    except Exception as e:
        logger.exception(f"Failed to configure OTEL metrics: {e}")
        return False


def _init_keep_metrics():
    """Initialize Keep application metrics matching prometheus_client metrics."""
    global _metrics, _meter
    
    if not _meter:
        return
    
    # Event processing metrics
    _metrics.events_in_counter = _meter.create_counter(
        name="keep_events_in_total",
        description="Total number of events received",
        unit="1",
    )
    
    _metrics.events_processed_counter = _meter.create_counter(
        name="keep_events_processed_total",
        description="Total number of events processed successfully",
        unit="1",
    )
    
    _metrics.events_error_counter = _meter.create_counter(
        name="keep_events_error_total",
        description="Total number of events with errors",
        unit="1",
    )
    
    # Alert ingestion metrics
    _metrics.alert_ingestion_counter = _meter.create_counter(
        name="keep_alert_ingestion_total",
        description="Total number of alerts ingested",
        unit="1",
    )
    
    _metrics.alert_ingestion_error_counter = _meter.create_counter(
        name="keep_alert_ingestion_error_total",
        description="Total number of alert ingestion errors",
        unit="1",
    )
    
    _metrics.alert_enrichment_histogram = _meter.create_histogram(
        name="keep_alert_enrichment_duration_seconds",
        description="Time spent enriching alerts",
        unit="s",
    )
    
    # Deduplication metrics
    _metrics.deduplication_counter = _meter.create_counter(
        name="keep_alert_deduplication_events_total",
        description="Total number of deduplicated events",
        unit="1",
    )
    
    _metrics.deduplication_histogram = _meter.create_histogram(
        name="keep_alert_deduplication_duration_seconds",
        description="Time spent deduplicating events",
        unit="s",
    )
    
    # Rules engine metrics
    _metrics.rules_engine_histogram = _meter.create_histogram(
        name="keep_alert_rules_engine_duration_seconds",
        description="Time spent in rules engine",
        unit="s",
    )
    
    # Workflow metrics
    _metrics.workflow_executions_counter = _meter.create_counter(
        name="keep_workflows_executions_total",
        description="Total number of workflow executions",
        unit="1",
    )
    
    _metrics.workflow_errors_counter = _meter.create_counter(
        name="keep_workflows_execution_errors_total",
        description="Total number of workflow execution errors",
        unit="1",
    )
    
    _metrics.workflow_duration_histogram = _meter.create_histogram(
        name="keep_workflows_execution_duration_seconds",
        description="Time spent executing workflows",
        unit="s",
    )
    
    # Incident metrics
    _metrics.incidents_opened_counter = _meter.create_counter(
        name="keep_incident_opened_total",
        description="Total number of incidents opened",
        unit="1",
    )
    
    # Consumer state gauge
    def _get_consumer_running_callback(options):
        yield metrics.Observation(_metrics.consumer_running_value)
    
    _meter.create_observable_gauge(
        name="keep_event_handler_consumer_running",
        description="Whether the consumer is currently running (1) or stopped (0)",
        unit="1",
        callbacks=[_get_consumer_running_callback],
    )


# ============================================================================
# Public API - Functions to record metrics
# These should be called from the event processing code
# ============================================================================

def record_event_in():
    """Record an incoming event."""
    if _metrics.events_in_counter:
        _metrics.events_in_counter.add(1)


def record_event_processed():
    """Record a successfully processed event."""
    if _metrics.events_processed_counter:
        _metrics.events_processed_counter.add(1)


def record_event_error():
    """Record an event processing error."""
    if _metrics.events_error_counter:
        _metrics.events_error_counter.add(1)


def record_alert_ingestion(source: str, status: str):
    """Record an alert ingestion."""
    if _metrics.alert_ingestion_counter:
        _metrics.alert_ingestion_counter.add(1, {"source": source, "status": status})


def record_alert_ingestion_error(source: str, error_type: str):
    """Record an alert ingestion error."""
    if _metrics.alert_ingestion_error_counter:
        _metrics.alert_ingestion_error_counter.add(1, {"source": source, "error_type": error_type})


def record_alert_enrichment_duration(source: str, duration_seconds: float):
    """Record alert enrichment duration."""
    if _metrics.alert_enrichment_histogram:
        _metrics.alert_enrichment_histogram.record(duration_seconds, {"source": source})


def record_deduplication(provider_type: str, status: str):
    """Record a deduplication event."""
    if _metrics.deduplication_counter:
        _metrics.deduplication_counter.add(1, {"provider_type": provider_type, "status": status})


def record_deduplication_duration(provider_type: str, duration_seconds: float):
    """Record deduplication duration."""
    if _metrics.deduplication_histogram:
        _metrics.deduplication_histogram.record(duration_seconds, {"provider_type": provider_type})


def record_rules_engine_duration(provider_type: str, duration_seconds: float):
    """Record rules engine duration."""
    if _metrics.rules_engine_histogram:
        _metrics.rules_engine_histogram.record(duration_seconds, {"provider_type": provider_type})


def record_workflow_execution(tenant_id: str, workflow_id: str, trigger_type: str):
    """Record a workflow execution."""
    if _metrics.workflow_executions_counter:
        _metrics.workflow_executions_counter.add(1, {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "trigger_type": trigger_type,
        })


def record_workflow_error(tenant_id: str, workflow_id: str, error_type: str):
    """Record a workflow execution error."""
    if _metrics.workflow_errors_counter:
        _metrics.workflow_errors_counter.add(1, {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "error_type": error_type,
        })


def record_workflow_duration(tenant_id: str, workflow_id: str, duration_seconds: float):
    """Record workflow execution duration."""
    if _metrics.workflow_duration_histogram:
        _metrics.workflow_duration_histogram.record(duration_seconds, {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
        })


def record_incident_opened(tenant_id: str, rule_id: str, rule_name: str):
    """Record an incident being opened."""
    if _metrics.incidents_opened_counter:
        _metrics.incidents_opened_counter.add(1, {
            "tenant_id": tenant_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
        })


def set_consumer_running(running: bool):
    """Set the consumer running state for the gauge."""
    _metrics.consumer_running_value = 1 if running else 0


def is_otel_metrics_enabled() -> bool:
    """Check if OTEL metrics are configured and enabled."""
    return _is_initialized
