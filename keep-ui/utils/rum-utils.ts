
/**
 * RUM Utilities - Re-exports from OTEL RUM module.
 *
 * This file now delegates to the OpenTelemetry SDK which sends metrics
 * directly to the OTEL Collector, instead of POSTing to /api/rum backend.
 */
export {
    reportActionLatency,
    reportPageLoadLatency,
    reportError,
    reportHeartbeat,
} from "./otel-rum";
