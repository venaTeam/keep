/**
 * RUM Utilities - Re-exports from the RUM module.
 *
 * Metrics are batched and POSTed via plain fetch to the URL
 * defined by NEXT_PUBLIC_RUM_ENDPOINT.
 */
export {
    reportActionLatency,
    reportPageLoadLatency,
    reportError,
    reportHeartbeat,
} from "./otel-rum";
