/**
 * OpenTelemetry RUM (Real User Monitoring) - Client-side metrics export
 *
 * Sends Web Vitals and custom action latency metrics directly from the browser
 * to the OTEL Collector via OTLP/HTTP, bypassing the backend.
 */

import { metrics, Histogram } from "@opentelemetry/api";
import {
    MeterProvider,
    PeriodicExportingMetricReader,
} from "@opentelemetry/sdk-metrics";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { Resource } from "@opentelemetry/resources";
import {
    ATTR_SERVICE_NAME,
    ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

// Collector URL defaults to /otlp which is proxied by NGINX to the OTEL Collector
const OTEL_COLLECTOR_URL =
    process.env.NEXT_PUBLIC_OTEL_COLLECTOR_URL || "/otlp";

const SESSION_ID = Math.random().toString(36).substring(2, 11);

let initialized = false;

// Histogram instruments (lazy-initialized)
let clsHistogram: Histogram;
let fcpHistogram: Histogram;
let lcpHistogram: Histogram;
let ttfbHistogram: Histogram;
let fidHistogram: Histogram;
let inpHistogram: Histogram;
let actionLatencyHistogram: Histogram;
let pageLoadLatencyHistogram: Histogram;
let errorCounter: any;
let activeUserHeartbeatCounter: any;

/**
 * Initialize the OTEL MeterProvider and create histogram instruments.
 * Safe to call multiple times — only initializes once.
 */
function ensureInitialized() {
    if (initialized) return;
    initialized = true;

    const resource = new Resource({
        [ATTR_SERVICE_NAME]: "keep-frontend",
        [ATTR_SERVICE_VERSION]: process.env.NEXT_PUBLIC_KEEP_VERSION || "local",
    });

    const exporter = new OTLPMetricExporter({
        url: `${OTEL_COLLECTOR_URL}/v1/metrics`,
        headers: {},
    });

    const reader = new PeriodicExportingMetricReader({
        exporter,
        exportIntervalMillis: 1_000, // Export every 1 second (faster testing)
        exportTimeoutMillis: 1_000,
    });

    const meterProvider = new MeterProvider({
        resource,
        readers: [reader],
    });

    // Set as global so other parts of the app can use it
    metrics.setGlobalMeterProvider(meterProvider);

    const meter = meterProvider.getMeter("keep-frontend-rum", "1.0.0");

    // Web Vitals histograms
    clsHistogram = meter.createHistogram("keep.frontend.web_vital.cls", {
        description: "Cumulative Layout Shift",
        unit: "",
        advice: {
            explicitBucketBoundaries: [0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0],
        },
    });

    fcpHistogram = meter.createHistogram("keep.frontend.web_vital.fcp", {
        description: "First Contentful Paint (seconds)",
        unit: "s",
        advice: {
            explicitBucketBoundaries: [
                0.5, 1.0, 1.5, 1.8, 2.0, 2.5, 3.0, 4.0, 5.0, 10.0,
            ],
        },
    });

    lcpHistogram = meter.createHistogram("keep.frontend.web_vital.lcp", {
        description: "Largest Contentful Paint (seconds)",
        unit: "s",
        advice: {
            explicitBucketBoundaries: [0.5, 1.0, 1.5, 2.5, 3.0, 4.0, 5.0, 10.0],
        },
    });

    ttfbHistogram = meter.createHistogram("keep.frontend.web_vital.ttfb", {
        description: "Time to First Byte (seconds)",
        unit: "s",
        advice: {
            explicitBucketBoundaries: [0.1, 0.2, 0.5, 0.8, 1.0, 1.8, 3.0, 5.0],
        },
    });

    fidHistogram = meter.createHistogram("keep.frontend.web_vital.fid", {
        description: "First Input Delay (seconds)",
        unit: "s",
        advice: {
            explicitBucketBoundaries: [0.1, 0.2, 0.3, 0.4, 0.5, 1.0],
        },
    });

    inpHistogram = meter.createHistogram("keep.frontend.web_vital.inp", {
        description: "Interaction to Next Paint (seconds)",
        unit: "s",
        advice: {
            explicitBucketBoundaries: [0.1, 0.2, 0.5, 1.0, 2.0, 5.0],
        },
    });

    actionLatencyHistogram = meter.createHistogram(
        "keep.frontend.action_latency",
        {
            description: "Frontend action latency (seconds)",
            unit: "s",
            advice: {
                explicitBucketBoundaries: [0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            },
        }
    );

    pageLoadLatencyHistogram = meter.createHistogram(
        "keep.frontend.page_load_latency",
        {
            description: "Frontend page load latency (seconds)",
            unit: "s",
            advice: {
                explicitBucketBoundaries: [0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 60.0],
            },
        }
    );

    errorCounter = meter.createCounter("keep.frontend.error_count", {
        description: "Total count of frontend errors",
    });

    activeUserHeartbeatCounter = meter.createCounter(
        "keep.frontend.active_user_heartbeat",
        {
            description: "Active user heartbeat count",
        }
    );
}

const METRICS_MAP: Record<string, () => Histogram> = {
    CLS: () => clsHistogram,
    FCP: () => fcpHistogram,
    LCP: () => lcpHistogram,
    TTFB: () => ttfbHistogram,
    FID: () => fidHistogram,
    INP: () => inpHistogram,
};

/**
 * Record a Web Vital metric via OTEL.
 * Called from WebVitalsReporter.
 */
export function recordWebVital(
    name: string,
    value: number,
    path: string
): void {
    ensureInitialized();

    const getHistogram = METRICS_MAP[name];
    if (!getHistogram) return;

    const histogram = getHistogram();

    // Convert ms to seconds for time-based metrics (CLS is unitless)
    const recordValue = name === "CLS" ? value : value / 1000.0;

    histogram.record(recordValue, { path });
}

/**
 * Record a custom action latency via OTEL.
 * Drop-in replacement for the old reportActionLatency that POSTed to /api/rum.
 *
 * @param action Name of the action (e.g., "change-status")
 * @param durationMs Duration of the action in milliseconds
 * @param path The current page path
 */
export function reportActionLatency(
    action: string,
    durationMs: number,
    path: string
): void {
    ensureInitialized();

    // Convert ms to seconds
    const durationSec = durationMs / 1000.0;
    actionLatencyHistogram.record(durationSec, { path, action });
}

/**
 * Record a page load latency via OTEL.
 *
 * @param page Name of the page (e.g., "dashboard")
 * @param durationMs Duration of the page load in milliseconds
 * @param path The current page path
 * @param attributes Additional labels for the metric
 */
export function reportPageLoadLatency(
    page: string,
    durationMs: number,
    path: string,
    attributes: Record<string, string> = {}
): void {
    ensureInitialized();

    const durationSec = durationMs / 1000.0;
    pageLoadLatencyHistogram.record(durationSec, {
        ...attributes,
        path,
        page,
    });
}

/**
 * Record a frontend error.
 *
 * @param type Type of error (e.g., "window-error")
 * @param message Error message
 * @param path The current page path
 */
export function reportError(type: string, message: string, path: string): void {
    ensureInitialized();

    errorCounter.add(1, { type, message, path });
}

/**
 * Record an active user heartbeat.
 *
 * @param path The current page path
 */
export function reportHeartbeat(path: string): void {
    ensureInitialized();

    // Include SESSION_ID to allow counting unique users/sessions in Prometheus
    activeUserHeartbeatCounter.add(1, { session_id: SESSION_ID });
}
