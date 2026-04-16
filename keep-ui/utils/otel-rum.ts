/**
 * RUM (Real User Monitoring) - Client-side metrics export via plain fetch.
 *
 * Sends metrics directly to a custom backend route defined by
 * NEXT_PUBLIC_RUM_ENDPOINT. No OTLP protocol required on the receiving end.
 *
 * Payload shape (array of events):
 * [{ type, name, value, path, timestamp, attributes }]
 */

const RUM_ENDPOINT = process.env.NEXT_PUBLIC_RUM_ENDPOINT || "";

const SESSION_ID = Math.random().toString(36).substring(2, 11);
const SERVICE_VERSION = process.env.NEXT_PUBLIC_KEEP_VERSION || "local";

// --- Batching ---

interface RumEvent {
    type: "histogram" | "counter";
    name: string;
    value: number;
    path: string;
    timestamp: number;
    attributes: Record<string, string | number>;
}

const queue: RumEvent[] = [];
let flushTimer: ReturnType<typeof setInterval> | null = null;

function enqueue(event: RumEvent) {
    if (!RUM_ENDPOINT) return; // silently no-op if not configured
    queue.push(event);
    scheduleFlush();
}

function scheduleFlush() {
    if (flushTimer !== null) return;
    flushTimer = setInterval(flush, 5_000); // flush every 5 s
}

async function flush() {
    if (queue.length === 0 || !RUM_ENDPOINT) return;

    const batch = queue.splice(0, queue.length);

    try {
        await fetch(RUM_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                service: "keep-frontend",
                version: SERVICE_VERSION,
                session_id: SESSION_ID,
                events: batch,
            }),
            // keepalive ensures the request completes even if the page is unloading
            keepalive: true,
        });
    } catch {
        // Best-effort: re-queue on network failure (up to a limit)
        if (queue.length < 200) {
            queue.unshift(...batch);
        }
    }
}

// Flush on page unload so we don't lose the last batch
if (typeof window !== "undefined") {
    window.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "hidden") {
            flush();
        }
    });
}

// --- Public API ---

/**
 * Record a Web Vital metric.
 * Called from WebVitalsReporter.
 */
export function recordWebVital(name: string, value: number, path: string): void {
    // Convert ms to seconds for time-based metrics; CLS is unitless
    const recordValue = name === "CLS" ? value : value / 1000.0;

    enqueue({
        type: "histogram",
        name: `keep.frontend.web_vital.${name.toLowerCase()}`,
        value: recordValue,
        path,
        timestamp: Date.now(),
        attributes: { metric: name },
    });
}

/**
 * Record a custom action latency.
 *
 * @param action  Name of the action (e.g. "change-status")
 * @param durationMs  Duration in milliseconds
 * @param path  Current page path
 */
export function reportActionLatency(
    action: string,
    durationMs: number,
    path: string
): void {
    enqueue({
        type: "histogram",
        name: "keep.frontend.action_latency",
        value: durationMs / 1000.0,
        path,
        timestamp: Date.now(),
        attributes: { action },
    });
}

/**
 * Record a page load latency.
 *
 * @param page  Name of the page (e.g. "dashboard")
 * @param durationMs  Duration in milliseconds
 * @param path  Current page path
 * @param attributes  Additional labels
 */
export function reportPageLoadLatency(
    page: string,
    durationMs: number,
    path: string,
    attributes: Record<string, string> = {}
): void {
    enqueue({
        type: "histogram",
        name: "keep.frontend.page_load_latency",
        value: durationMs / 1000.0,
        path,
        timestamp: Date.now(),
        attributes: { page, ...attributes },
    });
}

/**
 * Record a frontend error.
 *
 * @param type  Error category (e.g. "window-error")
 * @param message  Error message
 * @param path  Current page path
 */
export function reportError(type: string, message: string, path: string): void {
    enqueue({
        type: "counter",
        name: "keep.frontend.error_count",
        value: 1,
        path,
        timestamp: Date.now(),
        attributes: { type, message },
    });
}

/**
 * Record an active-user heartbeat.
 *
 * @param path  Current page path
 */
export function reportHeartbeat(path: string): void {
    enqueue({
        type: "counter",
        name: "keep.frontend.active_user_heartbeat",
        value: 1,
        path,
        timestamp: Date.now(),
        attributes: { session_id: SESSION_ID },
    });
}
