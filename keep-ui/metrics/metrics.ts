import { Registry, Gauge, Histogram } from "prom-client";

export const register = new Registry();

// Action latency histogram (in seconds)
export const actionLatency = new Histogram({
  name: "keep_ui_action_latency_seconds",
  help: "Latency of user actions in keep-ui",
  registers: [register],
  labelNames: ["action"],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30],
});

// Page load latency histogram
export const pageloadLatency = new Histogram({
  name: "keep_ui_page_load_latency_seconds",
  help: "Page load latency in keep-ui",
  registers: [register],
  labelNames: ["page"],
  buckets: [0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30, 60],
});

// Count of page loads
export const pageloads = new Gauge({
  name: "keep_ui_page_loads_total",
  help: "Total number of page loads in keep-ui",
  registers: [register],
  labelNames: ["page"],
});

// Count of action executions
export const actionExecutions = new Gauge({
  name: "keep_ui_action_executions_total",
  help: "Total number of action executions in keep-ui",
  registers: [register],
  labelNames: ["action"],
});

// Active users gauge
export const activeUsers = new Gauge({
  name: "keep_ui_active_users",
  help: "Number of currently active keep-ui users",
  registers: [register],
});

// Count of errors by action type
export const errors = new Gauge({
  name: "keep_ui_errors_total",
  help: "Total number of errors in keep-ui",
  registers: [register],
  labelNames: ["action"],
});

// Global errors counter
export const globalErrors = new Gauge({
  name: "keep_ui_global_errors_total",
  help: "Total number of uncaught JS errors and unhandled promise rejections in keep-ui",
  registers: [register],
});

// Pre-initialize all action labels to 0
const ALL_ACTIONS = [
  "change_status",
  "self_assign",
  "dismiss_alert",
  "create_preset",
  "create_incident",
  "create_dashboard",
  "add_note",
  "timeline_loading",
] as const;

for (const action of ALL_ACTIONS) {
  errors.set({ action }, 0);
}