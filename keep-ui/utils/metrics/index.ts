import axios from "axios";
import { v4 as uuidv4 } from "uuid";

const HEARTBEAT_INTERVAL_MS = 30_000;
let heartbeatInterval: ReturnType<typeof setInterval> | null = null;

const HEARTBEAT_STORAGE_KEY = "keep_ui_user_id";

function getUserId(): string {
  if (typeof window === "undefined") return "server";
  let userId = localStorage.getItem(HEARTBEAT_STORAGE_KEY);
  if (!userId) {
    userId = uuidv4();
    localStorage.setItem(HEARTBEAT_STORAGE_KEY, userId);
  }
  return userId;
}

async function sendHeartbeat() {
  const userId = getUserId();
  try {
    await axios.post("/api/metrics/heartbeat", { userId });
  } catch {
    // Fire-and-forget
  }
}

export function startHeartbeat() {
  if (heartbeatInterval !== null) return; // already running
  sendHeartbeat();
  heartbeatInterval = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL_MS);
}

export function stopHeartbeat() {
  if (heartbeatInterval !== null) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

// Types
export type ActionLabel = 
  | "change_status"
  | "self_assign"
  | "dismiss_alert"
  | "create_preset"
  | "create_incident"
  | "create_dashboard"
  | "add_note"
  | "timeline_loading";

export type PageLabel = 
  | "incidents"
  | "incidents_detail"
  | "alerts_feed"
  | "alerts_detail"
  | "dashboard"
  | "dashboard_detail"
  | string;

const recordedPages = new Set<string>();

// Record Page Load
export async function recordPageLoad(label: PageLabel, latencySeconds: number) {
  if (recordedPages.has(label)) return; // Deduplicate
  
  recordedPages.add(label);
  try {
    await axios.post("/api/metrics/page", { label, latency: latencySeconds });
  } catch (err) {
    // Silently fail
  }
}

// Record Action
export async function recordAction(label: ActionLabel, latencySeconds: number) {
  try {
    await axios.post("/api/metrics/action", { label, latency: latencySeconds });
  } catch (err) {
    // Silently fail
  }
}

// Helper for timing actions
export async function timeAction<T>(
  label: ActionLabel,
  fn: () => Promise<T>
): Promise<T> {
  const start = performance.now();
  try {
    return await fn();
  } finally {
    const latency = (performance.now() - start) / 1000;
    recordAction(label, latency);
  }
}

// Record Specific Error
export async function recordError(action: ActionLabel) {
  try {
    await axios.post("/api/metrics/errors", { action });
  } catch {
    // Fire-and-forget
  }
}

let globalErrorTrackingStarted = false;

export function startGlobalErrorTracking() {
  if (globalErrorTrackingStarted || typeof window === "undefined") return;
  globalErrorTrackingStarted = true;

  // Capture all uncaught JavaScript errors
  window.addEventListener("error", () => {
    axios.post("/api/metrics/global-errors").catch(() => {});
  });

  // Capture all unhandled promise rejections
  window.addEventListener("unhandledrejection", () => {
    axios.post("/api/metrics/global-errors").catch(() => {});
  });
}