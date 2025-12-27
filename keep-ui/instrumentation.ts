// @ts-nocheck
import * as Sentry from "@sentry/nextjs";

// Workaround for broken localStorage in some environments (e.g. dev/docker)
// where it exists but getItem is not a function
if (
  typeof global !== "undefined" &&
  typeof global.localStorage !== "undefined" &&
  typeof global.localStorage.getItem !== "function"
) {
  console.log("Blocking broken localStorage in instrumentation");
  // @ts-ignore
  delete global.localStorage;
}

export async function register() {
  if (
    process.env.SENTRY_DISABLED === "true" ||
    process.env.NODE_ENV === "development"
  ) {
    return;
  }

  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }

  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}

// We need NextJS 15 to use this
export const onRequestError = Sentry.captureRequestError;
