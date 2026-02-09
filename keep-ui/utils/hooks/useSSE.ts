/**
 * Server-Sent Events (SSE) hook for real-time notifications.
 *
 * This hook uses browser-native EventSource for SSE communication.
 */

import { useCallback, useEffect, useRef } from "react";
import { useConfig } from "./useConfig";
import { useHydratedSession as useSession } from "@/shared/lib/hooks/useHydratedSession";

// Shared EventSource instance and handlers across all hook instances
let sharedEventSource: EventSource | null = null;
let sharedHandlers: Map<string, Set<(data: any) => void>> = new Map();
let connectionAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;

// Known event types that the backend can send
const SSE_EVENT_TYPES = [
  "connected",
  "poll-alerts",
  "incident-change",
  "poll-presets",
  "topology-update",
  "ai-logs-change",
  "incident-comment",
  "alert-update",
];

export const useSSE = () => {
  const { data: configData } = useConfig();
  const { data: session } = useSession();
  const isInitializedRef = useRef(false);

  // Initialize SSE connection
  useEffect(() => {
    // Prevent multiple initializations
    if (isInitializedRef.current) {
      return;
    }

    // Check if SSE is disabled (using PUSHER_DISABLED for backward compatibility)
    if (configData?.PUSHER_DISABLED === true) {
      return;
    }

    // Don't connect if we don't have config yet
    if (configData === null || configData === undefined) {
      return;
    }

    // Check if we already have a connection
    if (sharedEventSource !== null && sharedEventSource.readyState !== EventSource.CLOSED) {
      isInitializedRef.current = true;
      return;
    }

    // Get the direct backend URL for SSE - IMPORTANT: EventSource cannot work through
    // Next.js middleware rewrites, so we need the direct backend URL (API_URL), not
    // the proxy path (/backend or API_URL_CLIENT).
    const sseBaseUrl = configData.API_URL;
    if (!sseBaseUrl) {
      console.error("useSSE: API_URL not configured, cannot establish SSE connection");
      return;
    }

    // Build the SSE URL with the direct backend URL
    let sseUrl = `${sseBaseUrl}/sse/subscribe`;

    // Add token as query parameter if we have a session (EventSource doesn't support headers)
    if (session?.accessToken) {
      sseUrl += `?token=${encodeURIComponent(session.accessToken)}`;
    }

    console.log("useSSE: Creating new EventSource connection");

    try {
      sharedEventSource = new EventSource(sseUrl);

      sharedEventSource.onopen = () => {
        console.log("useSSE: Connection opened successfully");
        connectionAttempts = 0;
      };

      sharedEventSource.onerror = (error) => {
        console.error("useSSE: Connection error:", error);

        // EventSource will auto-reconnect, but we track attempts
        if (sharedEventSource?.readyState === EventSource.CLOSED) {
          connectionAttempts++;
          if (connectionAttempts >= MAX_RECONNECT_ATTEMPTS) {
            console.error("useSSE: Max reconnection attempts reached");
            sharedEventSource?.close();
          }
        }
      };

      // Register listeners for all known event types
      SSE_EVENT_TYPES.forEach((eventType) => {
        sharedEventSource!.addEventListener(eventType, (event: MessageEvent) => {
          const handlers = sharedHandlers.get(eventType);
          if (handlers && handlers.size > 0) {
            try {
              // Parse the data - the backend sends JSON
              const data = JSON.parse(event.data);

              handlers.forEach((handler) => {
                try {
                  handler(data);
                } catch (handlerError) {
                  console.error(
                    `useSSE: Error in handler for '${eventType}':`,
                    handlerError
                  );
                }
              });
            } catch (parseError) {
              // If JSON parsing fails, pass the raw data
              handlers.forEach((handler) => {
                try {
                  handler(event.data);
                } catch (handlerError) {
                  console.error(
                    `useSSE: Error in handler for '${eventType}':`,
                    handlerError
                  );
                }
              });
            }
          }
        });
      });

      isInitializedRef.current = true;
    } catch (error) {
      console.error("useSSE: Error creating EventSource:", error);
    }

    // Cleanup on unmount - but we don't close the shared connection
    // as other components might still be using it
    return () => {
      // Individual component unmount - don't close shared connection
    };
  }, [configData, session?.accessToken]);

  // Bind a callback to an event
  const bind = useCallback((event: string, callback: (data: any) => void) => {
    if (!sharedHandlers.has(event)) {
      sharedHandlers.set(event, new Set());
    }

    sharedHandlers.get(event)!.add(callback);
  }, []);

  // Unbind a callback from an event
  const unbind = useCallback((event: string, callback: (data: any) => void) => {
    const handlers = sharedHandlers.get(event);
    if (handlers) {
      handlers.delete(callback);
      if (handlers.size === 0) {
        sharedHandlers.delete(event);
      }
    }
  }, []);

  return {
    bind,
    unbind,
  };
};


