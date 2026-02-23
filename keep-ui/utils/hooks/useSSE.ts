/**
 * Server-Sent Events (SSE) hook for real-time notifications.
 *
 * This hook uses browser-native EventSource for SSE communication.
 */

import { useCallback, useEffect, useRef } from "react";
import { useConfig } from "./useConfig";
import { useHydratedSession as useSession } from "@/shared/lib/hooks/useHydratedSession";

// Global singleton connection - shared across ALL hook instances
// This prevents multiple fetch connections when useSSE() is called
// from multiple components (SSEProvider, useAlertPolling, etc.)
let globalController: AbortController | null = null;
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
  const { data: user_session, status } = useSession();

  // Initialize SSE connection
  useEffect(() => {
    const session = status === "unauthenticated" ? {
      accessToken: "unauthenticated"
    } : user_session;

    // Check if SSE is disabled
    if (configData?.SSE_DISABLED === true) {
      return;
    }

    // Don't connect if we don't have config yet
    if (configData === null || configData === undefined) {
      return;
    }

    // Wait for authentication if auth is required (status will be loading initially)
    if (status === "loading") {
      return;
    }

    // If a global connection already exists, skip — only the first
    // component to mount creates the connection, all others just
    // use bind/unbind on the shared handler map.
    if (globalController) {
      return;
    }

    const sseBaseUrl = configData.API_URL;
    if (!sseBaseUrl) {
      console.error("useSSE: API_URL not configured, cannot establish SSE connection");
      return;
    }

    const sseUrl = `${sseBaseUrl}/sse/subscribe`;

    const controller = new AbortController();
    const signal = controller.signal;
    globalController = controller;

    const connectSSE = async () => {
      try {
        console.log("useSSE: Connecting via fetch...");

        const headers: HeadersInit = {
          "Accept": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        };

        // Logic from ApiClient.ts getHeaders()
        if (session && session.accessToken && session.accessToken !== "unauthenticated") {
          headers["Authorization"] = `Bearer ${session.accessToken}`;
        }
        headers["ngrok-skip-browser-warning"] = "true";

        const response = await fetch(sseUrl, {
          method: "POST",
          headers,
          signal,
        });

        if (!response.ok) {
          throw new Error(`SSE connection failed: ${response.status} ${response.statusText}`);
        }

        if (!response.body) {
          throw new Error("SSE connection failed: No body");
        }

        console.log("useSSE: Connected successfully");
        connectionAttempts = 0;

        // Notify connected
        const connectedHandlers = sharedHandlers.get("connected");
        if (connectedHandlers) {
          connectedHandlers.forEach(h => h({ status: "connected" }));
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop() || ""; // Keep incomplete chunk

          for (const block of lines) {
            const linesInBlock = block.split("\n");
            let eventType = "message";
            let data = "";

            for (const line of linesInBlock) {
              if (line.startsWith("event: ")) {
                eventType = line.substring(7).trim();
              } else if (line.startsWith("data: ")) {
                data = line.substring(6).trim();
              }
            }

            if (eventType && data) {
              const handlers = sharedHandlers.get(eventType);
              if (handlers) {
                try {
                  const parsedData = JSON.parse(data);
                  handlers.forEach(h => h(parsedData));
                } catch (e) {
                  handlers.forEach(h => h(data));
                }
              }
            }
          }
        }
      } catch (error: any) {
        if (signal.aborted) return;

        console.error("useSSE: Connection error", error);
        connectionAttempts++;

        if (connectionAttempts < MAX_RECONNECT_ATTEMPTS) {
          console.log(`useSSE: Reconnecting in ${connectionAttempts * 1000}ms...`);
          setTimeout(connectSSE, connectionAttempts * 1000); // Exponential backoff
        }
      }
    };

    connectSSE();

    // Cleanup: abort only if this component created the connection
    return () => {
      if (globalController === controller) {
        controller.abort();
        globalController = null;
      }
    };
  }, [configData, user_session?.accessToken, status]);

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
