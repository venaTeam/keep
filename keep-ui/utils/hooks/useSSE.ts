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
let globalToken: string | undefined = undefined; // track which token the connection uses
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

    const currentToken = session?.accessToken;

    // If a global connection already exists with the SAME token, skip.
    // But if the token changed (e.g. refresh in production), tear down
    // the old connection and reconnect with the new token.
    if (globalController) {
      if (globalToken === currentToken) {
        return; // same token, connection is fine
      }
      // Token changed — kill old connection so we reconnect below
      console.log("useSSE: Token changed, reconnecting with new token");
      globalController.abort();
      globalController = null;
      globalToken = undefined;
      connectionAttempts = 0;
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
    globalToken = currentToken;

    const connectSSE = async () => {
      try {
        console.log("useSSE: Connecting via fetch...");

        const headers: HeadersInit = {
          "Accept": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        };

        // Logic from ApiClient.ts getHeaders()
        if (currentToken && currentToken !== "unauthenticated") {
          headers["Authorization"] = `Bearer ${currentToken}`;
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

        // Stream ended (server closed it, e.g. timeout or deploy).
        // Reconnect unless we were intentionally aborted.
        if (!signal.aborted) {
          console.log("useSSE: Stream ended by server, reconnecting...");
          globalController = null;
          globalToken = undefined;
          connectionAttempts++;
          if (connectionAttempts < MAX_RECONNECT_ATTEMPTS) {
            setTimeout(connectSSE, connectionAttempts * 1000);
          }
        }
      } catch (error: any) {
        if (signal.aborted) return;

        console.error("useSSE: Connection error", error);
        globalController = null;
        globalToken = undefined;
        connectionAttempts++;

        if (connectionAttempts < MAX_RECONNECT_ATTEMPTS) {
          console.log(`useSSE: Reconnecting in ${connectionAttempts * 1000}ms...`);
          setTimeout(connectSSE, connectionAttempts * 1000);
        }
      }
    };

    connectSSE();

    // No cleanup on unmount — the connection is global and must persist
    // across component mounts/unmounts. The connection is only torn down
    // when the token changes (handled above) or the server closes it.
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
