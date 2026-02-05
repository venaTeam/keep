/**
 * Server-Sent Events (SSE) hook for real-time notifications.
 *
 * This hook provides a replacement for the Pusher/WebSocket real-time
 * communication, using browser-native EventSource for SSE.
 */

import { useCallback, useEffect, useRef } from "react";
import { useConfig } from "./useConfig";
import { useHydratedSession as useSession } from "@/shared/lib/hooks/useHydratedSession";

// Shared EventSource instance and handlers across all hook instances
let sharedEventSource: EventSource | null = null;
let sharedHandlers: Map<string, Set<(data: any) => void>> = new Map();
let connectionAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY_MS = 3000;

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
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:useEffect',message:'SSE useEffect triggered',data:{apiUrl:configData?.API_URL,configData:configData?'loaded':'null',sessionExists:!!session,isInitialized:isInitializedRef.current,sharedEventSourceExists:!!sharedEventSource},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'C,D'})}).catch(()=>{});
    // #endregion

    // Prevent multiple initializations
    if (isInitializedRef.current) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:earlyReturn1',message:'Already initialized, returning early',data:{},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'E'})}).catch(()=>{});
      // #endregion
      return;
    }

    // Check if SSE is disabled (using PUSHER_DISABLED for backward compatibility)
    if (configData?.PUSHER_DISABLED === true) {
      console.log("useSSE: Real-time notifications disabled");
      return;
    }

    // Don't connect if we don't have config yet
    if (configData === null || configData === undefined) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:earlyReturn2',message:'Config not ready, returning early',data:{configData},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'D'})}).catch(()=>{});
      // #endregion
      return;
    }

    // Check if we already have a connection
    if (sharedEventSource !== null && sharedEventSource.readyState !== EventSource.CLOSED) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:earlyReturn3',message:'EventSource already exists',data:{readyState:sharedEventSource?.readyState},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'E'})}).catch(()=>{});
      // #endregion
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

    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:beforeCreate',message:'About to create EventSource',data:{sseUrl,sseBaseUrl,hasToken:!!session?.accessToken},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'A,C'})}).catch(()=>{});
    // #endregion

    console.log("useSSE: Creating new EventSource connection");

    try {
      sharedEventSource = new EventSource(sseUrl);

      sharedEventSource.onopen = () => {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:onopen',message:'EventSource connection opened',data:{readyState:sharedEventSource?.readyState},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'A'})}).catch(()=>{});
        // #endregion
        console.log("useSSE: Connection opened successfully");
        connectionAttempts = 0;
      };

      sharedEventSource.onerror = (error) => {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/8c802fa3-a512-4e69-abbd-05224549bef4',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'useSSE.ts:onerror',message:'EventSource error occurred',data:{errorType:error?.type,readyState:sharedEventSource?.readyState,connectionAttempts},timestamp:Date.now(),sessionId:'debug-session',hypothesisId:'A,B'})}).catch(()=>{});
        // #endregion
        console.error("useSSE: Connection error:", error);

        // EventSource will auto-reconnect, but we track attempts
        if (sharedEventSource?.readyState === EventSource.CLOSED) {
          connectionAttempts++;
          if (connectionAttempts < MAX_RECONNECT_ATTEMPTS) {
            console.log(
              `useSSE: Connection closed, will retry (attempt ${connectionAttempts}/${MAX_RECONNECT_ATTEMPTS})`
            );
          } else {
            console.error("useSSE: Max reconnection attempts reached");
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
              console.log(`useSSE: Received event '${eventType}':`, data);
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
              console.log(
                `useSSE: Received non-JSON event '${eventType}':`,
                event.data
              );
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
    console.log(`useSSE: Binding to event '${event}'`);

    if (!sharedHandlers.has(event)) {
      sharedHandlers.set(event, new Set());
    }

    sharedHandlers.get(event)!.add(callback);
  }, []);

  // Unbind a callback from an event
  const unbind = useCallback((event: string, callback: (data: any) => void) => {
    console.log(`useSSE: Unbinding from event '${event}'`);

    const handlers = sharedHandlers.get(event);
    if (handlers) {
      handlers.delete(callback);
      if (handlers.size === 0) {
        sharedHandlers.delete(event);
      }
    }
  }, []);

  // These are kept for API compatibility but are no-ops for SSE
  const subscribe = useCallback(() => {
    console.log("useSSE: subscribe() called (no-op for SSE)");
    return undefined;
  }, []);

  const unsubscribe = useCallback(() => {
    console.log("useSSE: unsubscribe() called (no-op for SSE)");
    return undefined;
  }, []);

  const trigger = useCallback((event: string, data: any) => {
    console.log(
      `useSSE: trigger() called (no-op for SSE - use REST API instead)`,
      { event, data }
    );
    return undefined;
  }, []);

  const channel = useCallback(() => {
    console.log("useSSE: channel() called (no-op for SSE)");
    return undefined;
  }, []);

  return {
    subscribe,
    unsubscribe,
    bind,
    unbind,
    trigger,
    channel,
  };
};

// Export with the same name as the old hook for easier migration
export const useWebsocket = useSSE;
