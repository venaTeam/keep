import { useCallback, useEffect, useRef } from "react";
import { useSSE } from "@/utils/hooks/useSSE";
import { useSWRConfig } from "swr";

const PRESET_POLLING_INTERVAL = 3 * 1000; // Once per 3 seconds

export function usePresetPolling() {
  const { bind, unbind } = useSSE();
  const { mutate } = useSWRConfig();
  const lastPollTimeRef = useRef(0);

  const handleIncoming = useCallback(
    (presetNamesToUpdate: string[]) => {
      const currentTime = Date.now();
      const timeSinceLastPoll = currentTime - lastPollTimeRef.current;

      if (timeSinceLastPoll < PRESET_POLLING_INTERVAL) {
        return;
      }

      lastPollTimeRef.current = currentTime;
      // Revalidate preset definitions AND preset count queries (limit=0) only.
      // We deliberately exclude the main table query (which has limit>0)
      // to avoid flooding the API with heavy re-fetches under load.
      mutate(
        (key) =>
          typeof key === "string" &&
          (key.startsWith("/preset") ||
            (key.startsWith("/alerts/query") && key.includes("limit=0")))
      );
    },
    [mutate]
  );

  useEffect(() => {
    bind("poll-presets", handleIncoming);
    return () => {
      unbind("poll-presets", handleIncoming);
    };
  }, [bind, unbind, handleIncoming]);
}
