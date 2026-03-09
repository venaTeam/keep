import { useCallback, useEffect, useRef } from "react";
import { useSSE } from "@/utils/hooks/useSSE";
import { useSWRConfig } from "swr";

const PRESET_POLLING_INTERVAL = 5 * 1000; // Once per 5 seconds

export function usePresetPolling() {
  const { bind, unbind } = useSSE();
  const { mutate } = useSWRConfig();
  const lastPollTimeRef = useRef(0);

  const handleIncoming = useCallback(
    (presetNamesToUpdate: string[]) => {
      // Disabled per user request: only pull presets on refresh
      return;
      const currentTime = Date.now();
      const timeSinceLastPoll = currentTime - lastPollTimeRef.current;

      if (timeSinceLastPoll < PRESET_POLLING_INTERVAL) {
        console.log("usePresetPolling: Ignoring poll due to short interval");
        return;
      }

      console.log("usePresetPolling: Revalidating preset data");
      lastPollTimeRef.current = currentTime;

      mutate(
        (key) =>
          typeof key === "string" && key.startsWith("/preset")
      );
    },
    [mutate]
  );

  useEffect(() => {
    console.log(
      "usePresetPolling: Setting up event listener for 'poll-presets'"
    );
    bind("poll-presets", handleIncoming);
    return () => {
      console.log(
        "usePresetPolling: Cleaning up event listener for 'poll-presets'"
      );
      unbind("poll-presets", handleIncoming);
    };
  }, [bind, unbind, handleIncoming]);
}
