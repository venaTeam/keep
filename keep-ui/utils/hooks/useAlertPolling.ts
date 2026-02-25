import { useEffect } from "react";
import { useSSE } from "@/utils/hooks/useSSE";

export const useAlertPolling = (isEnabled: boolean, onEvent: (data?: any) => void) => {
  const { bind, unbind } = useSSE();

  useEffect(() => {
    if (!isEnabled) {
      return;
    }

    bind("poll-alerts", onEvent);
    return () => unbind("poll-alerts", onEvent);
  }, [isEnabled, bind, unbind, onEvent]);
};
