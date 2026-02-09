import { useEffect } from "react";
import { useWebsocket } from "@/utils/hooks/useSSE";

export const useAlertPolling = (isEnabled: boolean, onEvent: (data?: any) => void) => {
  const { bind, unbind } = useWebsocket();

  useEffect(() => {
    if (!isEnabled) {
      return;
    }

    bind("poll-alerts", onEvent);
    return () => unbind("poll-alerts", onEvent);
  }, [isEnabled, bind, unbind, onEvent]);
};
