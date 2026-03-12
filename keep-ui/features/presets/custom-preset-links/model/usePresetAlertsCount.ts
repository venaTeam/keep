import { useAlerts } from "@/entities/alerts/model/useAlerts";
import { useEffect } from "react";

export const usePresetAlertsCount = (
  presetCel: string,
  counterShowsFiringOnly: boolean,
  limit = 0,
  offset = 0,
  refreshInterval: number | undefined = undefined,
  enabled: boolean = true
) => {
  const { useLastAlerts } = useAlerts();

  const celList = [];

  if (counterShowsFiringOnly) {
    celList.push("status == 'firing'");
  }

  celList.push(presetCel);

  const query = enabled
    ? {
        cel: celList
          .filter((cel) => !!cel)
          .map((cel) => `(${cel})`)
          .join(" && "),
        limit: limit,
        offset: offset,
      }
    : undefined;

  const { data, totalCount, isLoading, mutate } = useLastAlerts(query);

  useEffect(() => {
    if (!refreshInterval) {
      return;
    }

    const intervalId = setInterval(() => mutate(), refreshInterval);
    return () => clearInterval(intervalId);
  }, [refreshInterval]);

  return { alerts: data, totalCount, isLoading };
};
