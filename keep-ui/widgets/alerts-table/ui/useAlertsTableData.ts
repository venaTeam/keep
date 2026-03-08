import { TimeFrameV2 } from "@/components/ui/DateRangePickerV2";
import { AlertDto, AlertsQuery, useAlerts } from "@/entities/alerts/model";
import { useAlertPolling } from "@/utils/hooks/useAlertPolling";
import { v4 as uuidv4 } from "uuid";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSWRConfig } from "swr";

export interface AlertsTableDataQuery {
  searchCel: string;
  filterCel: string;
  limit: number;
  offset: number;
  sortOptions?: { sortBy: string; sortDirection?: "ASC" | "DESC" }[];
  timeFrame: TimeFrameV2;
}

function getDateRangeCel(timeFrame: TimeFrameV2 | null): string | null {
  if (timeFrame === null) {
    return null;
  }

  if (timeFrame.type === "relative") {
    return `lastReceived >= '${new Date(
      new Date().getTime() - timeFrame.deltaMs
    ).toISOString()}'`;
  } else if (timeFrame.type === "absolute") {
    return [
      `lastReceived >= '${timeFrame.start.toISOString()}'`,
      `lastReceived <= '${timeFrame.end.toISOString()}'`,
    ].join(" && ");
  }

  return "";
}

export const useAlertsTableData = (query: AlertsTableDataQuery | undefined) => {
  const { useLastAlerts } = useAlerts();
  const { mutate: mutateGlobal } = useSWRConfig();

  const [canRevalidate, setCanRevalidate] = useState<boolean>(false);
  const [dateRangeCel, setDateRangeCel] = useState<string | null>(null);
  const [alertsQueryState, setAlertsQueryState] = useState<
    AlertsQuery | undefined
  >(undefined);
  const incidentsQueryStateRef = useRef(alertsQueryState);
  const [facetsPanelRefreshToken, setFacetsPanelRefreshToken] = useState<
    string | undefined
  >(undefined);
  incidentsQueryStateRef.current = alertsQueryState;
  const isDateRangeInit = useRef(false);

  const isPaused = useMemo(() => {
    if (!query) {
      return false;
    }

    switch (query.timeFrame.type) {
      case "absolute":
        return false;
      case "relative":
        return query.timeFrame.isPaused;
      case "all-time":
        return query.timeFrame.isPaused;
      default:
        return true;
    }
  }, [query]);

  useEffect(() => {
    if (canRevalidate) {
      return;
    }

    const timeout = setTimeout(() => {
      setCanRevalidate(true);
    }, 3000);
    return () => clearTimeout(timeout);
  }, [canRevalidate]);

  function updateAlertsCelDateRange() {
    if (!query?.timeFrame) {
      return;
    }

    const dateRangeCel = getDateRangeCel(query.timeFrame);

    setDateRangeCel(dateRangeCel);

    if (dateRangeCel) {
      return;
    }

    // if date does not change, just reload the data
    if (isDateRangeInit.current) {
      setFacetsPanelRefreshToken("REVALIDATE_" + uuidv4());
    }
    isDateRangeInit.current = true;
    mutateAlerts();
  }

  useEffect(() => updateAlertsCelDateRange(), [query?.timeFrame]);

  const mainCelQuery = useMemo(() => {
    if (!query || dateRangeCel === null) {
      return null;
    }

    const filterArray = [query?.searchCel, dateRangeCel];
    return filterArray
      .filter(Boolean)
      .map((cel) => `(${cel})`)
      .join(" && ");
  }, [query?.searchCel, dateRangeCel]);

  useEffect(() => {
    if (!query || mainCelQuery === null) {
      setAlertsQueryState(undefined);
      return;
    }

    const filterCel = query.filterCel ? `(${query.filterCel})` : "";
    const alertsQuery: AlertsQuery = {
      limit: query.limit,
      offset: query.offset,
      sortOptions: query.sortOptions,
      cel: [mainCelQuery, filterCel].filter(Boolean).join(" && "),
    };

    setAlertsQueryState(alertsQuery);
  }, [
    mainCelQuery,
    query?.filterCel,
    query?.sortOptions,
    query?.limit,
    query?.offset,
  ]);

  const {
    data: alerts,
    totalCount,
    isLoading: alertsLoading,
    mutate: mutateAlerts,
    error: alertsError,
    queryTimeInSeconds,
  } = useLastAlerts(alertsQueryState, {
    revalidateOnFocus: false,
    revalidateOnMount: true,
  });

  const fetchTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Simple alert polling - append incoming SSE events to the local cache
  useAlertPolling(!isPaused, (data) => {
    // MUST wait for DB to load first.
    // `alertsLoading` from useLastAlerts is computed as:
    //   swrValue.isLoading || !swrValue.data?.queryResult
    // This is reliable because it stays true until the DB query actually returns.
    if (alertsLoading) {
      return;
    }

    if (data?.alerts && Array.isArray(data.alerts)) {
      // Check if we're on the first page by looking at the query offset
      const isFirstPage = !query?.offset || query.offset === 0;
      const hasActiveFilters = Boolean(query?.searchCel || query?.filterCel);

      if (isFirstPage && !hasActiveFilters) {
        // Page 1 with NO filters: prepend SSE alerts locally, no DB re-fetch needed
        mutateAlerts((currentData: any) => {
          if (!currentData?.queryResult) return currentData;

          const currentResults = currentData.queryResult.results || [];
          const currentCount = currentData.queryResult.count || 0;

          const incomingFingerprints = new Set(
            data.alerts.map((a: any) => a.fingerprint)
          );
          const dedupedResults = currentResults.filter(
            (existing: any) => !incomingFingerprints.has(existing.fingerprint)
          );

          const existingFingerprints = new Set(
            currentResults.map((a: any) => a.fingerprint)
          );

          const newAlertsList = data.alerts.filter(
            (a: any) => !existingFingerprints.has(a.fingerprint)
          );
          const newAlertCount = newAlertsList.length;

          // Optimistically update the Facet Panel counts in SWR cache without fetching
          if (newAlertCount > 0) {
            mutateGlobal(
              (key) => typeof key === "string" && key.startsWith("/alerts/facets/options"),
              (currentFacetCache: any) => {
                if (!currentFacetCache?.response) return currentFacetCache;
                const newResponse = JSON.parse(JSON.stringify(currentFacetCache.response));

                newAlertsList.forEach((alert: any) => {
                  // increment severity
                  if (alert.severity && newResponse['severity']) {
                    const opt = newResponse['severity'].find((o: any) => o.value === alert.severity);
                    if (opt) opt.matches_count += 1;
                    else newResponse['severity'].push({ display_name: alert.severity, value: alert.severity, matches_count: 1 });
                  }
                  // increment status
                  if (alert.status && newResponse['status']) {
                    const opt = newResponse['status'].find((o: any) => o.value === alert.status);
                    if (opt) opt.matches_count += 1;
                    else newResponse['status'].push({ display_name: alert.status, value: alert.status, matches_count: 1 });
                  }
                  // increment source
                  if (Array.isArray(alert.source) && newResponse['source']) {
                    alert.source.forEach((src: string) => {
                      const opt = newResponse['source'].find((o: any) => o.value === src);
                      if (opt) opt.matches_count += 1;
                      else newResponse['source'].push({ display_name: src, value: src, matches_count: 1 });
                    });
                  }
                });
                return { ...currentFacetCache, response: newResponse };
              },
              { revalidate: false }
            );
          }

          const pageLimit = currentData.queryResult.limit || currentResults.length;
          const merged = [...data.alerts, ...dedupedResults].slice(0, pageLimit);

          return {
            ...currentData,
            queryResult: {
              ...currentData.queryResult,
              results: merged,
              count: currentCount + newAlertCount,
            },
          };
        }, { revalidate: false });
      } else {
        // Page 2+ OR filtered view (Presets): 
        // We cannot reliably inject the alert without evaluating the CEL filter.
        // Instead, debounce a DB re-fetch. This ensures accurate pagination and filter matching
        // without overloading the PostgreSQL database during an alert storm.
        if (fetchTimeoutRef.current) {
          clearTimeout(fetchTimeoutRef.current);
        }
        fetchTimeoutRef.current = setTimeout(() => {
          mutateAlerts();
        }, 800);
      }
    }
  });

  const [alertsToReturn, setAlertsToReturn] = useState<
    AlertDto[] | undefined
  >();
  useEffect(() => {
    if (!alerts) {
      return;
    }

    if (!isPaused) {
      if (!alertsLoading) {
        setAlertsToReturn(alerts);
      }

      return;
    }

    setAlertsToReturn(alertsLoading ? undefined : alerts);
  }, [isPaused, alertsLoading, alerts]);

  return {
    alerts: alertsToReturn,
    totalCount,
    alertsLoading: alertsLoading,
    facetsCel: mainCelQuery,
    alertsError: alertsError,
    mutateAlerts,
    facetsPanelRefreshToken,
  };
};
