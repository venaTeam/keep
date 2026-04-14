"use client";

import { ReactNode } from "react";
import { IncidentDto } from "@/entities/incidents/model";
import { IncidentChatClientPage } from "./chat/page.client";
import { useIncident } from "@/utils/hooks/useIncidents";
import { IncidentHeader } from "./incident-header";
import { IncidentTabsNavigation } from "./incident-tabs-navigation";
import ResizableColumns from "@/components/ui/ResizableColumns";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { reportPageLoadLatency } from "@/utils/rum-utils";

export function IncidentLayoutClient({
  children,
  initialIncident,
  AIEnabled,
}: {
  children: ReactNode;
  initialIncident: IncidentDto;
  AIEnabled: boolean;
}) {
  const { data: incident, mutate } = useIncident(initialIncident.id, {
    fallbackData: initialIncident,
  });

  const pathname = usePathname();
  const [loadStartTime] = useState(performance.now());
  const [metricReported, setMetricReported] = useState(false);

  useEffect(() => {
    // Incident page is considered loaded when we have the incident data
    if (!metricReported && incident) {
      reportPageLoadLatency("incident", performance.now() - loadStartTime, pathname, {
        incident_id: initialIncident.id
      });
      setMetricReported(true);
    }
  }, [incident, metricReported, loadStartTime, pathname, initialIncident.id]);

  if (!incident) {
    return null;
  }

  return (
    <div className="flex flex-col h-fit overflow-hidden">
      <IncidentHeader incident={incident} />
      <IncidentTabsNavigation />
      {AIEnabled ? (
        <ResizableColumns
          leftChild={
            <div className="pr-2">
              <div className="flex-1 min-w-0">{children}</div>
            </div>
          }
          rightChild={
            <div className="pl-2">
              <IncidentChatClientPage
                mutateIncident={mutate}
                incident={incident}
              />
            </div>
          }
          initialLeftWidth={65}
        />
      ) : (
        // Adding padding to avoid cutting off card border and shadow
        <div className="flex-1 min-w-0 py-2 p-px">{children}</div>
      )}
    </div>
  );
}
