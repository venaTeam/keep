"use client";

import { IncidentDto } from "@/entities/incidents/model";
import { useConfig } from "@/utils/hooks/useConfig";
import { CopilotKit } from "@copilotkit/react-core";
import dynamic from "next/dynamic";

const IncidentChat = dynamic(() => import("./incident-chat").then((mod) => mod.IncidentChat), {
  ssr: false,
  loading: () => <div className="h-full flex items-center justify-center">Loading Chat...</div>,
});

export function IncidentChatClientPage({
  incident,
  mutateIncident,
}: {
  incident: IncidentDto;
  mutateIncident: () => void;
}) {
  const { data: config } = useConfig();

  // If AI is not enabled, return null to collapse the chat section
  if (!config?.OPEN_AI_API_KEY_SET) {
    return null;
  }

  return (
    <CopilotKit showDevConsole={false} runtimeUrl="/api/copilotkit">
      <IncidentChat incident={incident} mutateIncident={mutateIncident} />
    </CopilotKit>
  );
}
