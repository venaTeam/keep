"use client";

import { getIncidentName } from "@/entities/incidents/lib/utils";
import {
  useIncident,
  useIncidentFutureIncidents,
} from "@/utils/hooks/useIncidents";
import type { IncidentDto } from "@/entities/incidents/model";
import { FieldHeader } from "@/shared/ui";
import { Link } from "@/components/ui";
import { StatusIcon } from "@/entities/incidents/ui/statuses";

function FollowingIncident({ incidentId }: { incidentId: string }) {
  const { data: incident } = useIncident(incidentId);

  if (!incident) {
    return null;
  }

  return (
    <div data-cy={`incidents-past-item-${incidentId}`} data-cy-id={incidentId}>
      <Link
        icon={() => <StatusIcon className="!p-0" status={incident.status} />}
        href={"/incidents/" + incidentId}
      >
        {getIncidentName(incident)}
      </Link>
    </div>
  );
}

export function FollowingIncidents({ incident }: { incident: IncidentDto }) {
  const { data: same_incidents_in_the_future } = useIncidentFutureIncidents(
    incident.id
  );

  if (
    !same_incidents_in_the_future ||
    same_incidents_in_the_future.items.length === 0
  ) {
    return null;
  }

  return (
    <>
      <FieldHeader>Following incidents</FieldHeader>
      <ul data-cy="incidents-following-list">
        {same_incidents_in_the_future.items.map((item) => (
          <li key={item.id} data-cy="incidents-following-item" data-cy-id={item.id}>
            <FollowingIncident incidentId={item.id} />
          </li>
        ))}
      </ul>
    </>
  );
}
