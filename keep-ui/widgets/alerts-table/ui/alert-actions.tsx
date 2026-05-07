import { Button } from "@tremor/react";
import { useState } from "react";
import { AlertDto } from "@/entities/alerts/model";
import { PlusIcon, RocketIcon } from "@radix-ui/react-icons";
import { toast } from "react-toastify";
import { useRouter, useSearchParams } from "next/navigation";
import { SilencedDoorbellNotification } from "@/components/icons";
import { AlertAssociateIncidentModal } from "@/features/alerts/alert-associate-to-incident";
import { CreateIncidentWithAIModal } from "@/features/alerts/alert-create-incident-ai";
import { useApi } from "@/shared/lib/hooks/useApi";
import { Table } from "@tanstack/react-table";

import { useRevalidateMultiple } from "@/shared/lib/state-utils";
import { useConfig } from "@/utils/hooks/useConfig";
import { XMarkIcon, BellIcon } from "@heroicons/react/24/outline";
import { ChevronDoubleRightIcon } from "@heroicons/react/24/solid";
import { AlertChangeStatusModal } from "@/features/alerts/alert-change-status/ui/alert-change-status-modal";
import { CreatePresetModal } from "./create-preset-modal";

interface Props {
  selectedAlertsFingerprints: string[];
  table: Table<AlertDto>;
  clearRowSelection: () => void;
  setDismissModalAlert?: (alert: AlertDto[] | null) => void;
  mutateAlerts?: () => void;
  setIsIncidentSelectorOpen: (open: boolean) => void;
  isIncidentSelectorOpen: boolean;
  setIsCreateIncidentWithAIOpen: (open: boolean) => void;
  isCreateIncidentWithAIOpen: boolean;
}

export default function AlertActions({
  selectedAlertsFingerprints,
  table,
  clearRowSelection,
  setDismissModalAlert,
  mutateAlerts,
  setIsIncidentSelectorOpen,
  isIncidentSelectorOpen,
  setIsCreateIncidentWithAIOpen,
  isCreateIncidentWithAIOpen,
}: Props) {
  const router = useRouter();
  const api = useApi();
  const { data: config } = useConfig();
  const revalidateMultiple = useRevalidateMultiple();
  const presetsMutator = () => revalidateMultiple(["/preset"]);
  const [modalAlert, setModalAlert] = useState<AlertDto | AlertDto[] | null>(null);
  const [isCreatePresetModalOpen, setIsCreatePresetModalOpen] = useState(false);

  // TODO: refactor
  const searchParams = useSearchParams();
  const createIncidentsFromLastAlerts = searchParams.get(
    "createIncidentsFromLastAlerts"
  );

  const selectedAlerts = table
    .getSelectedRowModel()
    .rows.map((row) => row.original);

  // Categorize alerts by dismissed status for showing appropriate actions
  const dismissedAlerts = selectedAlerts.filter((a) => a.dismissed);
  const activeAlerts = selectedAlerts.filter((a) => !a.dismissed);
  const hasDismissedAlerts = dismissedAlerts.length > 0;
  const hasActiveAlerts = activeAlerts.length > 0;

  async function addOrUpdatePreset(newPresetName: string) {
    if (newPresetName) {
      const distinctAlertNames = Array.from(
        new Set(selectedAlerts.map((alert) => alert.name))
      );
      const formattedCel = distinctAlertNames.reduce(
        (accumulator, currentValue, currentIndex) => {
          return (
            accumulator +
            (currentIndex > 0 ? " || " : "") +
            `name == "${currentValue}"`
          );
        },
        ""
      );
      const options = [{ value: formattedCel, label: "CEL" }];
      try {
        const response = await api.post(`/preset`, {
          name: newPresetName,
          options: options,
        });
        toast(`Preset ${newPresetName} created!`, {
          position: "top-left",
          type: "success",
        });
        presetsMutator();
        clearRowSelection();
        router.replace(`/alerts/${newPresetName}`);
      } catch (error) {
        toast(`Error creating preset ${newPresetName}`, {
          position: "top-left",
          type: "error",
        });
      }
    }
  }

  const showIncidentSelector = () => {
    setIsIncidentSelectorOpen(true);
  };
  const hideIncidentSelector = () => {
    setIsIncidentSelectorOpen(false);
  };

  const showCreateIncidentWithAI = () => {
    setIsCreateIncidentWithAIOpen(true);
  };
  const hideCreateIncidentWithAI = () => {
    setIsCreateIncidentWithAIOpen(false);
  };

  const handleSuccessfulAlertsAssociation = () => {
    hideIncidentSelector();
    clearRowSelection();
    if (mutateAlerts) {
      mutateAlerts();
    }
  };

  return (
    <div className="w-full flex gap-2.5 justify-end items-center" data-cy="alerts-actions">
      <Button
        icon={XMarkIcon}
        size="xs"
        color="slate"
        title="Clear Selection"
        onClick={clearRowSelection}
        data-cy="alerts-action-clear-selection-btn"
      >
        Clear Selection
      </Button>
      <Button
        icon={ChevronDoubleRightIcon}
        size="xs"
        color="blue"
        title="Resolve"
        onClick={() => {
          setModalAlert(selectedAlerts);
        }}
        data-cy="alerts-action-change-status-btn"
      >
        Change status of {selectedAlertsFingerprints.length} alert(s)
      </Button>
      {modalAlert && (
        <AlertChangeStatusModal
          alert={modalAlert}
          presetName="resolve"
          handleClose={() => setModalAlert(null)}
          onSuccess={clearRowSelection}
        />
      )}
      {/* Restore button - only show if there are dismissed alerts */}
      {hasDismissedAlerts && (
        <Button
          icon={BellIcon}
          size="xs"
          color="orange"
          title="Restore"
          onClick={() => setDismissModalAlert?.(dismissedAlerts)}
          data-cy="alerts-action-restore-btn"
        >
          Restore {dismissedAlerts.length} alert(s)
        </Button>
      )}
      {/* Dismiss button - only show if there are active (non-dismissed) alerts */}
      {hasActiveAlerts && (
        <Button
          icon={SilencedDoorbellNotification}
          size="xs"
          color="red"
          title="Dismiss"
          onClick={() => setDismissModalAlert?.(activeAlerts)}
          data-cy="alerts-action-dismiss-btn"
        >
          Dismiss {activeAlerts.length} alert(s)
        </Button>
      )}
      <Button
        icon={PlusIcon}
        size="xs"
        color="orange"
        onClick={() => setIsCreatePresetModalOpen(true)}
        tooltip="Save current filter as a view"
        data-cy="alerts-action-create-preset-btn"
      >
        Create Preset
      </Button>
      <Button
        icon={PlusIcon}
        size="xs"
        color="orange"
        onClick={showIncidentSelector}
        tooltip="Associate events with incident"
        data-cy="alerts-action-associate-incident-btn"
      >
        Associate with incident
      </Button>
      {config?.AI_FEATURES_ENABLED && (
        <Button
          icon={RocketIcon}
          size="xs"
          color="orange"
          onClick={showCreateIncidentWithAI}
          tooltip="Create incidents with AI"
          data-cy="alerts-action-create-incident-ai-btn"
        >
          Create incidents with AI
        </Button>
      )}
      <AlertAssociateIncidentModal
        isOpen={isIncidentSelectorOpen}
        alerts={selectedAlerts}
        handleSuccess={handleSuccessfulAlertsAssociation}
        handleClose={hideIncidentSelector}
      />
      <CreateIncidentWithAIModal
        isOpen={isCreateIncidentWithAIOpen}
        alerts={selectedAlerts}
        handleClose={hideCreateIncidentWithAI}
      />
      <CreatePresetModal
        isOpen={isCreatePresetModalOpen}
        handleClose={() => setIsCreatePresetModalOpen(false)}
        handleCreate={addOrUpdatePreset}
      />
    </div>
  );
}
