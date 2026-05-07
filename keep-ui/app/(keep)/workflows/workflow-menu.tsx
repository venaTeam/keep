import { EllipsisHorizontalIcon } from "@heroicons/react/20/solid";
import {
  EyeIcon,
  PlayIcon,
  TrashIcon,
  WrenchIcon,
  PauseIcon,
  PlayCircleIcon,
} from "@heroicons/react/24/outline";
import { DownloadIcon } from "@radix-ui/react-icons";
import React from "react";
import { DropdownMenu } from "@/shared/ui";

interface WorkflowMenuProps {
  onDelete?: () => Promise<void>;
  onRun?: () => void;
  onView?: () => void;
  onDownload?: () => void;
  onBuilder?: () => void;
  onToggleState?: () => Promise<void>;
  isRunButtonDisabled: boolean;
  runButtonToolTip?: string;
  provisioned?: boolean;
  isDisabled?: boolean;
}

export default function WorkflowMenu({
  onDelete,
  onRun,
  onView,
  onDownload,
  onBuilder,
  onToggleState,
  isRunButtonDisabled,
  runButtonToolTip,
  provisioned,
  isDisabled,
}: WorkflowMenuProps) {
  return (
    <div className="js-dont-propagate" data-testid="workflow-menu" data-cy="workflow-menu">
      <DropdownMenu.Menu icon={EllipsisHorizontalIcon} label="" data-cy="wf-menu-trigger" listDataCy="wf-menu-list">
        <DropdownMenu.Item
          icon={PlayIcon}
          label="Run workflow"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onRun?.();
          }}
          title={runButtonToolTip}
          disabled={isRunButtonDisabled}
          data-cy="wf-menu-run-btn"
        />
        <DropdownMenu.Item
          icon={DownloadIcon}
          label="Download"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onDownload?.();
          }}
          data-cy="wf-menu-download-btn"
        />
        <DropdownMenu.Item
          icon={EyeIcon}
          label="Last executions"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onView?.();
          }}
          data-cy="wf-menu-view-btn"
        />
        <DropdownMenu.Item
          icon={WrenchIcon}
          label="Open in builder"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onBuilder?.();
          }}
          data-cy="wf-menu-builder-btn"
        />
        <DropdownMenu.Item
          icon={isDisabled ? PlayCircleIcon : PauseIcon}
          label={isDisabled ? "Enable workflow" : "Disable workflow"}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onToggleState?.();
          }}
          disabled={provisioned}
          title={provisioned ? "Cannot modify a provisioned workflow" : ""}
          data-cy="wf-menu-toggle-btn"
        />
        <DropdownMenu.Item
          icon={TrashIcon}
          label="Delete"
          variant="destructive"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onDelete?.();
          }}
          disabled={provisioned}
          title={provisioned ? "Cannot delete a provisioned workflow" : ""}
          data-testid="wf-menu-delete-button"
          data-cy="wf-menu-delete-btn"
        />
      </DropdownMenu.Menu>
    </div>
  );
}
