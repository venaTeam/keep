import { useRef } from "react";
import {
  Button,
  Tab,
  TabGroup,
  TabList,
  TabPanels,
  TabPanel,
} from "@tremor/react";
import { Popover } from "@headlessui/react";
import { FiSettings } from "react-icons/fi";
import { FloatingArrow, arrow, offset, useFloating } from "@floating-ui/react";
import { Table } from "@tanstack/table-core";
import { AlertDto } from "@/entities/alerts/model";
import ColumnSelection from "./ColumnSelection";
import { AlertTableThemeSelection } from "@/features/alerts/change-alert-table-theme";
import { RowStyleSelection } from "@/widgets/alerts-table/ui/RowStyleSelection";
import { ActionTraySelection } from "@/widgets/alerts-table/ui/ActionTraySelection";
import { FontSizeSelection } from "@/widgets/alerts-table/ui/FontSizeSelection";

interface SettingsSelectionProps {
  table: Table<AlertDto>;
  presetName: string;
  presetId?: string;
  onResetGrouping?: () => void;
  onResetFacets?: () => void;
}

export default function SettingsSelection({
  table,
  presetName,
  presetId,
  onResetGrouping,
  onResetFacets,
}: SettingsSelectionProps) {
  const arrowRef = useRef(null);
  const { refs, floatingStyles, context } = useFloating({
    strategy: "fixed",
    placement: "bottom-end",
    middleware: [
      offset({ mainAxis: 10 }),
      arrow({
        element: arrowRef,
      }),
    ],
  });

  return (
    <Popover as="div" className="flex items-center">
      {({ close }) => (
        <>
          <Popover.Button
            variant="light"
            color="gray"
            as={Button}
            icon={FiSettings}
            ref={refs.setReference}
            data-testid="settings-button"
            data-cy="settings-button"
            aria-label="Settings"
          />
          <Popover.Overlay className="fixed inset-0 bg-black opacity-30 z-20" />
          <Popover.Panel
            className="bg-white dark:bg-[#111827] z-[60] p-4 rounded-sm shadow-xl border border-gray-100 dark:border-gray-800 min-w-[300px] w-auto max-w-[600px] overflow-hidden"
            ref={refs.setFloating}
            data-testid="settings-panel"
            data-cy="settings-panel"
            style={{
              ...floatingStyles,
              maxHeight: "85vh", // Limit height to 85% of viewport height
              overflowY: "auto", // Add scroll when content exceeds max height
            }}
          >
            <FloatingArrow
              className="fill-white [&>path:last-of-type]:stroke-white"
              ref={arrowRef}
              context={context}
            />
            <div
              className="flex flex-col"
              style={{ maxHeight: "calc(80vh - 40px)" }}
            >
              <TabGroup className="flex flex-col flex-1 w-full max-w-full">
                <TabList className="mb-4 overflow-x-auto whitespace-nowrap overflow-y-hidden pb-1" variant="line">
                  <Tab data-testid="tab-columns" data-cy="tab-columns">Columns</Tab>
                  <Tab data-testid="tab-theme" data-cy="tab-theme">Theme</Tab>
                  <Tab data-testid="tab-row-style" data-cy="tab-row-style">Row Style</Tab>
                  <Tab data-testid="tab-action-tray" data-cy="tab-action-tray">Action Tray</Tab>
                  <Tab data-testid="tab-font-size" data-cy="tab-font-size">Font Size</Tab>
                </TabList>
                <TabPanels className="flex-1 overflow-hidden">
                  <TabPanel className="h-full" data-testid="panel-columns" data-cy="panel-columns">
                    <ColumnSelection
                      table={table}
                      presetName={presetName}
                      presetId={presetId}
                      onClose={close}
                      onResetGrouping={onResetGrouping}
                      onResetFacets={onResetFacets}
                    />
                  </TabPanel>
                  <TabPanel className="h-full" data-testid="panel-theme" data-cy="panel-theme">
                    <AlertTableThemeSelection onClose={close} />
                  </TabPanel>
                  <TabPanel className="h-full" data-testid="panel-row-style" data-cy="panel-row-style">
                    <RowStyleSelection onClose={close} />
                  </TabPanel>
                  <TabPanel className="h-full" data-testid="panel-action-tray" data-cy="panel-action-tray">
                    <ActionTraySelection onClose={close} />
                  </TabPanel>
                  <TabPanel className="h-full" data-testid="panel-font-size" data-cy="panel-font-size">
                    <FontSizeSelection onClose={close} />
                  </TabPanel>
                </TabPanels>
              </TabGroup>
            </div>
          </Popover.Panel>
        </>
      )}
    </Popover>
  );
}
