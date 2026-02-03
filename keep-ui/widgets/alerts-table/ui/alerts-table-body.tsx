import { TableBody, TableRow, TableCell } from "@tremor/react";
import { AlertDto } from "@/entities/alerts/model";
import { Table, flexRender } from "@tanstack/react-table";
import React, { useRef, useEffect } from "react";
import { GroupedRow } from "@/widgets/alerts-table/ui/alert-grouped-row";
import { useAlertRowStyle } from "@/entities/alerts/model/useAlertRowStyle";
import { getCommonPinningStylesAndClassNames } from "@/shared/ui";
import {
  getRowClassName,
  getCellClassName,
} from "@/widgets/alerts-table/lib/alert-table-utils";
import { useExpandedRows } from "@/utils/hooks/useExpandedRows";
import { useGroupExpansion } from "@/utils/hooks/useGroupExpansion";
import clsx from "clsx";
import "react-loading-skeleton/dist/skeleton.css";
import { SelectableGroup } from "react-selectable-fast";
import { SelectableRow } from "./selectable-row";

interface Props {
  table: Table<AlertDto>;
  showSkeleton: boolean;
  pageSize?: number;
  theme: { [key: string]: string };
  onRowClick: (alert: AlertDto) => void;
  lastViewedAlert: string | null;
  presetName: string;
  groupExpansionState?: ReturnType<typeof useGroupExpansion>;
}

export function AlertsTableBody({
  table,
  showSkeleton,
  theme,
  onRowClick,
  lastViewedAlert,
  presetName,
  pageSize,
  groupExpansionState,
}: Props) {
  const [rowStyle] = useAlertRowStyle();
  const { isRowExpanded } = useExpandedRows(presetName);

  // Use provided groupExpansionState or create a local one
  const localGroupExpansion = useGroupExpansion(true);
  const { isGroupExpanded, toggleGroup, initializeGroup } = groupExpansionState || localGroupExpansion;

  // Use any here because the type definition for SelectableGroup might be tricky or missing specific methods in TS
  const selectableGroupRef = useRef<any>(null);

  // Sync external selection changes (e.g. unselect all from header) with the selectable group
  const isClearingRef = useRef(false);
  useEffect(() => {
    // If the table selection is empty, we should clear the selectable group selection
    // exact equality to empty object check
    if (
      Object.keys(table.getState().rowSelection).length === 0 &&
      selectableGroupRef.current
    ) {
      isClearingRef.current = true;
      selectableGroupRef.current.clearSelection();
      // Reset the flag after a short delay to allow the clearSelection callback (if any) to process
      setTimeout(() => {
        isClearingRef.current = false;
      }, 0);
    }
  }, [table.getState().rowSelection]);

  const handleSelectionFinish = (selectedItems: any[]) => {
    if (isClearingRef.current) return;

    const newSelection: Record<string, boolean> = {};
    selectedItems.forEach((item) => {
      // react-selectable-fast returns the component instances.
      // We attach data-row-id prop to SelectableRow to identify them.
      const id = item.props['data-row-id'];
      if (id) newSelection[id] = true;
    });

    // Check if selection actually changed to avoid unnecessary updates
    const currentSelection = table.getState().rowSelection;
    const isSame =
      Object.keys(currentSelection).length === Object.keys(newSelection).length &&
      Object.keys(newSelection).every(key => currentSelection[key]);

    if (!isSame) {
      table.setRowSelection(newSelection);
    }
  };

  const handleRowClick = (e: React.MouseEvent, alert: AlertDto) => {
    // Only prevent clicks on specific interactive elements
    const target = e.target as HTMLElement;
    const clickableElements = target.closest(
      'button, .menu, input, a, [role="button"], .prevent-row-click, .tremor-Select-root, .tremor-MultiSelect-root'
    );

    // Check if the click is on a menu or if the element is marked as clickable
    if (clickableElements || target.classList.contains("menu-open")) {
      return;
    }

    onRowClick(alert);
  };

  if (showSkeleton) {
    return (
      <TableBody>
        {Array.from({ length: pageSize || 20 }).map((_, index) => (
          <TableRow
            key={index}
            className={getRowClassName(
              { id: index.toString(), original: {} as AlertDto },
              theme,
              lastViewedAlert,
              rowStyle
            )}
          >
            {Array.from({ length: 7 }).map((_, cellIndex) => (
              <TableCell
                key={cellIndex}
                className={getCellClassName(
                  {
                    column: {
                      id: cellIndex.toString(),
                      columnDef: { meta: { tdClassName: "" } },
                    },
                  },
                  "",
                  rowStyle,
                  false
                )}
              >
                <div className="h-4 bg-gray-200 rounded animate-pulse mx-0.5" />
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    );
  }

  // This trick handles cases when rows have duplicated ids
  // It shouldn't happen, but the API currently returns duplicated ids
  // And in order to mitigate this issue, we append the rowIndex to the key for duplicated keys
  const visitedIds = new Set<string>();

  return (
    <TableBody>
      {/* @ts-ignore */}
      <SelectableGroup
        ref={selectableGroupRef}
        className="contents"
        clickClassName="tick"
        enableDeselect
        tolerance={0}
        globalMouse={true}
        allowClickWithoutSelected={false}
        onSelectionFinish={handleSelectionFinish}
      >
        {table.getExpandedRowModel().rows.map((row, rowIndex) => {
          let renderingKey = row.id;

          if (visitedIds.has(renderingKey)) {
            renderingKey = `${renderingKey}-${rowIndex}`;
          } else {
            visitedIds.add(renderingKey);
          }

          if (row.getIsGrouped()) {
            return (
              <GroupedRow
                key={renderingKey}
                row={row}
                table={table}
                theme={theme}
                onRowClick={handleRowClick}
                lastViewedAlert={lastViewedAlert}
                rowStyle={rowStyle}
                isExpanded={isGroupExpanded(row.id)}
                onToggleExpanded={toggleGroup}
                onGroupInitialized={initializeGroup}
              />
            );
          }

          const isLastViewed = row.original.fingerprint === lastViewedAlert;
          const expanded = isRowExpanded(row.original.fingerprint);

          return (
            <SelectableRow
              key={renderingKey}
              className={clsx(
                "group/row",
                // Using tailwind classes for expanded rows instead of a custom class
                expanded ? "!h-auto min-h-12" : null,
                getRowClassName(row, theme, lastViewedAlert, rowStyle, expanded)
              )}
              onClick={(e) => handleRowClick(e, row.original)}
              isSelected={row.getIsSelected()}
              data-row-id={row.id}
            >
              {row.getVisibleCells().map((cell) => {
                const { style, className } = getCommonPinningStylesAndClassNames(
                  cell.column,
                  table.getState().columnPinning.left?.length,
                  table.getState().columnPinning.right?.length
                );

                const isNameCell = cell.column.id === "name";
                const isDescriptionCell = cell.column.id === "description";
                const isSourceCell = cell.column.id === "source";
                const expanded = isRowExpanded(row.original.fingerprint);

                return (
                  <TableCell
                    key={cell.id}
                    data-column-id={cell.column.id}
                    className={clsx(
                      getCellClassName(
                        cell,
                        className,
                        rowStyle,
                        isLastViewed,
                        expanded
                      ),
                      // Force padding when expanded but not for source column
                      expanded && !isSourceCell ? "!p-2" : null,
                      // Source cell needs specific treatment when expanded
                      expanded && isSourceCell
                        ? "!p-1 !w-8 !min-w-8 !max-w-8"
                        : null,
                      // Name cell specific classes when expanded
                      expanded && isNameCell
                        ? "!max-w-[180px] w-[180px] !overflow-hidden"
                        : null,
                      // Description cell specific classes when expanded
                      expanded && isDescriptionCell
                        ? "!whitespace-pre-wrap !break-words w-auto"
                        : null
                    )}
                    style={{
                      ...style,
                      // For source cells, enforce fixed width always
                      ...(isSourceCell
                        ? {
                          width: "32px",
                          minWidth: "32px",
                          maxWidth: "32px",
                          padding: 0,
                        }
                        : {}),
                      // For name cells when expanded, use strict fixed width
                      ...(expanded && isNameCell
                        ? {
                          width: "180px",
                          maxWidth: "180px",
                          minWidth: "180px",
                          overflow: "hidden",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                        }
                        : {}),
                      // For description cells when expanded
                      ...(expanded && isDescriptionCell
                        ? {
                          width: "auto",
                          minWidth: "200px",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                          overflow: "visible",
                        }
                        : {}),
                    }}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                );
              })}
            </SelectableRow>
          );
        })}
      </SelectableGroup>
    </TableBody>
  );
}
