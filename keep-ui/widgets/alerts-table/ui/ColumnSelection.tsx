import React, { FormEvent, useState, useMemo } from "react";
import { Table } from "@tanstack/table-core";
import { Button, TextInput } from "@tremor/react";
import { VisibilityState } from "@tanstack/react-table";
import { FiSearch, FiRotateCcw } from "react-icons/fi";
import { AlertDto } from "@/entities/alerts/model";
import { usePresetColumnState } from "@/entities/presets/model";
import {
  DEFAULT_COLS,
  DEFAULT_COLS_VISIBILITY,
} from "@/widgets/alerts-table/lib/alert-table-utils";

interface AlertColumnsSelectProps {
  table: Table<AlertDto>;
  presetName: string;
  presetId?: string;
  onClose?: () => void;
  onResetGrouping?: () => void;
  onResetFacets?: () => void;
}

export default function ColumnSelection({
  table,
  presetName,
  presetId,
  onClose,
  onResetGrouping,
  onResetFacets,
}: AlertColumnsSelectProps) {
  const tableColumns = table.getAllColumns();

  // Use the unified column state hook - it will automatically determine
  // whether to use backend or local storage based on preset type
  const {
    columnVisibility,
    columnOrder,
    updateMultipleColumnConfigs,
    isLoading,
    useBackend,
  } = usePresetColumnState({
    presetName,
    presetId,
    useBackend: !!presetId, // Try to use backend if preset ID is available
  });

  const [searchTerm, setSearchTerm] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  // Local state to track checkbox changes before submission
  const [localColumnVisibility, setLocalColumnVisibility] =
    useState<VisibilityState>(columnVisibility);

  // Use a ref to track the previous columnVisibility to prevent infinite loops
  const prevColumnVisibilityRef = React.useRef<VisibilityState>(columnVisibility);

  // Detect if user has customized beyond defaults
  const isCustomized = useMemo(() => {
    const visKeys = Object.keys(columnVisibility);
    const defaultKeys = Object.keys(DEFAULT_COLS_VISIBILITY);
    if (visKeys.length !== defaultKeys.length) return true;
    for (const key of visKeys) {
      if (columnVisibility[key] !== DEFAULT_COLS_VISIBILITY[key]) return true;
    }
    if (JSON.stringify(columnOrder) !== JSON.stringify(DEFAULT_COLS)) return true;
    return false;
  }, [columnVisibility, columnOrder]);

  // Update local state when backend state changes
  React.useEffect(() => {
    // Only update if the columnVisibility has actually changed
    if (JSON.stringify(prevColumnVisibilityRef.current) !== JSON.stringify(columnVisibility)) {
      setLocalColumnVisibility(columnVisibility);
      prevColumnVisibilityRef.current = columnVisibility;
    }
  }, [columnVisibility, presetName]);

  // Common enrichment fields that should always be available for selection
  const COMMON_ENRICHMENT_FIELDS = [
    'ticket_id',
    'ticket_url',
    'ticket_type',
    'ticket_status',
    'environment',
    'service',
    'region',
    'cluster',
    'namespace',
    'pod',
    'container',
    'host',
    'instance',
    'application',
    'team',
    'owner',
    'runbook_url',
    'dashboard_url',
    'logs_url',
    'metrics_url',
    'impacted_customer_name',
    'severity_override',
    'priority',
    'escalation_policy',
    'on_call_engineer',
    'alert_enrichment',
  ];

  const columnsOptions = [
    // Include columns from table data
    ...tableColumns
      .filter((col) => col.getIsPinned() === false)
      .map((col) => col.id),
    // Include common enrichment fields that might not be in current data
    ...COMMON_ENRICHMENT_FIELDS.filter(field =>
      !tableColumns.some(col => col.id === field)
    )
  ];

  const filteredColumns = React.useMemo(() => {
    return columnsOptions.filter((column) =>
      column.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [columnsOptions, searchTerm]);

  // Handle search state - only set to false when search finishes
  React.useEffect(() => {
    if (isSearching) {
      setIsSearching(false);
    }
  }, [filteredColumns, isSearching]); // Only run when we're currently searching



  const handleSearchChange = (value: string) => {
    if (value) {
      setIsSearching(true);
    }
    setSearchTerm(value);
  };

  const handleResetToDefault = async () => {
    try {
      await updateMultipleColumnConfigs({
        columnVisibility: DEFAULT_COLS_VISIBILITY,
        columnOrder: DEFAULT_COLS,
        columnRenameMapping: {},
        columnTimeFormats: {},
        columnListFormats: {},
      });
      setLocalColumnVisibility(DEFAULT_COLS_VISIBILITY);
      // Also reset grouping and facets if callbacks provided
      onResetGrouping?.();
      onResetFacets?.();
      onClose?.();
    } catch (error) {
      console.error("Failed to reset column configuration:", error);
    }
  };

  const handleCheckboxChange = (column: string, checked: boolean) => {
    setLocalColumnVisibility((prev) => {
      const newState = {
        ...prev,
        [column]: checked,
      };
      return newState;
    });
  };

  const onMultiSelectChange = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    // Create a new order array with all existing columns and newly selected columns
    const selectedColumnIds = filteredColumns.filter(
      (column) => localColumnVisibility[column]
    );

    const updatedOrder = [
      ...columnOrder,
      ...selectedColumnIds.filter((id) => !columnOrder.includes(id)),
    ];

    // Remove any columns that are no longer selected
    const finalOrder = updatedOrder.filter(
      (id) => localColumnVisibility[id] || !filteredColumns.includes(id)
    );

    try {
      // Use batched update to avoid multiple API calls and toasts
      await updateMultipleColumnConfigs({
        columnVisibility: localColumnVisibility,
        columnOrder: finalOrder,
      });
      onClose?.();
    } catch (error) {
      console.error("Failed to save column configuration:", error);
      // Don't close on error, let user try again
    }
  };

  return (
    <form onSubmit={onMultiSelectChange} className="flex flex-col h-full">
      <div className="flex-1 overflow-hidden flex flex-col">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="text-gray-400 text-sm">Set table fields</span>
            {isCustomized && (
              <span className="text-xs text-orange-600 bg-orange-50 px-2 py-0.5 rounded-full" data-testid="custom-view-indicator">
                Customized
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {useBackend && (
              <span className="text-xs text-green-600 bg-green-100 px-2 py-1 rounded">
                Synced across devices
              </span>
            )}
            {isCustomized && (
              <button
                type="button"
                onClick={handleResetToDefault}
                className="text-xs text-gray-500 hover:text-orange-600 flex items-center gap-1 transition-colors"
                data-testid="reset-to-default-button"
                title="Reset columns to default view"
              >
                <FiRotateCcw size={12} />
                Reset
              </button>
            )}
          </div>
        </div>
        <TextInput
          icon={FiSearch}
          placeholder="Search fields..."
          value={searchTerm}
          onChange={(e) => handleSearchChange(e.target.value)}
          className="mb-3"
        />
        <div className="flex-1 overflow-y-auto max-h-[350px]">
          {isLoading && useBackend ? (
            <div className="flex items-center justify-center py-8 text-gray-400">
              <span data-testid="columns-loading">
                Loading column configuration...
              </span>
            </div>
          ) : isSearching ? (
            <div className="flex items-center justify-center py-8 text-gray-400">
              <span data-testid="columns-searching">Searching...</span>
            </div>
          ) : (
            <ul
              className="space-y-1"
              data-testid="column-list"
              data-column-count={filteredColumns.length}
            >
              {filteredColumns.map((column) => (
                <li key={column}>
                  <label className="cursor-pointer p-2 flex items-center">
                    <input
                      className="mr-2"
                      name={column}
                      type="checkbox"
                      checked={localColumnVisibility[column] || false}
                      onChange={(e) =>
                        handleCheckboxChange(column, e.target.checked)
                      }
                      data-testid={`column-checkbox-${column}`}
                      data-checked={localColumnVisibility[column] || false}
                    />
                    {column}
                  </label>
                </li>
              ))}
              {filteredColumns.length === 0 && (
                <li
                  className="text-gray-400 p-2"
                  data-testid="no-columns-found"
                >
                  No columns found matching &ldquo;{searchTerm}&rdquo;
                </li>
              )}
            </ul>
          )}
        </div>
      </div>
      <Button
        className="mt-4"
        color="orange"
        type="submit"
        loading={useBackend && isLoading}
        disabled={useBackend && isLoading}
      >
        {useBackend && isLoading ? "Saving..." : "Save changes"}
      </Button>
    </form>
  );
}
