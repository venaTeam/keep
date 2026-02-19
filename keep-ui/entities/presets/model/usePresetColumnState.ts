import { useCallback, useEffect, useMemo, useRef } from "react";
import { VisibilityState, ColumnOrderState } from "@tanstack/react-table";
import { useLocalStorage } from "@/utils/hooks/useLocalStorage";
import { usePresetColumnConfig } from "./usePresetColumnConfig";
import { TimeFormatOption } from "@/widgets/alerts-table/lib/alert-table-time-format";
import { ListFormatOption } from "@/widgets/alerts-table/lib/alert-table-list-format";
import { ColumnRenameMapping } from "@/widgets/alerts-table/ui/alert-table-column-rename";
import {
  DEFAULT_COLS,
  DEFAULT_COLS_VISIBILITY,
} from "@/widgets/alerts-table/lib/alert-table-utils";
import { STATIC_PRESETS_NAMES, STATIC_PRESET_IDS } from "./constants";
import { ColumnConfiguration } from "./types";
import { useHydratedSession } from "@/shared/lib/hooks/useHydratedSession";

interface UsePresetColumnStateOptions {
  presetName: string;
  presetId?: string;
  useBackend?: boolean; // Flag to enable backend usage
}

/**
 * Generates a user-scoped localStorage key prefix.
 * When a user session is available, keys are prefixed with the user's email
 * to ensure per-user isolation in shared browser environments.
 */
function getUserScopedKey(
  baseName: string,
  presetName: string,
  userEmail?: string | null
): string {
  const userPrefix = userEmail ? `${userEmail}-` : "";
  return `${baseName}-${userPrefix}${presetName}`;
}

/**
 * One-time migration key names for localStorage migration tracking.
 */
const MIGRATION_KEY = "keephq-column-config-migrated-v1";

export const usePresetColumnState = ({
  presetName,
  presetId,
  useBackend = false,
}: UsePresetColumnStateOptions) => {
  const { data: session } = useHydratedSession();
  const userEmail = session?.user?.email;

  // Check if this is a static preset that should always use local storage
  // Check both by ID and by name as fallbacks
  const isStaticPreset =
    !presetId ||
    STATIC_PRESET_IDS.includes(presetId) ||
    STATIC_PRESETS_NAMES.includes(presetName);
  const shouldUseBackend = useBackend && !isStaticPreset && !!presetId;

  // Backend-based state - always call hook but conditionally enable fetching
  const { columnConfig, updateColumnConfig, isLoading, error } =
    usePresetColumnConfig({
      presetId, // Always pass presetId, let the hook decide internally
      enabled: shouldUseBackend, // Use enabled flag to control fetching
    });

  // User-scoped localStorage keys
  const visibilityKey = getUserScopedKey(
    "column-visibility",
    presetName,
    userEmail
  );
  const orderKey = getUserScopedKey("column-order", presetName, userEmail);
  const renameMappingKey = getUserScopedKey(
    "column-rename-mapping",
    presetName,
    userEmail
  );
  const timeFormatsKey = getUserScopedKey(
    "column-time-formats",
    presetName,
    userEmail
  );
  const listFormatsKey = getUserScopedKey(
    "column-list-formats",
    presetName,
    userEmail
  );

  // One-time migration from old unscoped keys to user-scoped keys
  const migrationDone = useRef(false);
  useEffect(() => {
    if (
      !userEmail ||
      migrationDone.current ||
      typeof window === "undefined" ||
      typeof localStorage === "undefined"
    ) {
      return;
    }

    // Only migrate once per user/preset combination
    const migrationMarker = `${MIGRATION_KEY}-${userEmail}-${presetName}`;
    if (localStorage.getItem(migrationMarker)) {
      migrationDone.current = true;
      return;
    }

    const keysToMigrate = [
      { oldSuffix: `column-visibility-${presetName}`, newKey: visibilityKey },
      { oldSuffix: `column-order-${presetName}`, newKey: orderKey },
      {
        oldSuffix: `column-rename-mapping-${presetName}`,
        newKey: renameMappingKey,
      },
      {
        oldSuffix: `column-time-formats-${presetName}`,
        newKey: timeFormatsKey,
      },
      {
        oldSuffix: `column-list-formats-${presetName}`,
        newKey: listFormatsKey,
      },
    ];

    let migrated = false;
    for (const { oldSuffix, newKey } of keysToMigrate) {
      const oldFullKey = `keephq-${oldSuffix}`;
      const newFullKey = `keephq-${newKey}`;
      const oldValue = localStorage.getItem(oldFullKey);
      const newValue = localStorage.getItem(newFullKey);

      // Only migrate if old key exists and new user-scoped key doesn't
      if (oldValue && !newValue) {
        localStorage.setItem(newFullKey, oldValue);
        migrated = true;
      }
    }

    if (migrated) {
      console.info(
        `Migrated column config for preset "${presetName}" to user-scoped keys for ${userEmail}`
      );
    }
    localStorage.setItem(migrationMarker, "true");
    migrationDone.current = true;
  }, [
    userEmail,
    presetName,
    visibilityKey,
    orderKey,
    renameMappingKey,
    timeFormatsKey,
    listFormatsKey,
  ]);

  // Local storage fallbacks with user-scoped keys
  const [localColumnVisibility, setLocalColumnVisibility] =
    useLocalStorage<VisibilityState>(visibilityKey, DEFAULT_COLS_VISIBILITY);

  const [localColumnOrder, setLocalColumnOrder] =
    useLocalStorage<ColumnOrderState>(orderKey, DEFAULT_COLS);

  const [localColumnRenameMapping, setLocalColumnRenameMapping] =
    useLocalStorage<ColumnRenameMapping>(renameMappingKey, {});

  const [localColumnTimeFormats, setLocalColumnTimeFormats] = useLocalStorage<
    Record<string, TimeFormatOption>
  >(timeFormatsKey, {});

  const [localColumnListFormats, setLocalColumnListFormats] = useLocalStorage<
    Record<string, ListFormatOption>
  >(listFormatsKey, {});

  // Determine which state to use - with fallback to local storage on error
  // Always return immediately with either backend or local data
  const columnVisibility = useMemo(() => {
    // If we shouldn't use backend or there's an error, use local storage immediately
    if (!shouldUseBackend || error) {
      return localColumnVisibility;
    }
    // If backend is loading, return defaults to avoid blocking render
    // Once loaded, backend config will be used
    return {
      ...DEFAULT_COLS_VISIBILITY,
      ...(columnConfig?.column_visibility || {}),
    };
  }, [
    shouldUseBackend,
    columnConfig?.column_visibility,
    localColumnVisibility,
    error,
  ]);

  const columnOrder = useMemo(() => {
    // If we shouldn't use backend or there's an error, use local storage immediately
    if (!shouldUseBackend || error) {
      return localColumnOrder;
    }
    // For backend presets, use backend order if available, otherwise default
    return columnConfig?.column_order && columnConfig.column_order.length > 0
      ? columnConfig.column_order
      : DEFAULT_COLS;
  }, [shouldUseBackend, columnConfig?.column_order, localColumnOrder, error]);

  const columnRenameMapping = useMemo(() => {
    // If we shouldn't use backend or there's an error, use local storage immediately
    if (!shouldUseBackend || error) {
      return localColumnRenameMapping;
    }
    return columnConfig?.column_rename_mapping || {};
  }, [
    shouldUseBackend,
    columnConfig?.column_rename_mapping,
    localColumnRenameMapping,
    error,
  ]);

  const columnTimeFormats = useMemo(() => {
    // If we shouldn't use backend or there's an error, use local storage immediately
    if (!shouldUseBackend || error) {
      return localColumnTimeFormats;
    }
    return (columnConfig?.column_time_formats || {}) as Record<
      string,
      TimeFormatOption
    >;
  }, [
    shouldUseBackend,
    columnConfig?.column_time_formats,
    localColumnTimeFormats,
    error,
  ]);

  const columnListFormats = useMemo(() => {
    // If we shouldn't use backend or there's an error, use local storage immediately
    if (!shouldUseBackend || error) {
      return localColumnListFormats;
    }
    return (columnConfig?.column_list_formats || {}) as Record<
      string,
      ListFormatOption
    >;
  }, [
    shouldUseBackend,
    columnConfig?.column_list_formats,
    localColumnListFormats,
    error,
  ]);

  // Batched update function to avoid multiple API calls
  const updateMultipleColumnConfigs = useCallback(
    async (updates: {
      columnVisibility?: VisibilityState;
      columnOrder?: ColumnOrderState;
      columnRenameMapping?: ColumnRenameMapping;
      columnTimeFormats?: Record<string, TimeFormatOption>;
      columnListFormats?: Record<string, ListFormatOption>;
    }) => {
      if (shouldUseBackend && !error) {
        // Batch all updates into a single API call
        const batchedUpdate: Partial<ColumnConfiguration> = {};

        if (updates.columnVisibility !== undefined) {
          batchedUpdate.column_visibility = updates.columnVisibility;
        }
        if (updates.columnOrder !== undefined) {
          batchedUpdate.column_order = updates.columnOrder;
        }
        if (updates.columnRenameMapping !== undefined) {
          batchedUpdate.column_rename_mapping = updates.columnRenameMapping;
        }
        if (updates.columnTimeFormats !== undefined) {
          batchedUpdate.column_time_formats = updates.columnTimeFormats;
        }
        if (updates.columnListFormats !== undefined) {
          batchedUpdate.column_list_formats = updates.columnListFormats;
        }

        try {
          return await updateColumnConfig(batchedUpdate);
        } catch (err) {
          // If backend update fails, fall back to local storage
          console.warn(
            "Failed to update backend column config, falling back to local storage",
            err
          );
          // Fall through to local storage update
        }
      }

      // For local storage or on backend failure, update each one individually (synchronously)
      if (updates.columnVisibility !== undefined) {
        setLocalColumnVisibility(updates.columnVisibility);
      }
      if (updates.columnOrder !== undefined) {
        setLocalColumnOrder(updates.columnOrder);
      }
      if (updates.columnRenameMapping !== undefined) {
        setLocalColumnRenameMapping(updates.columnRenameMapping);
      }
      if (updates.columnTimeFormats !== undefined) {
        setLocalColumnTimeFormats(updates.columnTimeFormats);
      }
      if (updates.columnListFormats !== undefined) {
        setLocalColumnListFormats(updates.columnListFormats);
      }
      return Promise.resolve();
    },
    [
      shouldUseBackend,
      updateColumnConfig,
      setLocalColumnVisibility,
      setLocalColumnOrder,
      setLocalColumnRenameMapping,
      setLocalColumnTimeFormats,
      setLocalColumnListFormats,
      error,
    ]
  );

  // Individual update functions for backward compatibility
  const setColumnVisibility = useCallback(
    (visibility: VisibilityState) => {
      return updateMultipleColumnConfigs({ columnVisibility: visibility });
    },
    [updateMultipleColumnConfigs]
  );

  const setColumnOrder = useCallback(
    (order: ColumnOrderState) => {
      return updateMultipleColumnConfigs({ columnOrder: order });
    },
    [updateMultipleColumnConfigs]
  );

  const setColumnRenameMapping = useCallback(
    (mapping: ColumnRenameMapping) => {
      return updateMultipleColumnConfigs({ columnRenameMapping: mapping });
    },
    [updateMultipleColumnConfigs]
  );

  const setColumnTimeFormats = useCallback(
    (formats: Record<string, TimeFormatOption>) => {
      return updateMultipleColumnConfigs({ columnTimeFormats: formats });
    },
    [updateMultipleColumnConfigs]
  );

  const setColumnListFormats = useCallback(
    (formats: Record<string, ListFormatOption>) => {
      return updateMultipleColumnConfigs({ columnListFormats: formats });
    },
    [updateMultipleColumnConfigs]
  );

  return {
    columnVisibility,
    columnOrder,
    columnRenameMapping,
    columnTimeFormats,
    columnListFormats,
    setColumnVisibility,
    setColumnOrder,
    setColumnRenameMapping,
    setColumnTimeFormats,
    setColumnListFormats,
    updateMultipleColumnConfigs,
    isLoading,
    useBackend: shouldUseBackend && !error,
  };
};

export type UsePresetColumnStateValue = ReturnType<typeof usePresetColumnState>;
