import { useEffect, useRef } from "react";
import { StoreApi, useStore } from "zustand";
import { FacetsPanelState } from "./create-facets-store";

const STORAGE_EVENT = "keephq";

/**
 * Persists the facet selection state to localStorage so it survives across sessions.
 *
 * Priority order:
 * 1. URL query params (highest priority — if present, they override localStorage)
 * 2. localStorage (restored when no URL params exist)
 * 3. Default initial state (from facetsConfig)
 *
 * This hook must be called AFTER useQueryParams in the hook chain so that
 * URL query param state is applied first.
 */
export function useFacetsStatePersistence(
    store: StoreApi<FacetsPanelState>,
    persistenceKey: string | undefined
) {
    const facetsState = useStore(store, (state) => state.facetsState);
    const patchFacetsState = useStore(store, (state) => state.patchFacetsState);
    const isInitialStateHandled = useStore(
        store,
        (state) => state.isInitialStateHandled
    );
    const isFacetsStateInitializedFromQueryParams = useStore(
        store,
        (state) => state.isFacetsStateInitializedFromQueryParams
    );
    const facetsStateRefreshToken = useStore(
        store,
        (state) => state.facetsStateRefreshToken
    );

    const hasRestoredRef = useRef(false);

    // Restore from localStorage after initial state and query params are handled
    useEffect(() => {
        if (
            !persistenceKey ||
            hasRestoredRef.current ||
            !isInitialStateHandled ||
            !isFacetsStateInitializedFromQueryParams ||
            typeof window === "undefined"
        ) {
            return;
        }

        hasRestoredRef.current = true;

        // Check if URL has actual facet query params — if so, they take priority
        const params = new URLSearchParams(window.location.search);
        const hasFacetParams = Array.from(params.keys()).some((key) =>
            key.startsWith("facet_")
        );

        if (hasFacetParams) {
            // URL params are already applied by useQueryParams, don't override
            return;
        }

        // No facet query params in URL — try to restore from localStorage
        try {
            const stored = localStorage.getItem(`keephq-${persistenceKey}`);
            if (stored) {
                const parsed = JSON.parse(stored);
                if (
                    parsed &&
                    typeof parsed === "object" &&
                    Object.keys(parsed).length > 0
                ) {
                    patchFacetsState(parsed);
                }
            }
        } catch {
            // Ignore parse errors
        }
    }, [
        persistenceKey,
        isInitialStateHandled,
        isFacetsStateInitializedFromQueryParams,
        patchFacetsState,
    ]);

    // Save to localStorage whenever facetsState changes (after initial restore)
    useEffect(() => {
        if (
            !persistenceKey ||
            !hasRestoredRef.current ||
            typeof window === "undefined"
        ) {
            return;
        }

        try {
            localStorage.setItem(
                `keephq-${persistenceKey}`,
                JSON.stringify(facetsState)
            );
            window.dispatchEvent(new StorageEvent(STORAGE_EVENT));
        } catch {
            // Ignore storage errors
        }
    }, [persistenceKey, facetsState, facetsStateRefreshToken]);
}
