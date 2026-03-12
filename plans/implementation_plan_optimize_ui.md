# Fix Excessive Frontend Requests on Page Load

## Background

The frontend is organized with a **root layout** (`app/(keep)/layout.tsx`) that always renders the [Navbar](file:///Users/yarin/keep/keep-ui/components/navbar/Navbar.tsx#13-33) for every page. The [Navbar](file:///Users/yarin/keep/keep-ui/components/navbar/Navbar.tsx#13-33) is composed of several sidebar components that immediately trigger data fetching hooks on mount — meaning **every page load fires all of these requests simultaneously**, even when the user never visits those pages.

At 4,000 alerts/minute, the per-preset alert count queries (POST `/alerts/query`) are the highest-impact issue, but all the sources compound together.

---

## Root Causes

| Component | Hook | API Call | Trigger |
|---|---|---|---|
| [IncidentsLinks](file:///Users/yarin/keep/keep-ui/components/navbar/IncidentLinks.tsx#19-68) | [useIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#98-137) | `GET /incidents?candidate=false&limit=0&...` | Every page load |
| [IncidentsLinks](file:///Users/yarin/keep/keep-ui/components/navbar/IncidentLinks.tsx#19-68) | [usePollIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#241-269) | Re-fires on SSE `incident-change` event | Every page load |
| [NoiseReductionLinks](file:///Users/yarin/keep/keep-ui/components/navbar/NoiseReductionLinks.tsx#52-198) | [useTopology](file:///Users/yarin/keep/keep-ui/app/%28keep%29/topology/model/useTopology.ts#18-62) | `GET /topology` | Every page load |
| [DashboardLinks](file:///Users/yarin/keep/keep-ui/components/navbar/DashboardLinks.tsx#22-151) | [useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) | `GET /dashboard` | Every page load |
| [AlertsLinks](file:///Users/yarin/keep/keep-ui/components/navbar/AlertsLinks.tsx#27-184) | [usePresetAlertsCount("")](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) | `POST /alerts/query` (for the Feed count) | Every page load |
| [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123) × N | [usePresetAlertsCount(cel)](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) | `POST /alerts/query` × **N** (one per preset) | Every page load |

The **biggest offender** is [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123) — it's rendered once per dynamic preset in the sidebar, and each instance independently calls [usePresetAlertsCount()](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41), which calls [useLastAlerts()](file:///Users/yarin/keep/keep-ui/entities/alerts/model/useAlerts.ts#146-217), which POSTs to `/alerts/query`. With 5 presets in the sidebar, this is **5 simultaneous alert query requests on every page load**, not just on the alerts page.

---

## User Review Required

> [!IMPORTANT]
> **Fix 1 (preset counts)** changes visible sidebar behavior: The alert count badges next to preset links in the sidebar will no longer update in real-time or on every page load. They will only be shown when the user is actively on an alerts-related page.
>
> This is a deliberate tradeoff to avoid N×POST /alerts/query on every non-alerts page. Please confirm this tradeoff is acceptable.

> [!IMPORTANT]  
> **Fix 2 (incidents count)** means the incident badge count in the sidebar will only update via SSE events (already existing), not via a proactive `GET /incidents` on every page load. This is sound because [usePollIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#241-269) already handles real-time updates via SSE.

> [!IMPORTANT]
> **Fix 5 (feed default behavior)** changes the alerts feed page so it no longer loads all alerts on initial visit. Instead, users must enter a CEL query or select a facet before any alerts are fetched. This is a significant UX change — the feed will show a prompt instead of a full alert list on first load.
>
> At 4,000 alerts/minute, loading all alerts by default is extremely expensive and rarely what the user actually wants. This tradeoff prioritizes performance and intentional querying over "show everything".

---

## Additional Considerations

### SSE-triggered refetches

The gating approach (null SWR key when not on the relevant page) is solid, but audit whether **alert-related SSE event handlers** (e.g., `alert-change`) globally call `mutate()` on alert query SWR keys. If so, gated sidebar hooks could still wake up and refetch on non-alert pages. Ensure SSE handlers only mutate keys that are actively in use.

### `revalidateOnFocus` and `revalidateOnReconnect`

For all hooks that remain enabled, verify that `revalidateOnFocus: false` and `revalidateOnReconnect: false` are set consistently. Otherwise, a user tabbing away and returning could trigger a wave of refetches across all enabled hooks.

### Consider prefetch-on-hover for sidebar links

To soften the UX impact of removing upfront badge counts, consider prefetching data when the user **hovers** over a sidebar section (e.g., hovering over "Alerts" starts loading preset counts ~200ms before the click). This keeps the sidebar snappy without the cost of fetching on every page load. This is a potential follow-up enhancement, not a blocker for this PR.

---

## Proposed Changes

### Fix 1: Remove per-preset alert count fetching from the sidebar's [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123)

The most expensive fix. Each [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123) independently calls [usePresetAlertsCount()](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) → [useLastAlerts()](file:///Users/yarin/keep/keep-ui/entities/alerts/model/useAlerts.ts#146-217) → POST `/alerts/query`. Since these are sidebar nav links, they **don't need live counts while navigating non-alert pages**.

**Strategy**: Gate the [usePresetAlertsCount](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) call inside [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123) so it only runs when the user is actually on an alerts-related page (pathname starts with `/alerts`).

---

#### [MODIFY] [AlertPresetLink / CustomPresetAlertLinks.tsx](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx)

- In [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123), wrap [usePresetAlertsCount](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) in a conditional — only activate SWR key when `pathname` starts with `/alerts`.
- Pass `pathname` as a prop to [AlertPresetLink](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#36-123) (it's already being passed from the parent [CustomPresetAlertLinks](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/ui/CustomPresetAlertLinks.tsx#127-219)).
- When not on an alerts page, `totalCount` returns `undefined`, so the badge simply won't render (existing behavior when count is `undefined`).

---

#### [MODIFY] [usePresetAlertsCount.ts](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts)

- Add an optional `enabled: boolean` parameter (default `true`). When `false`, skip calling [useLastAlerts](file:///Users/yarin/keep/keep-ui/entities/alerts/model/useAlerts.ts#146-217) (pass `undefined` as query so SWR key is null).

---

#### [MODIFY] [AlertsLinks.tsx](file:///Users/yarin/keep/keep-ui/components/navbar/AlertsLinks.tsx)

- The [usePresetAlertsCount("", false)](file:///Users/yarin/keep/keep-ui/features/presets/custom-preset-links/model/usePresetAlertsCount.ts#4-41) call on line 73 (for the Feed count badge) should be similarly gated — only fire when on `/alerts/*`.

---

### Fix 2: Remove proactive `GET /incidents` from [IncidentsLinks](file:///Users/yarin/keep/keep-ui/components/navbar/IncidentLinks.tsx#19-68) in the sidebar

The [IncidentsLinks](file:///Users/yarin/keep/keep-ui/components/navbar/IncidentLinks.tsx#19-68) component calls [useIncidents({limit: 0})](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#98-137) on every page. `limit: 0` returns the count but not actual records. This is purely for the badge count in the sidebar.

The incidents count is only **actually useful** when the user is on or navigating to the incidents page. Additionally, [usePollIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#241-269) already handles SSE-based real-time updates.

**Strategy**: Gate [useIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#98-137) so the initial fetch only runs when the user is on an `/incidents` page, but SSE-driven updates via [usePollIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#241-269) still work normally.

---

#### [MODIFY] [IncidentLinks.tsx](file:///Users/yarin/keep/keep-ui/components/navbar/IncidentLinks.tsx)

- Use `usePathname()` to get the current page.
- Pass `null` as the query to [useIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#98-137) when not on `/incidents*` path (SWR skips fetching when key is null).
- [usePollIncidents](file:///Users/yarin/keep/keep-ui/utils/hooks/useIncidents.ts#241-269) remains enabled globally for real-time updates via SSE, which will trigger a revalidation when an incident changes.

---

### Fix 3: Remove `GET /topology` from [NoiseReductionLinks](file:///Users/yarin/keep/keep-ui/components/navbar/NoiseReductionLinks.tsx#52-198) in the sidebar

[NoiseReductionLinks](file:///Users/yarin/keep/keep-ui/components/navbar/NoiseReductionLinks.tsx#52-198) calls [useTopology()](file:///Users/yarin/keep/keep-ui/app/%28keep%29/topology/model/useTopology.ts#18-62) on every page to get `topologyData.length` for the badge count beside "Service Topology" link.

The topology data is heavy and only relevant on the `/topology` page itself.

**Strategy**: Remove [useTopology()](file:///Users/yarin/keep/keep-ui/app/%28keep%29/topology/model/useTopology.ts#18-62) from [NoiseReductionLinks](file:///Users/yarin/keep/keep-ui/components/navbar/NoiseReductionLinks.tsx#52-198). The badge is only informational and not critical for navigation. The `/topology` page itself already calls [useTopology()](file:///Users/yarin/keep/keep-ui/app/%28keep%29/topology/model/useTopology.ts#18-62).

---

#### [MODIFY] [NoiseReductionLinks.tsx](file:///Users/yarin/keep/keep-ui/components/navbar/NoiseReductionLinks.tsx)

- Remove the [useTopology()](file:///Users/yarin/keep/keep-ui/app/%28keep%29/topology/model/useTopology.ts#18-62) hook call completely from this component.
- Remove the `topologyData` reference in the `isBeta` prop — set `isBeta` to a constant value (e.g., always show it as stable/no badge, or keep `isBeta={false}`).

---

### Fix 4: Gate [useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) and add `revalidateIfStale: false`

[useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) fetches `GET /dashboard` on every page load. Dashboards change infrequently. This is lower priority than the others but still unnecessary.

**Strategy**: Gate the initial fetch so it only runs when `pathname` starts with `/dashboard`, consistent with Fixes 1–3. Additionally, add `revalidateIfStale: false` so that if the data is already cached from a previous navigation, it won't refetch on every page mount.

---

#### [MODIFY] [DashboardLinks.tsx](file:///Users/yarin/keep/keep-ui/components/navbar/DashboardLinks.tsx)

- Use `usePathname()` to get the current page.
- Pass an `enabled` flag (or null key) to [useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) when not on `/dashboard*` path.

---

#### [MODIFY] [useDashboards.ts](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts)

- Add an optional `enabled: boolean` parameter (default `true`). When `false`, pass `null` as SWR key to skip fetching.
- Add `revalidateIfStale: false` to the SWR config so subsequent page loads reuse cached data.

---

### Fix 5: Don't load all alerts on the Feed page by default — require a query first

Currently, navigating to `/alerts/feed` immediately fires `POST /alerts/query` with **no CEL filter**, returning **all alerts in the system**. At 4,000 alerts/minute, this is the single most expensive page load in the app and often not what the user actually wants.

**Strategy**: When the user lands on the **feed preset** (`/alerts/feed`) with no CEL search query and no facet filters applied, **skip the initial fetch entirely** and show an empty state prompting the user to enter a query. Alerts are only fetched once the user provides input (via the CEL bar or by selecting a facet).

This change applies **only to the "feed" preset**. Custom presets already have a built-in CEL expression and will continue to load immediately.

---

#### [MODIFY] [alert-table-server-side.tsx](file:///Users/yarin/keep/keep-ui/widgets/alerts-table/ui/alert-table-server-side.tsx)

- Accept a new prop: `presetName: string` (or derive from the URL `[id]` param).
- Add a computed flag: `isFeedAwaitingQuery = presetName === "feed" && !searchCel && !filterCel`.
- When `isFeedAwaitingQuery` is `true`:
  - **Do not call `onQueryChange`** — this prevents `useAlertsTableData` from receiving a query and prevents `POST /alerts/query` from firing.
  - Render a new empty state instead of the alerts table body. This empty state should:
    - Use the existing [EmptyStateCard](file:///Users/yarin/keep/keep-ui/shared/ui/EmptyState/EmptyStateCard.tsx) component for visual consistency.
    - Show a search/filter icon.
    - Display a title like **"Query your alerts"**.
    - Display a description like **"Use the CEL search bar above to filter alerts, or select facets from the panel on the left."**
    - Optionally show example CEL queries as clickable chips (e.g., `severity == 'critical'`, `source == 'datadog'`, `status == 'firing'`).
  - The **CEL bar**, **facet panel**, and **timeframe selector** must still be rendered and functional above/beside the empty state, so the user can immediately start building a query.
- When the user enters a CEL query (updating `searchCel`) or selects a facet (updating `filterCel`), `isFeedAwaitingQuery` becomes `false`, `onQueryChange` fires normally, and alerts load.

---

#### [MODIFY] [alerts.tsx](file:///Users/yarin/keep/keep-ui/app/(keep)/alerts/[id]/ui/alerts.tsx)

- Pass `presetName` (already available from props/params) down through [AlertTableTabPanelServerSide](file:///Users/yarin/keep/keep-ui/app/(keep)/alerts/[id]/ui/alert-table-tab-panel-server-side.tsx) to [AlertTableServerSide](file:///Users/yarin/keep/keep-ui/widgets/alerts-table/ui/alert-table-server-side.tsx).

---

#### [MODIFY] [alert-table-tab-panel-server-side.tsx](file:///Users/yarin/keep/keep-ui/app/(keep)/alerts/[id]/ui/alert-table-tab-panel-server-side.tsx)

- Thread the `presetName` prop through to `AlertTableServerSide`.

---

#### [NO CHANGES NEEDED] [useAlertsTableData.ts](file:///Users/yarin/keep/keep-ui/widgets/alerts-table/ui/useAlertsTableData.ts)

- When `AlertTableServerSide` doesn't call `onQueryChange`, `alertsTableDataQuery` in the parent `Alerts` component remains `undefined`. `useAlertsTableData(undefined)` passes `undefined` to `useLastAlerts`, which results in a `null` SWR key — no fetch occurs. This already works correctly.

---

#### UX Considerations

- **Facet clicks should also trigger the fetch.** The gate is: skip fetch only when **both** `searchCel` is empty **and** `filterCel` is empty on the feed preset. As soon as either has a value, fetch proceeds.
- **Timeframe selection alone should NOT trigger a fetch** on the feed (timeframe without any alert filter would still return all alerts). Timeframe only takes effect in combination with a CEL or facet filter.
- **Custom presets are unaffected.** They have a non-empty `presetCel` by definition, so they load immediately.
- **Example query chips** (optional enhancement): Clicking a chip like `severity == 'critical'` should populate the CEL bar and trigger the fetch. This can be a follow-up if scope needs to be limited.

---

## Verification Plan

### Automated Tests

Run the existing frontend test suite to confirm no regressions:

```bash
cd keep-ui
npx jest --testPathPattern="preset-navigation|alert-preset-manager|incident-alerts" --no-coverage 2>&1 | tail -30
```

### Manual Verification (Browser Network Tab)

This is the primary validation method since the bug is about runtime behavior.

**Before/After Comparison Test:**

1. Open **Chrome DevTools → Network tab**
2. Filter by `XHR/Fetch` requests
3. **Clear the network log**
4. Navigate to **any non-alerts page** (e.g., `http://localhost:3000/incidents`)
5. **Before fix**: Observe N×`POST /alerts/query` calls immediately firing (one per preset in sidebar) + `GET /topology` + `GET /incidents` (even though we're on the incidents page, there would be duplicates)
6. **After fix**: 
   - On `/incidents` page: Only the alerts-related queries that the actual page needs should fire. The sidebar should NOT fire preset count queries.
   - On `/alerts/feed`: See Feed-specific tests below.
   - The incident count badge should still update when an incident changes (via SSE).

### Pass/Fail Criteria (Fixes 1–4: Sidebar)

On a **non-alerts page** load, there should be:
- **Zero** `POST /alerts/query` requests originating from sidebar components
- **Zero** `GET /topology` requests from the sidebar
- **Zero** `GET /dashboard` requests from the sidebar (unless on `/dashboard`)

| Page loaded | Expected `POST /alerts/query` from sidebar | Expected `GET /topology` from sidebar | Expected `GET /dashboard` from sidebar |
|---|---|---|---|
| `/incidents` | 0 | 0 | 0 |
| `/dashboard` | 0 | 0 | Allowed (page-specific) |
| `/alerts/feed` | 0 (page handles its own, see Fix 5) | 0 | 0 |
| `/alerts/{custom-preset}` | 0 from sidebar, page fetches own | 0 | 0 |

### Pass/Fail Criteria (Fix 5: Feed Default Behavior)

| Action | Expected behavior |
|---|---|
| Navigate to `/alerts/feed` (fresh load, no URL params) | **No** `POST /alerts/query` fires. Empty state prompt is shown: "Query your alerts". CEL bar and facet panel are visible and functional. |
| Type a CEL query in the search bar and press Enter | `POST /alerts/query` fires with the entered CEL. Alerts matching the query are displayed. |
| Click a facet in the left panel (without CEL query) | `POST /alerts/query` fires with the facet filter. Matching alerts are displayed. |
| Navigate to `/alerts/{custom-preset}` | Alerts for that preset load **immediately** (no empty state). Custom presets are unaffected by this change. |
| Clear the CEL bar (back to empty) while facets are still selected | Alerts remain visible (facet filter still active). |
| Clear both CEL bar and all facets | Returns to empty state prompt. No `POST /alerts/query` fires. |
