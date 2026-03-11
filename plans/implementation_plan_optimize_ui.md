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

### Fix 4: Keep [useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) but add `revalidateOnMount: false` when data is cached

[useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) fetches `GET /dashboard` on every page load. Dashboards change infrequently. This is lower priority than the others but still unnecessary.

**Strategy**: Add `revalidateIfStale: false` to [useDashboards](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts#10-28) so that if the data is already cached from a previous navigation, it won't refetch on every page mount.

---

#### [MODIFY] [useDashboards.ts](file:///Users/yarin/keep/keep-ui/utils/hooks/useDashboards.ts)

- Add `revalidateIfStale: false` to the SWR config so subsequent page loads reuse cached data.

---

## Verification Plan

### Automated Tests

Run the existing frontend test suite to confirm no regressions:

```bash
cd /Users/yarin/keep/keep-ui
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
   - On `/alerts/feed`: `POST /alerts/query` calls are expected and appropriate.
   - The incident count badge should still update when an incident changes (via SSE).

**Expected outcome after fix:**
- Loading `/incidents` page: **No** `POST /alerts/query` calls from sidebar presets, **No** `GET /topology` from sidebar
- Loading `/alerts/feed`: `POST /alerts/query` calls fire normally (page-specific)
- Loading `/dashboard`: **No** `POST /alerts/query`, **No** `GET /topology`
