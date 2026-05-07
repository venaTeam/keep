# data-cy Conventions

This document defines the naming convention, scope, and usage rules for the
`data-cy` selector attribute across the Keep frontend (`keep-ui`).

## 1. Why data-cy exists

The external QA team owns a Cypress automation suite that exercises the Keep
UI end-to-end. Historically that suite has selected DOM nodes through CSS
class chains (e.g. `.tremor-TableRow-row`, `button:has(svg)`) or through
localized button labels. Both approaches are fragile:

- CSS classes change whenever a UI library is upgraded, swapped, or restyled.
- Labels change with copy edits or i18n.
- `:has(...)` fallbacks are slow and easily defeated by markup changes.

The fix is a stable, semantic selector layer dedicated to test automation:

- `data-cy` is the only attribute QA is allowed to select on.
- It is owned by the application code, not by styling concerns.
- It survives refactors, library swaps, and copy edits.

The end goal: every interactive surface (button, input, row, cell, link, tab,
menu item, drawer, modal, etc.) is reachable from Cypress through a single
`data-cy` value with a predictable structure.

## 2. Coexistence with data-testid

`data-testid` is already used in some components for Jest / React Testing
Library tests. We do not remove or rename it.

Rule: when a single DOM node carries both attributes, the values are
identical.

```tsx
// Good
<Button data-testid="wf-run-now-button" data-cy="wf-run-now-button" />

// Bad - drift between the two
<Button data-testid="wf-run-now-button" data-cy="wf-runNow" />

// Forbidden - never delete or rename an existing data-testid
<Button data-cy="wf-run-now-button" /> // (was data-testid before)
```

The audit script (`scripts/data-cy/audit.ts`) reports any node that has
`data-testid` without a matching `data-cy`, or where the two values diverge.

## 3. Format grammar

```
data-cy = <area> "-" <role> [ "-" <id> ]
```

Rules:

- Lowercase ASCII only. Use kebab-case (hyphen-separated tokens).
- Maximum length 60 characters.
- No spaces, no localized strings, no user-generated content.
- The area prefix is mandatory and must come from the table in section 4.
- The role token is mandatory and must come from the table in section 5.
- The optional id segment is for dynamic instances only (rows, tiles,
  options) and must be derived from a server-issued identifier (uuid,
  slug, deterministic key). Never use array indices, never use display
  labels, never use user content.

Examples:

```
nav-btn-settings           ok
alerts-row                 ok
alerts-cell-severity       ok
wf-tile-9f2c8b21-1c3d-...  ok (server uuid)
wf-tile-0                  forbidden (array index)
wf-tile-My-Workflow        forbidden (user-supplied label)
WfTile                     forbidden (camelCase, no area, no role)
modal-close-btn            ok (cross-cutting modal area)
```

## 4. Area prefixes

Every selector must start with one of the following area prefixes. Prefixes
correspond to top-level product surfaces in the Keep UI; the cross-cutting
prefixes apply to widgets that can appear anywhere.

| Prefix         | Meaning                                                                          |
| -------------- | -------------------------------------------------------------------------------- |
| `nav-`         | Top navigation, sidebar, breadcrumbs                                             |
| `alerts-`      | Alerts feed, alert details, alert actions                                        |
| `wf-`          | Workflows list, workflow runs, workflow editor (YAML + visual)                   |
| `incidents-`   | Incidents list, incident timeline, incident detail panel                         |
| `dashboard-`   | Dashboards list, dashboard widgets, dashboard editor                             |
| `topology-`    | Topology graph, topology node/edge inspectors                                    |
| `ai-`          | AI assistant chat, suggestion drawers, copilot surfaces                          |
| `notif-`       | Notification center, toasts, in-app alerts                                       |
| `providers-`   | Provider catalogue, connect/configure provider dialogs                           |
| `settings-`    | Settings hub, user profile, organization settings                                |
| `auth-`        | Sign in / sign up / password / SSO flows                                         |
| `rules-`       | Rule management (correlation, suppression)                                       |
| `mapping-`     | Field-to-field mapping configuration                                             |
| `dedup-`       | Deduplication rules                                                              |
| `extraction-`  | Extraction rules                                                                 |
| `maintenance-` | Maintenance windows                                                              |
| `modal-`       | Cross-cutting: any modal dialog (close button, panel, footer)                    |
| `drawer-`      | Cross-cutting: any drawer (close button, content)                                |
| `form-`        | Cross-cutting: form-level controls (submit, cancel, validation)                  |
| `table-`       | Cross-cutting: table primitives shared across areas                              |
| `tab-`         | Cross-cutting: tab containers and tab triggers                                   |
| `menu-`        | Cross-cutting: dropdown menus and their items                                    |
| `toast-`       | Cross-cutting: toast notifications                                               |

Pick the most specific area first. Use a cross-cutting prefix only when the
component genuinely belongs to no single product area (a generic modal close
button is `modal-close-btn`, the workflow run modal's title bar is
`wf-modal-...`).

## 5. Component roles

The role token (second segment) describes the kind of element. It is always a
single token from this list. Compose with a third segment when needed
(`alerts-btn-acknowledge`, not `alerts-acknowledge-button`).

| Role         | Use for                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `btn`        | `<button>` elements that trigger an action                               |
| `input`      | Text-like inputs (`<input type="text">`, autocomplete, textarea)         |
| `select`     | Single- or multi-select widgets (native `<select>`, react-select)        |
| `checkbox`   | `<input type="checkbox">` or visually equivalent                         |
| `radio`      | `<input type="radio">` or visually equivalent                            |
| `link`       | `<a>` elements meant for navigation                                      |
| `tab`        | Tab triggers (within a tab container)                                    |
| `row`        | A `<tr>` (one per item in a table or list)                               |
| `cell`       | A `<td>` (one per visible column per row)                                |
| `header`     | A `<th>` or section header                                               |
| `pagination` | Pagination controls (prev/next, page size)                               |
| `filter`     | Filter chips, filter triggers, filter forms                              |
| `submit`     | The primary submit button of a form                                      |
| `cancel`     | The cancel/dismiss button of a form or dialog                            |
| `confirm`    | An explicit confirm button on a destructive prompt                       |
| `close`      | A close affordance (X icon) on a modal/drawer/banner                     |
| `delete`     | A button that initiates deletion                                         |
| `edit`       | A button that opens an editor for an item                                |
| `save`       | A save button (distinct from generic submit)                             |
| `dropdown`   | A dropdown trigger (the button that opens a menu)                        |
| `option`     | A single option inside a select / autocomplete / menu                    |
| `search`     | A search input (`<input type="search">`)                                 |
| `node`       | A node in a graph (topology, workflow visual editor)                     |
| `edge`       | An edge in a graph (topology, workflow visual editor)                    |

If a role you need is not in this list, prefer composition over invention:
`wf-btn-run-now` (not `wf-runner`), `incidents-btn-merge` (not
`incidents-merger`).

## 6. Dynamic IDs

When a selector targets a specific instance, append the server-side
identifier:

```tsx
<tr data-cy={`alerts-row-${alert.id}`}>...</tr>
<button data-cy={`wf-btn-run-${workflow.id}`}>Run</button>
```

Strict rules:

- The id MUST come from a server-issued field: uuid, ULID, slug, numeric
  primary key. Anything the backend persists and returns is acceptable.
- Array indices (`items.map((_, i) => ...-${i})`) are forbidden. They become
  unstable as soon as the order changes.
- User-supplied content (titles, names, free-text labels) is forbidden. Use
  the entity's id or slug instead.
- If a stable id is genuinely unavailable (e.g. an ephemeral computed list),
  use the parent area's selector and a role only, with no id, and select by
  index from Cypress.

When you record a dynamic selector in the manifest, you can resolve a real
example for the docs by adding an entry to
`scripts/data-cy/manifest.descriptions.yaml` with `idSource` and
`resolvedExample` fields.

## 7. Tables and lists

Tables and item lists must follow this pattern uniformly:

- Each `<tr>` (or list item) gets `data-cy="<area>-row"` if the row is
  generic, or `data-cy="<area>-row-${id}"` if a per-row selector is needed
  for assertions. When using the dynamic form, also keep a static
  `data-cy-row` data attribute or a parent `data-cy="<area>-table"` so QA can
  enumerate rows by area.
- Each `<td>` gets `data-cy="<area>-cell-<column-key>"` where `<column-key>`
  is the column identifier known at design time (e.g. `severity`, `status`,
  `last-seen`, `assignee`). Never use the column index.
- Each sortable header gets `data-cy="<area>-header-<column-key>"`.
- Pagination controls use the cross-cutting `pagination-prev`,
  `pagination-next`, `pagination-page-size`, optionally namespaced with the
  consumer's area: `alerts-pagination-prev`.

## 8. Reusable primitives

These primitives all accept a `"data-cy"?: string` prop. Pass it from the
call site; the primitive forwards it to the outermost interactive DOM node.
Where applicable the primitive also hard-codes its own internal `data-cy`
values for affordances that are unambiguous (e.g. modal close button).

| Primitive                                | Path                                                                   | Notes                                                                                      |
| ---------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `Button`                                 | `components/ui/Button.tsx`                                             | Forwards to Tremor `Button`.                                                               |
| `Modal`                                  | `components/ui/Modal.tsx`                                              | Forwards to `DialogPanel`. Internal close hard-codes `data-cy="modal-close-btn"`.         |
| `TextInput`                              | `components/ui/TextInput.tsx`                                          | Forwards to Tremor `TextInput`.                                                            |
| `Textarea`                               | `components/ui/Textarea.tsx`                                           | Forwards to Tremor `Textarea`.                                                             |
| `AutocompleteInput`                      | `components/ui/AutocompleteInput.tsx`                                  | Forwards to inner `TextInput`.                                                             |
| `CreatableMultiSelect`                   | `components/ui/CreatableMultiSelect.tsx`                               | Wrapped in a `<div data-cy="...">` to ensure the attribute reaches the DOM.                |
| `DateRangePicker` / `DateRangePickerV2`  | `components/ui/DateRangePicker.tsx`, `DateRangePickerV2.tsx`           | Forwarded to the popover trigger button.                                                   |
| `Calendar`                               | `components/ui/Calendar.tsx`                                           | Forwarded to the wrapping `<div>` around `DayPicker`.                                      |
| `Drawer`                                 | `shared/ui/Drawer/Drawer.tsx`                                          | Forwards to `DrawerContent`. Internal close hard-codes `data-cy="drawer-close-btn"`.       |
| `TremorDrawer`                           | `shared/ui/Drawer/TremorDrawer.tsx`                                    | `DrawerContent` accepts `data-cy`.                                                         |
| `DropdownMenu`                           | `shared/ui/DropdownMenu/DropdownMenu.tsx`                              | Trigger and list both accept `data-cy`. Items get `menu-item-<id>` automatically.          |
| `TablePagination`                        | `shared/ui/TablePagination/TablePagination.tsx`                        | Hard-codes `pagination-prev/next/page-size`. Optional `dataCyPrefix` namespaces the value. |
| `Select`                                 | `shared/ui/Select/Select.tsx`                                          | Wrapped in a `<div data-cy="...">`.                                                        |
| `Tooltip`                                | `shared/ui/Tooltip/Tooltip.tsx`                                        | Forwards to the `TooltipPrimitives.Content` element.                                       |
| `TableIndeterminateCheckbox`             | `shared/ui/TableIndeterminateCheckbox/TableIndeterminateCheckbox.tsx`  | Forwards to the `<input type="checkbox">`.                                                 |
| `Input`                                  | `shared/ui/Input/index.tsx`                                            | Forwards to the inner `<input>`.                                                           |
| `TabLinkNavigation` / `TabNavigationLink`| `shared/ui/TabLinkNavigation/...`                                      | Container forwards to `<nav>`. Link forwards to `<a>`.                                     |

Prop signature in every case (use the bracketed string key, not camelCase, so
the prop round-trips identically to the DOM attribute):

```tsx
type Props = {
  // ...
  "data-cy"?: string;
};
```

`TablePagination` additionally accepts:

```tsx
type Props = {
  // ...
  dataCyPrefix?: string; // e.g. "alerts" => "alerts-pagination-prev"
};
```

## 9. Concrete examples per area

Navigation:

```tsx
<a data-cy="nav-link-incidents" href="/incidents">Incidents</a>
<button data-cy="nav-btn-user-menu">...</button>
```

Alerts:

```tsx
<tr data-cy="alerts-row" data-id={alert.id}>
  <td data-cy="alerts-cell-severity">{alert.severity}</td>
  <td data-cy="alerts-cell-name">{alert.name}</td>
</tr>
<Button data-cy="alerts-btn-acknowledge">Acknowledge</Button>
```

Workflows:

```tsx
<div data-cy={`wf-tile-${workflow.id}`}>
  <Button data-cy={`wf-btn-run-${workflow.id}`}>Run</Button>
</div>
```

Incidents:

```tsx
<Button data-cy="incidents-btn-create">Create incident</Button>
<tr data-cy="incidents-row">
  <td data-cy="incidents-cell-status">{incident.status}</td>
</tr>
```

Modal / drawer (cross-cutting):

```tsx
<Modal data-cy="wf-modal-edit" isOpen={open} onClose={close}>
  ...
</Modal>
// The modal's internal close button is automatically modal-close-btn.

<Drawer data-cy="incidents-drawer-detail" isOpen={open} onClose={close}>
  ...
</Drawer>
// The drawer's internal close button is automatically drawer-close-btn.
```

Pagination (cross-cutting, namespaced by consumer):

```tsx
<TablePagination dataCyPrefix="alerts" table={table} />
// Renders prev/next/page-size as alerts-pagination-prev / -next / -page-size.
```

## 10. Anti-patterns

The following patterns are explicitly forbidden. The audit script flags
them on PR review.

- Index-based ids: `data-cy={\`row-${i}\`}`. Use `${item.id}` instead.
- Label-based ids: `data-cy={\`btn-${button.label}\`}`. Use a stable role
  token instead.
- Missing area prefix: `data-cy="run-now"`. Always lead with an area prefix.
- camelCase / PascalCase: `data-cy="wfRunNow"`. Use kebab-case.
- Renaming or deleting an existing `data-testid` to make room for `data-cy`.
  Both must coexist with identical values.
- Including localized or user-generated text in the value.
- Selectors longer than 60 characters.

## 11. PR review checklist

Reviewers checking a PR that touches user-facing UI should verify:

- [ ] Every new interactive element (button, input, row, cell, link, tab,
  menu item) has a `data-cy` value.
- [ ] The value matches `<area>-<role>[-<id>]`, with area and role from this
  document.
- [ ] Any dynamic id segment is sourced from a server-issued identifier, not
  an index or user content.
- [ ] No existing `data-testid` was deleted or renamed; if both attributes
  attach to the same node, their values are identical.
- [ ] `npm run audit:data-cy -- --check` passes (manifest is up to date).
- [ ] If reusable primitives changed prop shape, this document and the
  manifest descriptions sidecar were updated.
