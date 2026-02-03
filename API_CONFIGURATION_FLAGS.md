# API Configuration Flags Reference

This document explains the responsibilities of key configuration flags found in `keep/api/api.py`.

## Feature Flags

### `TOPOLOGY` (Env: `KEEP_TOPOLOGY_PROCESSOR`)
*   **Responsibility**: Enables the **Topology Processor** service.
*   **Action**: Starts a background process that aggregates service dependency data from providers to build a map of your infrastructure. This is used to correlate alerts with services and visualize dependencies.

### `MAINTENANCE_WINDOWS` (Env: `MAINTENANCE_WINDOWS`)
*   **Responsibility**: Enables the **Maintenance Windows** feature.
*   **Action**: Allows users to define time periods where alerts are suppressed.
*   **Related**: If `MAINTENANCE_WINDOW_ALERT_STRATEGY` is set to `"recover_previous_status"`, the system also starts the **Watcher** service to monitor window expiration and restore alert statuses.

## Security & Performance

### `KEEP_USE_LIMITER` (Env: `KEEP_USE_LIMITER`)
*   **Responsibility**: Enables **API Rate Limiting**.
*   **Action**: Adds the `SlowAPIMiddleware` to the application. This enforces limits on the number of requests a user or IP can make, protecting the API from abuse (returning `429 Too Many Requests` when limits are exceeded).

## Debugging & Profiling

### `KEEP_DEBUG_TASKS` (Env: `KEEP_DEBUG_TASKS`)
*   **Responsibility**: **Task Monitoring**.
*   **Action**: Starts a background loop that logs the count of pending `asyncio` tasks every second.
*   **Use Case**: Detects "task leaks" or high concurrency load issues during development/debugging.
