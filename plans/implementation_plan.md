# Redis Cache Implementation — Task Breakdown

## Task 1: Configuration & Constants
- [ ] Add cache TTL constants to [keep/common/consts.py](file:///Users/yarin/keep/keep/common/consts.py)
- [ ] Verify [.env](file:///Users/yarin/keep/.env) already has `CACHE_REDIS_HOST` / `CACHE_REDIS_PORT` ✅
- [ ] Verify [pyproject.toml](file:///Users/yarin/keep/pyproject.toml/Users/yarin/keep/pyproject.toml) already has `redis >= 5.0` ✅

## Task 2: Cache Module (`keep/api/core/cache.py`)
- [ ] Create `cache.py` with `get_redis_client()`, `get_cached()`, `set_cached()`, `invalidate()`
- [ ] Use `model_dump()` serialization flow for Pydantic models before `orjson.dumps()`
- [ ] Add `X-Cache: HIT/MISS` response header helper

## Task 3: Alerts Caching ([alerts.py](file:///Users/yarin/keep/keep/api/routes/alerts.py))
- [ ] Cache [query_alerts](file:///Users/yarin/keep/keep/api/routes/alerts.py#183-237) (TTL 30s) — serialize [AlertDto](file:///Users/yarin/keep/keep/common/models/alert.py#71-334) list via `model_dump()`
- [ ] Cache [fetch_alert_facet_options](file:///Users/yarin/keep/keep/api/routes/alerts.py#82-122) (TTL 30s)
- [ ] Add invalidation to [receive_generic_event](file:///Users/yarin/keep/keep/api/routes/alerts.py#465-514), [enrich_alert](file:///Users/yarin/keep/keep/api/routes/alerts.py#845-883), [batch_enrich_alerts](file:///Users/yarin/keep/keep/api/routes/alerts.py#636-843), [delete_alert](file:///Users/yarin/keep/keep/api/routes/alerts.py#302-370)

## Task 4: Providers Caching ([providers.py](file:///Users/yarin/keep/keep/api/routes/providers.py))
- [ ] Cache [get_providers](file:///Users/yarin/keep/keep/api/routes/providers.py#68-111) (TTL 120s)
- [ ] Add invalidation to [install_provider](file:///Users/yarin/keep/keep/api/routes/providers.py#471-536), [delete_provider](file:///Users/yarin/keep/keep/api/routes/providers.py#368-386), [update_provider](file:///Users/yarin/keep/keep/api/routes/providers.py#431-469)

## Task 5: Presets Caching ([preset.py](file:///Users/yarin/keep/keep/api/routes/preset.py))
- [ ] Cache [get_presets](file:///Users/yarin/keep/keep/api/routes/preset.py#202-238) (TTL 300s) — serialize [PresetDto](file:///Users/yarin/keep/keep/common/models/db/preset.py#98-214) list via `model_dump()`
- [ ] Add invalidation to [create_preset](file:///Users/yarin/keep/keep/api/routes/preset.py#251-316), [update_preset](file:///Users/yarin/keep/keep/api/routes/preset.py#352-431), [delete_preset](file:///Users/yarin/keep/keep/api/routes/preset.py#318-350)

## Task 6: Incidents Caching ([incidents.py](file:///Users/yarin/keep/keep/api/routes/incidents.py))
- [ ] Cache [get_all_incidents](file:///Users/yarin/keep/keep/api/routes/incidents.py#125-209) (TTL 60s) — serialize [IncidentsPaginatedResultsDto](file:///Users/yarin/keep/keep/common/utils/pagination.py#19-21) via `model_dump()`
- [ ] Add invalidation to [create_incident](file:///Users/yarin/keep/keep/api/routes/incidents.py#92-108), [update_incident](file:///Users/yarin/keep/keep/api/routes/incidents.py#380-420), [delete_incident](file:///Users/yarin/keep/keep/api/routes/incidents.py#439-454), [bulk_delete_incidents](file:///Users/yarin/keep/keep/api/routes/incidents.py#422-437), [merge_incidents](file:///Users/yarin/keep/keep/api/routes/incidents.py#492-536), [split_incident](file:///Users/yarin/keep/keep/api/routes/incidents.py#456-490)

## Task 7: Tests
- [ ] Write `tests/test_api_cache.py` covering HIT/MISS/invalidation/fallback/disabled scenarios
