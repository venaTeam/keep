# Fix PostgreSQL High CPU: JSON → JSONB + GIN Index

## Context

Production PostgreSQL is near 100% CPU. Profiling identified this as the heaviest query:

```sql
SELECT ... FROM alert WHERE json_extract_path_text(alert.event, $1) = $2
```

Root cause: `alert.event` is stored as `JSON` (raw text). PostgreSQL must re-parse the entire text blob on every row scanned — no binary representation, no index support. Migrating to `JSONB` (binary storage) eliminates the per-row re-parse and is the primary fix. A GIN index is added for the CEL-layer queries that already use `@>`/`?` operators.

---

## Changes

### 1. Model — `keep/common/models/db/alert.py`

Add import at the top:
```python
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
```

Change four columns from plain `JSON` to a dialect-aware variant:

| Line | Field | Change |
|------|-------|--------|
| 122 | `Alert.event` | `Column(JSON)` → `Column(JSON().with_variant(PG_JSONB, "postgresql"))` |
| 188 | `AlertEnrichment.enrichments` | same |
| 216 | `AlertDeduplicationRule.fingerprint_fields` | same |
| 218 | `AlertDeduplicationRule.ignore_fields` | same |
| 293 | `AlertRaw.raw_alert` | same |

`JSON().with_variant(...)` keeps SQLite/MySQL behavior unchanged; only PostgreSQL uses JSONB.

---

### 2. Alembic Migration — `keep/common/models/db/migrations/versions/2026-03-19-00-00_json_to_jsonb.py`

```python
"""json_to_jsonb

Revision ID: json_to_jsonb
Revises: a1b2c3d4e5f6
Create Date: 2026-03-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel

revision = "json_to_jsonb"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite/MySQL: no-op, JSON stays as-is

    # Convert JSON → JSONB (acquires ACCESS EXCLUSIVE lock per table)
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSONB USING event::JSONB")
    op.execute("ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSONB USING enrichments::JSONB")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN fingerprint_fields TYPE JSONB USING fingerprint_fields::JSONB")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN ignore_fields TYPE JSONB USING ignore_fields::JSONB")
    op.execute("ALTER TABLE alertraw ALTER COLUMN raw_alert TYPE JSONB USING raw_alert::JSONB")

    # GIN indexes — accelerate @> / ? operators used by the CEL-to-SQL layer
    op.create_index("ix_alert_event_gin", "alert", ["event"], postgresql_using="gin")
    op.create_index("ix_alertenrichment_enrichments_gin", "alertenrichment", ["enrichments"], postgresql_using="gin")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.drop_index("ix_alertenrichment_enrichments_gin", table_name="alertenrichment")
    op.drop_index("ix_alert_event_gin", table_name="alert")

    op.execute("ALTER TABLE alertraw ALTER COLUMN raw_alert TYPE JSON USING raw_alert::JSON")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN ignore_fields TYPE JSON USING ignore_fields::JSON")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN fingerprint_fields TYPE JSON USING fingerprint_fields::JSON")
    op.execute("ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSON USING enrichments::JSON")
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSON USING event::JSON")
```

---

### 3. No changes needed elsewhere

| File | Why |
|------|-----|
| `keep/common/core/db_utils.py` — `get_json_extract_field` | `json_extract_path_text()` and `json_unquote/json_extract` work correctly on JSONB columns. The binary-parse speedup applies automatically. |
| `keep/common/core/cel_to_sql/sql_providers/postgresql.py` | Already uses `::JSONB` cast in `_json_contains_path` (line 29-31) and `::jsonb @>` in `_visit_equal_for_array_datatype` (lines 150-170). These become true no-ops after the column is natively JSONB. |

---

## GIN Index Scope (Important)

The GIN index with default `jsonb_ops` accelerates:
- `@>` (containment) — used by `_visit_equal_for_array_datatype` in the CEL layer
- `?` / `?|` / `?&` (key existence) — used by `_json_contains_path`
- `jsonb_path_exists` — used by `_json_contains_path`

The GIN index does **NOT** accelerate `json_extract_path_text(event, 'status') = 'firing'` (the profiled query). That query benefits solely from JSONB's binary storage (no re-parse per row). If further optimization is needed for specific high-frequency scalar lookups, add expression indexes in a follow-up (e.g., `CREATE INDEX ON alert ((event->>'status'))`).

---

## Risks & Operational Considerations

### 1. ACCESS EXCLUSIVE Lock — Full Table Downtime

`ALTER TABLE ... TYPE JSONB` acquires an `ACCESS EXCLUSIVE` lock on the `alert` table for the **entire duration of the rewrite**. This is the most serious risk:

- **All reads and writes to `alert` are blocked** until the rewrite finishes.
- Any queries that arrive while the lock is held will queue up. If they queue long enough, the application connection pool saturates and new requests start failing immediately.
- Duration scales linearly with table size — a 50M-row table can take 10–30 minutes or more.

**Mitigation**: Set `lock_timeout` before running the migration:
```sql
SET lock_timeout = '5s';
ALTER TABLE alert ALTER COLUMN event TYPE JSONB USING event::JSONB;
```

### 2. Should Writes Be Stopped?

**Yes, ideally stop the application (or put it in maintenance mode) before running the migration.** Recommended procedure:
1. Scale down event handler consumers (Kafka/ARQ workers) to 0.
2. Run the migration.
3. Scale consumers back up — they will replay any buffered Kafka events.

### 3. Replication Lag (if using streaming replication / read replicas)

Every row rewrite produces WAL records. Monitor `pg_stat_replication` and wait for replicas to catch up before restoring full traffic.

### 4. Disk Space Spike

The rewrite creates a new version of every page on disk. You need **~2× the current size of the `alert` table** free in the PostgreSQL data directory. Check with:
```sql
SELECT pg_size_pretty(pg_total_relation_size('alert'));
```

### 5. JSONB Key-Order Semantic Difference — Code Audit Results

JSONB stores keys in sorted order. When Python reads a JSONB value back from PostgreSQL via `psycopg2`, the resulting `dict` has alphabetically-sorted keys.

**Audit of the codebase for order-sensitive code:**

| File | Line | Pattern | Safe? |
|------|------|---------|-------|
| `keep/common/alert_deduplicator/alert_deduplicator.py` | 67 | `json.dumps(alert_copy.dict(), sort_keys=True)` → SHA-256 | ✅ Safe |
| `keep/common/bl/ai_suggestion_bl.py` | 78 | `json.dumps(suggestion_input, sort_keys=True)` → SHA-256 | ✅ Safe |
| `keep/providers/prometheus_provider/prometheus_provider.py` | 281 | `json.dumps(labels, sort_keys=True)` → MD5 | ✅ Safe |
| `keep/providers/grafana_provider/grafana_provider.py` | 1463 | `json.dumps(alert_payload, sort_keys=True)` → MD5 | ✅ Safe |
| `keep/common/models/alert.py` | 28 | `json.dumps(values)` → SHA-256 (no `sort_keys`) | ✅ Fixed |
| `keep/providers/base/base_provider.py` | 526 | `json.dumps(fingerprint_field_value)` → SHA-256 (no `sort_keys`) | ✅ Fixed |

**Fix applied (Step 1, before migration):**

`keep/common/models/alert.py:28`:
```python
# Before
fingerprint_payload = json.dumps(values)
# After
fingerprint_payload = json.dumps(values, sort_keys=True)
```

`keep/providers/base/base_provider.py:526`:
```python
# Before
fingerprint_field_value = json.dumps(fingerprint_field_value)
# After
fingerprint_field_value = json.dumps(fingerprint_field_value, sort_keys=True)
```

### 6. Post-Migration: Run VACUUM ANALYZE

```sql
VACUUM ANALYZE alert;
VACUUM ANALYZE alertenrichment;
```

### 7. Alternative: Zero-Downtime Online Migration (if table is too large)

1. Add `event_jsonb JSONB NULL` column (instant, no lock).
2. Backfill in small batches with `UPDATE alert SET event_jsonb = event::JSONB WHERE id BETWEEN $1 AND $2`.
3. Deploy application code that writes to **both** `event` (JSON) and `event_jsonb` (JSONB).
4. Once backfill is 100% complete, swap queries to read from `event_jsonb`.
5. Drop old `event` column.

---

## Recommended Procedure (Standard Maintenance Window)

1. Announce maintenance window.
2. Scale Kafka/ARQ consumers to 0 (events buffer in Kafka; no data loss).
3. Optionally put the UI in read-only or maintenance mode.
4. Run `VACUUM ANALYZE alert` first to reduce dead tuples and speed up the rewrite.
5. Apply the Alembic migration: `poetry run alembic -c keep/alembic.ini upgrade head`
6. Run `VACUUM ANALYZE alert; VACUUM ANALYZE alertenrichment;` after.
7. Confirm column types and GIN index (verification queries below).
8. Scale consumers back up; monitor CPU.

> **MAINTENANCE WINDOW REQUIRED.**
> `ALTER TABLE alert ALTER COLUMN event TYPE JSONB` acquires an `ACCESS EXCLUSIVE` lock and rewrites every row. On a large table this will cause downtime proportional to table size. Run during a scheduled window.

---

## Implementation Task List

- [x] **Step 1 — Pre-migration code fix (sort_keys)**
  - `keep/common/models/alert.py:28`: added `sort_keys=True` to `json.dumps(values)`
  - `keep/providers/base/base_provider.py:526`: added `sort_keys=True` to `json.dumps(fingerprint_field_value)`

- [x] **Step 2 — Update SQLModel column definitions**
  - `keep/common/models/db/alert.py`: added `from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB`
  - Changed 5 JSON columns to use `JSON().with_variant(PG_JSONB, "postgresql")`

- [ ] **Step 3 — Apply Alembic migration** *(maintenance window)*
  1. **Pre-migration**: `VACUUM ANALYZE alert; VACUUM ANALYZE alertenrichment;`
  2. Scale Kafka/ARQ consumers to 0
  3. Apply: `poetry run alembic -c keep/alembic.ini upgrade head`
  4. **Post-migration**: `VACUUM ANALYZE alert; VACUUM ANALYZE alertenrichment;`
  5. Verify column types and GIN indexes
  6. Scale consumers back up; monitor CPU and replication lag

---

## Verification

### Automated tests

```bash
# CEL-to-SQL unit tests (no DB needed)
poetry run pytest tests/cel_to_sql/ -v

# Alert search tests (use SQLite, validate functional equivalence)
poetry run pytest tests/test_search_alerts.py tests/test_search_alerts_configuration.py -v

# Full unit suite
poetry run pytest --timeout 20 -n auto --non-integration --ignore=tests/e2e_tests/
```

### Manual verification on PostgreSQL after migration

```sql
-- 1. Confirm column types changed
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'alert' AND column_name = 'event';
-- Expected: data_type = 'jsonb'

-- 2. Confirm GIN index exists
SELECT indexname, indexdef FROM pg_indexes
WHERE tablename = 'alert' AND indexname = 'ix_alert_event_gin';

-- 3. Compare query plan before/after
EXPLAIN ANALYZE SELECT * FROM alert WHERE json_extract_path_text(event, 'status') = 'firing' LIMIT 100;
```

Monitor PostgreSQL CPU after deployment — should drop significantly from the ~100% baseline.
