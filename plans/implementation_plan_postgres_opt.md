# Fix PostgreSQL High CPU: JSON → JSONB Migration + GIN Index

## Problem

The production PostgreSQL DB is at ~100% CPU. The profiled heaviest query is:

```sql
SELECT alert.id, alert.tenant_id, alert.timestamp, alert.provider_type, alert.provider_id, alert.event, alert.fingerprint, alert.alert_hash
FROM alert
WHERE json_extract_path_text(alert.event, $1) = $2
```

**Root cause:** The `alert.event` column is declared as `JSON` (not `JSONB`). PostgreSQL's `JSON` type stores data as raw text and must **re-parse the entire blob on every row scan** — there is no binary representation and no indexing support. With a large [alert](file:///Users/yarin/keep/keep/common/core/db.py#1717-1788) table, every query that filters by a JSON field triggers a full sequential text-parse, saturating CPU.

## User Review Required

> [!CAUTION]
> The Alembic migration performs `ALTER COLUMN ... TYPE JSONB USING event::JSONB` on the [alert](file:///Users/yarin/keep/keep/common/core/db.py#1717-1788) table. On a very large table this acquires an **ACCESS EXCLUSIVE lock** and rewrites every row. This can take significant time and cause downtime. Consider:
> - Running during a maintenance window
> - Alternatively, creating a new JSONB column, backfilling in batches, then swapping — but that's more complex

> [!IMPORTANT]
> `AlertEnrichment.enrichments` is also `JSON`. It should be migrated to `JSONB` in the same window for consistency, though it is **not** the primary offender in the profiled query.

## Proposed Changes

### Alert Model

#### [MODIFY] [alert.py](file:///Users/yarin/keep/keep/common/models/db/alert.py)

Change `Alert.event` and `AlertEnrichment.enrichments` column types from `JSON` to `JSONB`.

```diff
-from sqlmodel import JSON, TEXT, Column, Field, Index, Relationship, SQLModel
+from sqlmodel import TEXT, Column, Field, Index, Relationship, SQLModel
+from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
+from sqlmodel import JSON
```

For PostgreSQL we need to conditionally use `JSONB`, while keeping `JSON` for SQLite/MySQL. We'll create a helper column type:

```diff
 # Line 122
-    event: dict = Field(sa_column=Column(JSON))
+    event: dict = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")))
```

```diff
 # Line 188
-    enrichments: dict = Field(sa_column=Column(JSON))
+    enrichments: dict = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")))
```

Also update `AlertDeduplicationRule.fingerprint_fields` (line 216), `AlertDeduplicationRule.ignore_fields` (line 218), and `AlertRaw.raw_alert` (line 293) the same way, since they also use `JSON` and could benefit.

---

### Database Utilities

#### [MODIFY] [db_utils.py](file:///Users/yarin/keep/keep/common/core/db_utils.py)

No changes needed here. The [get_json_extract_field](file:///Users/yarin/keep/keep/common/core/db_utils.py#169-176) function uses `func.json_extract_path_text()` for PostgreSQL. When the column type is `JSONB`, PostgreSQL automatically uses the JSONB-optimized code path for `json_extract_path_text`. The `->>` operator used by the CEL-to-SQL layer also works natively on JSONB. So the existing helper function works correctly with JSONB columns — the performance gain comes from the storage format change and GIN index.

---

### CEL-to-SQL Provider  

#### [MODIFY] [postgresql.py](file:///Users/yarin/keep/keep/common/core/cel_to_sql/sql_providers/postgresql.py)

The provider already uses `->>`  and `::JSONB` casts in several places. After the column becomes native JSONB, the `::JSONB` casts in [_json_contains_path](file:///Users/yarin/keep/keep/common/core/cel_to_sql/sql_providers/base.py#234-238) and [_visit_equal_for_array_datatype](file:///Users/yarin/keep/keep/common/core/cel_to_sql/sql_providers/base.py#399-405) become no-ops (safe, zero-cost). **No changes required** in this file.

---

### Alembic Migration

#### [NEW] [2026-03-19_json_to_jsonb.py](file:///Users/yarin/keep/keep/common/models/db/migrations/versions/2026-03-19_json_to_jsonb.py)

A new Alembic migration that:

1. **Converts `alert.event` from JSON to JSONB** (PostgreSQL only; skipped for SQLite/MySQL)
2. **Converts `alertenrichment.enrichments` from JSON to JSONB**
3. **Converts other JSON columns** (`alertdeduplicationrule`, `alertraw`) to JSONB
4. **Creates a GIN index** on `alert.event` to accelerate `@>`, `?`, `?|`, `?&` operators and jsonpath queries
5. **Creates a GIN index** on `alertenrichment.enrichments`

```python
# Pseudocode for the migration
def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # Only applies to PostgreSQL

    # Convert JSON → JSONB
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSONB USING event::JSONB")
    op.execute("ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSONB USING enrichments::JSONB")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN fingerprint_fields TYPE JSONB USING fingerprint_fields::JSONB")
    op.execute("ALTER TABLE alertdeduplicationrule ALTER COLUMN ignore_fields TYPE JSONB USING ignore_fields::JSONB")
    op.execute("ALTER TABLE alertraw ALTER COLUMN raw_alert TYPE JSONB USING raw_alert::JSONB")

    # Create GIN indexes for the most queried columns
    op.create_index("ix_alert_event_gin", "alert", ["event"], postgresql_using="gin")
    op.create_index("ix_alertenrichment_enrichments_gin", "alertenrichment", ["enrichments"], postgresql_using="gin")

def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.drop_index("ix_alertenrichment_enrichments_gin")
    op.drop_index("ix_alert_event_gin")
    
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSON USING event::JSON")
    op.execute("ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSON USING enrichments::JSON")
    # ... reverse other columns
```

> [!NOTE]
> The GIN index supports operators like `@>` (containment), `?` (key existence), and `jsonb_path_exists`. The existing `json_extract_path_text()` function and `->>`operator will **not** use the GIN index directly, but they will benefit enormously from JSONB's binary-parsed format (no re-parsing on each row). For further optimization, frequently queried fields (e.g. [status](file:///Users/yarin/keep/keep/common/core/db.py#2066-2073), [severity](file:///Users/yarin/keep/keep/common/core/db.py#4312-4317), `service`) could later be turned into **expression indexes** like: `CREATE INDEX idx_alert_event_status ON alert ((event->>'status'))`.

## Verification Plan

### Automated Tests

All existing tests should continue to pass since the functional behavior is identical — JSONB is a superset of JSON.

1. **CEL-to-SQL unit tests** (no DB required):
   ```bash
   cd /Users/yarin/keep && poetry run pytest tests/cel_to_sql/ -v
   ```
   These test the SQL string generation for PostgreSQL, MySQL, and SQLite. The PostgreSQL tests confirm `->>`operator usage.

2. **Alert-related tests** (use SQLite test DB):
   ```bash
   cd /Users/yarin/keep && poetry run pytest tests/test_search_alerts.py tests/test_search_alerts_configuration.py -v
   ```

3. **Full test suite sanity check**:
   ```bash
   cd /Users/yarin/keep && poetry run pytest tests/ -v --timeout=120 -x
   ```

### Manual Verification

After deploying the migration to a staging PostgreSQL instance:

1. **Verify column types changed:**
   ```sql
   SELECT column_name, data_type 
   FROM information_schema.columns 
   WHERE table_name = 'alert' AND column_name = 'event';
   -- Expected: data_type = 'jsonb'
   ```

2. **Verify GIN index exists:**
   ```sql
   SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'alert' AND indexname = 'ix_alert_event_gin';
   ```

3. **Verify query performance improvement:**
   ```sql
   EXPLAIN ANALYZE SELECT * FROM alert WHERE event->>'status' = 'firing' LIMIT 10;
   ```
   Compare execution time before and after the migration.

4. **Monitor CPU** after deployment — should drop significantly from the ~100% baseline.
