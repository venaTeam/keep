DBA raised a question, since the json_extract_path_text() function is used in the query, does the GIN index help actually ? The DBA says it might interrupt the planner working with the desired index, is 
                                                                                                                                                                                                                 
he right with his assumption ?                                                                                                                                                                                   
                                                                                                                                                                                                                 
⏺ Your DBA is correct, and the plan already acknowledges this — let me be precise about what's happening.                                                                                                        
                                                                                                                                                                                                               
  json_extract_path_text() and the GIN index                                                                                                                                                                     
                                                                                                                                                                                                                 
  The profiled query is:                                                                                                                                                                                         
  SELECT ... FROM alert WHERE json_extract_path_text(alert.event, 'status') = 'firing'                                                                                                                           
                                                                                                                                                                                                                 
  The GIN index with jsonb_ops operator class supports only these operators:                                                                                                                                     
  - @> (containment)                                                                                                                                                                                             
  - ?, ?|, ?& (key existence)                                                                                                                                                                                    
  - jsonb_path_exists                                                                                                                                                                                            
                                                                                                                                                                                                                 
  json_extract_path_text() is not in that list. The planner cannot use the GIN index for this query — it will always do a sequential scan. So the GIN index provides zero benefit for the specific query causing
  the CPU spike.                                                                                                                                                                                                 
                                                            
  What the GIN index actually helps with                                                                                                                                                                         
                                                            
  The GIN index only accelerates the CEL layer queries in postgresql.py that use ::jsonb @> and JSONB_PATH_EXISTS. Those are secondary queries, not the hot path.                                                
                                                            
  What actually fixes the CPU problem                                                                                                                                                                            
                                                            
  Solely the JSON → JSONB column type change. JSONB stores data in a pre-parsed binary format, so PostgreSQL doesn't re-parse the raw text blob on every row during the sequential scan. The scan still happens, 
  but it's significantly cheaper.
                                                                                                                                                                                                                 
  Is the DBA right about the GIN index "interrupting" the planner?

  Not exactly — the planner won't misuse the GIN index for json_extract_path_text() since it knows the operator isn't supported. But the DBA's concern is valid in a different sense: GIN indexes are large and  
  expensive to maintain (every INSERT/UPDATE on alert must update it). If the CEL @>/? queries are infrequent or fast enough without it, the GIN index is net-negative: write overhead with no read benefit for
  the hot path.                                                                                                                                                                                                  
                                                            
  Recommendation

  If the primary goal is fixing the CPU spike, the GIN index is optional and can be deferred. The migration can safely be run without it:                                                                        
   
  # Can remove these two lines from upgrade() if GIN isn't justified yet:                                                                                                                                        
  op.create_index("ix_alert_event_gin", "alert", ["event"], postgresql_using="gin")                                                                                                                              
  op.create_index("ix_alertenrichment_enrichments_gin", "alertenrichment", ["enrichments"], postgresql_using="gin")                                                                                              
                                                                                                                                                                                                                 
  If specific scalar lookups on event remain slow after the JSONB migration, the right follow-up is expression indexes, not GIN:                                                                                 
  CREATE INDEX ON alert ((event->>'status'));                                                                                                                                                                    
  CREATE INDEX ON alert ((event->>'severity'));                                                                                                                                                                  
  These are small, fast to scan, and directly support event->>'status' = 'firing' style queries that the planner can use.
                                                                                                                                                                                                                 
❯ Where does the query operation originate from? "SELECT ... FROM alert WHERE json_extract_path_text(alert.event, $1) = $2                                                                                       
", I see the CPU spiking when we load a dashboard that has about 10-20 widgets, each has it's own query and has a preset linked to it, will this optimization help the dashboard loading? Are there any other    
optimizations that can be made to improve this ? As usually preset cels are "source=='grafana' && status=='firing'"                                                                                              
                                                                                                                                                                                                                 
  Searched for 2 patterns (ctrl+o to expand)                                                                                                                                                                     
                                                                                                                                                                                                                 
⏺ Now let me look at the PostgreSQL CEL provider's json_extract_as_text and how presets feed into alert queries:                                                                                                 
                             
  Searched for 6 patterns, read 3 files (ctrl+o to expand)                                                                                                                                                       
                                                                                                                                                                                                                 
⏺ Now I have a full picture. Let me trace the complete path.                                                                                                                                                     
                                                                                                                                                                                                                 
  ---                                                                                                                                                                                                            
  Where json_extract_path_text() comes from                                                                                                                                                                      
                                                                                                                                                                                                                 
  It originates from db_utils.py:get_json_extract_field() (db_utils.py:171), which is called from various internal functions in db.py — things like get_alerts_by_status, topology queries, incident             
  severity/source tracking, and dismissal expiry logic. This is NOT the dashboard widget path.                                                                                                                   
                                                            
  ---                                                                                                                                                                                                            
  How dashboard preset queries actually work                
                                            
  The dashboard widgets hit POST /alerts → query_last_alerts() → __build_query_for_filtering() → cel_to_sql_instance.convert_to_sql_str_v2(cel).
                                                                                                                                                                                                                 
  The CEL-to-SQL layer uses completely different operators. For source=='grafana' && status=='firing':                                                                                                           
                                                                                                                                                                                                                 
  source=='grafana' — source is an array type, handled by _visit_equal_for_array_datatype (postgresql.py:170):                                                                                                   
  alert.event::jsonb @> '["grafana"]'                       
                                                                                                                                                                                                                 
  status=='firing' — handled by json_extract_as_text (postgresql.py:27), which generates ->>:
  COALESCE(                                                                                                                                                                                                      
    (alertenrichment.enrichments) ->> 'status',             
    (alert.event) ->> 'status'                                                                                                                                                                                   
  ) = 'firing'                                                                                                                                                                                                   
              
  No json_extract_path_text() anywhere in the dashboard path.                                                                                                                                                    
                                                                                                                                                                                                                 
  ---
  Does the JSONB migration help the dashboard?                                                                                                                                                                   
                                                            
  Yes, meaningfully. Even without indexes, JSONB changes the storage format from raw text to a pre-parsed binary B-tree. Every ->> key lookup on JSONB is O(log n) (binary search over sorted keys) vs O(n)
  (linear text scan from the start of the blob) on JSON. With 20 concurrent widget queries each scanning thousands of rows, this compounds quickly.                                                              
   
  ---                                                                                                                                                                                                            
  Does the GIN index help the dashboard?                    
                                        
  Partially. Revisiting my earlier answer:
                                                                                                                                                                                                                 
  ┌────────────────────────┬─────────────────────────────────┬───────────────────────────────────────────────┐                                                                                                   
  │        Operator        │             Used by             │                  GIN helps?                   │                                                                                                   
  ├────────────────────────┼─────────────────────────────────┼───────────────────────────────────────────────┤                                                                                                   
  │ @> (source=='grafana') │ _visit_equal_for_array_datatype │ ✅ Yes — GIN jsonb_ops directly supports @> │  │
  ├────────────────────────┼─────────────────────────────────┼───────────────────────────────────────────────┤
  │ ->> (status=='firing') │ json_extract_as_text            │ ❌ No — GIN doesn't index ->> text extraction │                                                                                                    
  └────────────────────────┴─────────────────────────────────┴───────────────────────────────────────────────┘                                                                                                   
                                                                                                                                                                                                                 
  So the GIN index benefits source filter queries but not status or severity scalar comparisons.                                                                                                                 
                                                            
  ---                                                                                                                                                                                                            
  Best additional optimizations for the dashboard           
                                                 
  Given the common preset pattern source=='grafana' && status=='firing', the highest-value additions are expression indexes on the scalar fields that ->> produces:
                                                                                                                                                                                                                 
  -- Directly accelerates status=='firing', status=='resolved', etc.
  CREATE INDEX ix_alert_event_status ON alert ((event->>'status'));                                                                                                                                              
                                                            
  -- Directly accelerates severity comparisons                                                                                                                                                                   
  CREATE INDEX ix_alert_event_severity ON alert ((event->>'severity'));
                                                                                                                                                                                                                 
  -- Accelerates enrichment-side status (overridden status)                                                                                                                                                      
  CREATE INDEX ix_enrichment_status ON alertenrichment ((enrichments->>'status'));
                                                                                                                                                                                                                 
  These are small, cheap to maintain (updated only when status/severity changes), and the planner can use them directly for equality comparisons from preset CELs.                                               
                                                                                                                                                                                                                 
  The GIN index on event is still worthwhile for source containment queries, but dropping it is also safe if write throughput is more important.                                                                 
                                                            
✻ Churned for 1m 45s                                                                                                                                                                                             
                                                                                          
❯ There more fields to an alert that are commonly used like "application" and "operator", should those be indexed aswell ?                                                                                       
                                                                                                                                                                                                                 
  Searched for 2 patterns (ctrl+o to expand)                                                                                                                                                                     
                                                                                                                                                                                                                 
⏺ These fields are not in the standard alert schema — no match in alert_field_configurations or AlertDto. That's the key issue: application and operator are custom fields that live inside the event JSON blob  
  or alertenrichment.enrichments as dynamic enrichments. They'd be accessed via the wildcard * mapping and generate queries like:
                                                                                                                                                                                                                 
  COALESCE(                                                                                                                                                                                                      
    (alertenrichment.enrichments) ->> 'application',                                                                                                                                                             
    (alert.event) ->> 'application'                                                                                                                                                                              
  ) = 'myapp'                                               
                                                                                                                                                                                                                 
  The short answer: expression indexes would help for these specific fields, but this approach doesn't scale.                                                                                                    
   
  Expression indexes require knowing the field name at creation time:                                                                                                                                            
  CREATE INDEX ON alert ((event->>'application'));          
  CREATE INDEX ON alertenrichment ((enrichments->>'application'));                                                                                                                                               
                                                                                                                                                                                                                 
  This works fine if application and operator are truly universal across your tenants. But since Keep supports arbitrary enrichment fields — any provider can push any key into event or enrichments — you'd be
  playing whack-a-mole: every time a team adds a new commonly-filtered field to their presets, someone needs to manually create an index.                                                                        
                                                            
  The more scalable alternatives:                                                                                                                                                                                
                                                            
  1. Promote high-frequency fields to real columns — if application and operator are always present and always filtered on, they deserve to be first-class columns on Alert or AlertEnrichment (indexed by       
  default, no JSON overhead). This is a schema migration but pays off permanently.
  2. Dynamic expression index creation based on AlertField usage — the AlertField table already tracks which fields exist per tenant. You could build a background job that identifies fields appearing in preset
   CELs above a usage threshold and auto-creates expression indexes for them. Complex to build, but fully automatic.                                                                                             
  3. Accept the JSONB sequential scan for custom fields — after the JSON→JSONB migration, ->> on JSONB is already much cheaper than before (binary lookup vs text parse). For fields with reasonable row counts,
  this may be acceptable without indexes.                                                                                                                                                                        
                                                            
  Practical recommendation: Add expression indexes for application and operator only if you can confirm they're present in the majority of alerts and appear in presets across most tenants. Otherwise, option 1 
  (real columns) is the right architectural move for fields that are truly universal.
                                                                                                                                                                                                                 
 In our Keep deployment we only use one provider that actually has a strict schema, which is not apart of AlertDTO but does not change over time and the amount of custom fields of an alert is limited and     
well known.                                                                                                                                                                                                      
                                                                                                                                                                                                                 
⏺ That changes things significantly — if the schema is fixed and well-known, promoting those fields to real columns is the right call, not expression indexes.                                                   
                                                                                                                                                                                                               
  Real columns give you:                                                                                                                                                                                         
  - Standard B-tree indexes (far cheaper to maintain than GIN, faster for equality/range)
  - Type safety and validation at the DB level                                                                                                                                                                   
  - Clean query plans with no JSON extraction overhead at all for those fields                                                                                                                                 
  - No COALESCE/fallback logic needed in queries                                                                                                                                                                 
                                                                                                                                                                                                                 
  To move forward properly, I need to understand the actual schema. Can you share:                                                                                                                               
                                                                                                                                                                                                                 
  1. The full list of custom fields your provider pushes (the fixed schema you mentioned)                                                                                                                        
  2. Which fields are commonly used in preset CELs (i.e., which ones actually need indexes)                                                                                                                      
  3. Where they currently land — are they in alert.event, alertenrichment.enrichments, or both?                                                                                                                  
                                                                                                                                                                                                                 
  With that I can plan the right migration: new columns on Alert (or a dedicated table if the field count is large), proper indexes, and the query layer changes needed to stop going through JSON for those     
  fields.               

This is the situation for now, but in the future we might add couple more providers that will have their own costum fields. So perhaps its better to keep the current jsonb column instead of actual column    
for each custom field ? and they are held in alert.event or alertenrichment.enrichments                                                                                                                          
                                                                                                                                                                                                                 
⏺ Then expression indexes are exactly the right call — you get index performance for your known fields today, and the JSONB column stays flexible for future providers without any schema changes.               
                                                                                                                                                                                                                 
  The pattern is clean: when a new provider lands and its fields start appearing in presets, you add expression indexes for those fields in a new migration. No column additions, no model changes, no           
  application code changes — just a migration file.
                                                                                                                                                                                                                 
  For your current provider, the migration would look like this alongside (or as a follow-up to) the JSONB migration:                                                                                            
   
  def upgrade() -> None:                                                                                                                                                                                         
      bind = op.get_bind()                                                                                                                                                                                       
      if bind.dialect.name != "postgresql":
          return                                                                                                                                                                                                 
                                                            
      # Known high-frequency preset filter fields — current provider                                                                                                                                             
      op.execute("CREATE INDEX ix_alert_event_status     ON alert ((event->>'status'))")
      op.execute("CREATE INDEX ix_alert_event_severity   ON alert ((event->>'severity'))")                                                                                                                       
      op.execute("CREATE INDEX ix_alert_event_application ON alert ((event->>'application'))")                                                                                                                   
      op.execute("CREATE INDEX ix_alert_event_operator    ON alert ((event->>'operator'))")                                                                                                                      
                                                                                                                                                                                                                 
      # Enrichment-side overrides for the same fields                                                                                                                                                            
      op.execute("CREATE INDEX ix_enrichment_status      ON alertenrichment ((enrichments->>'status'))")                                                                                                         
      op.execute("CREATE INDEX ix_enrichment_application ON alertenrichment ((enrichments->>'application'))")                                                                                                    
      op.execute("CREATE INDEX ix_enrichment_operator    ON alertenrichment ((enrichments->>'operator'))")
                                                                                                                                                                                                                 
                                                            
  def downgrade() -> None:                                                                                                                                                                                       
      bind = op.get_bind()                                  
      if bind.dialect.name != "postgresql":                                                                                                                                                                      
          return
                                                                                                                                                                                                                 
      op.execute("DROP INDEX IF EXISTS ix_enrichment_operator")
      op.execute("DROP INDEX IF EXISTS ix_enrichment_application")
      op.execute("DROP INDEX IF EXISTS ix_enrichment_status")                                                                                                                                                    
      op.execute("DROP INDEX IF EXISTS ix_enrichment_severity")
      op.execute("DROP INDEX IF EXISTS ix_alert_event_operator")                                                                                                                                                 
      op.execute("DROP INDEX IF EXISTS ix_alert_event_application")
      op.execute("DROP INDEX IF EXISTS ix_alert_event_severity")                                                                                                                                                 
      op.execute("DROP INDEX IF EXISTS ix_alert_event_status")                                                                                                                                                   
                                                                                                                                                                                                                 
  Two things worth noting:                                                                                                                                                                                       
                                                            
  1. These indexes are only useful after the JSONB migration. On a JSON column, expression indexes on ->> still require text parsing at index-build time and don't give you the binary lookup benefit. Run this  
  migration after json_to_jsonb completes.
  2. Cardinality matters. status and severity have very few distinct values — PostgreSQL may ignore the index for those if selectivity is too low (e.g., 50% of rows are firing). In that case, a partial index  
  is more effective:                                                                                                                                                                                             
  CREATE INDEX ix_alert_event_status_firing ON alert ((event->>'status')) WHERE (event->>'status') = 'firing';
  application and operator are likely high-cardinality (many distinct values), so standard expression indexes will work well there.            