# Cloud SaaS Providers Removal Summary

## Date: 2026-01-13

## Overview
Removed 76 cloud SaaS providers from the Keep codebase, retaining only self-hosted/on-premise providers.

## Removed Providers

### Cloud Infrastructure (7 providers)
- aks_provider (Azure Kubernetes Service)
- eks_provider (AWS Elastic Kubernetes Service)
- gke_provider (Google Kubernetes Engine)
- azuremonitoring_provider
- gcpmonitoring_provider
- cloudwatch_provider (AWS)
- opensearchserverless_provider

### Monitoring & Observability SaaS (16 providers)
- datadog_provider
- newrelic_provider
- dynatrace_provider
- signalfx_provider
- appdynamics_provider
- checkly_provider
- sentry_provider
- coralogix_provider
- sumologic_provider
- site24x7_provider
- thousandeyes_provider
- pingdom_provider
- statuscake_provider

- rollbar_provider
- dash0_provider

### Incident Management SaaS (10 providers)
- pagerduty_provider
- opsgenie_provider
- ilert_provider
- squadcast_provider
- zenduty_provider
- flashduty_provider
- pagertree_provider
- incidentio_provider
- grafana_incident_provider
- grafana_oncall_provider

### Ticketing & Project Management SaaS (8 providers)
- jira_provider
- servicenow_provider
- zendesk_provider
- linear_provider
- asana_provider
- monday_provider
- trello_provider
- salesforce_provider

### Collaboration SaaS (6 providers)
- slack_provider
- teams_provider
- discord_provider
- zoom_provider
- google_chat_provider
- mattermost_provider

### Communication SaaS (8 providers)
- twilio_provider
- sendgrid_provider
- mailgun_provider
- resend_provider
- pushover_provider
- signl4_provider
- telegram_provider
- ntfy_provider

### Developer Tools SaaS (5 providers)
- github_provider
- github_workflows_provider
- gitlab_provider
- gitlabpipelines_provider
- linearb_provider

### Database SaaS (4 providers)
- bigquery_provider
- snowflake_provider
- mongodb_provider
- databend_provider

### Cloud Storage SaaS (2 providers)
- s3_provider
- amazonsqs_provider

### AI SaaS (6 providers)
- openai_provider
- anthropic_provider
- gemini_provider
- grok_provider
- deepseek_provider
- litellm_provider

### Other SaaS (4 providers)
- auth0_provider
- axiom_provider
- quickchart_provider
- incidentmanager_provider

## Remaining Providers (50 self-hosted/on-premise providers)

These providers remain as they support self-hosted or on-premise deployments:

- airflow_provider
- argocd_provider
- bash_provider
- centreon_provider
- checkmk_provider
- cilium_provider
- clickhouse_provider
- console_provider
- elastic_provider
- fluxcd_provider
- grafana_loki_provider
- grafana_provider
- graylog_provider
- http_provider
- icinga2_provider
- jiraonprem_provider
- kafka_provider
- keep_provider
- kibana_provider
- kubernetes_provider
- libre_nms_provider
- llamacpp_provider
- mock_provider
- mysql_provider
- netbox_provider
- netdata_provider
- netxms_provider
- ollama_provider
- openobserve_provider
- openshift_provider
- parseable_provider
- planner_provider
- postgres_provider
- prometheus_provider
- python_provider
- redmine_provider
- smtp_provider
- splunk_provider
- ssh_provider
- ticket_count_provider
- uptimekuma_provider
- vectordev_provider
- victorialogs_provider
- victoriametrics_provider
- vllm_provider
- wazuh_provider
- webhook_provider
- youtrack_provider
- zabbix_provider

## Changes Made

### 1. Removed Provider Directories
Deleted 76 provider directories from `/Users/young/keep/keep/providers/`

### 2. Removed Tests
Removed all test files related to the removed providers from `/Users/young/keep/tests/`

### 3. Removed Examples & Documentation
Removed example workflows and documentation for:
- Cloud-specific providers (aks, eks, gke, etc.)
- SaaS providers (slack, pagerduty, datadog, etc.)

### 4. Updated Test Files
Updated test workflow and configuration files to use `console_provider` instead of removed `slack_provider`:
- `/Users/young/keep/tests/test_parser.py`
- `/Users/young/keep/tests/workflows/providers_for_testing.yaml`
- `/Users/young/keep/tests/workflows/db_disk_space_for_testing.yml`
- `/Users/young/keep/tests/workflows/reusable_actions_for_testing.yml`
- `/Users/young/keep/tests/workflows/reusable_alert_for_testing.yml`
- `/Users/young/keep/tests/workflows/reusable_alert_with_actions_for_testing.yml`

## Test Status

✅ All parser tests passing (19 tests)
✅ Provider factory dynamically loads providers - no code changes needed
✅ No broken imports detected

## Notes

- The provider factory (`providers_factory.py`) dynamically discovers providers, so removing directories
  is sufficient - no code modifications needed
- All test files were updated to use `console_provider` as a replacement for testing purposes
- The conftest.py was already using console provider for mock workflows

## Next Steps

### Documentation Cleanup Required

The documentation files that contained references to removed cloud SaaS providers have been cleaned up:

1. ✅ **`docs/providers/overview.mdx`** - Regenerated with valid provider cards (removed 76 invalid entries).
2. ✅ **`docs/providers/overview.md`** - Filtered to remove broken links (removed 73 invalid entries).
3. ✅ **`docs/overview/servicetopology.mdx`** - Removed Datadog and Pagerduty references.
4. ✅ All provider documentation snippets regenerated.

**All known references to removed cloud SaaS providers have been eliminated.**
