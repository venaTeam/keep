# Start Keep backend with Redis (simpler than Kafka)
# Usage: .\scripts\run-redis-dev.ps1
# Then: cd keep-ui && npm run dev
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

Write-Host "Starting Postgres, Redis, Keep backend and event handler (no frontend - run npm run dev separately)..." -ForegroundColor Cyan
docker compose -f docker-compose-lite.yml up -d --build postgres keep-arq-redis keep-backend keep-event-handler

Write-Host "`nWaiting for services to be ready (25s)..." -ForegroundColor Yellow
Start-Sleep -Seconds 25

Write-Host "`nServices status:" -ForegroundColor Green
docker compose -f docker-compose-lite.yml ps

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Start frontend: cd keep-ui; npm run dev"
Write-Host "  2. Open http://localhost:3000"
Write-Host "  3. Use Test alerts button in the UI to simulate an alert"
Write-Host "`nTo stop: docker compose -f docker-compose-lite.yml down"
Write-Host "`nNote: Frontend runs separately (npm run dev) for hot reload."
