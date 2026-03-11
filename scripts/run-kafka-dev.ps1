# Start Keep backend + Kafka for local development
# Usage: .\scripts\run-kafka-dev.ps1
# Then: cd keep-ui && npm run dev
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

Write-Host "Starting Kafka, Postgres, Keep backend and event handler..." -ForegroundColor Cyan
docker compose -f docker-compose.kafka-dev.yml up -d --build

Write-Host "`nWaiting for services to be ready (30s)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host "`nServices status:" -ForegroundColor Green
docker compose -f docker-compose.kafka-dev.yml ps

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Start frontend: cd keep-ui; npm run dev"
Write-Host "  2. Open http://localhost:3000"
Write-Host "  3. Use Test alerts button in the UI to simulate an alert"
Write-Host "`nTo stop: docker compose -f docker-compose.kafka-dev.yml down"
