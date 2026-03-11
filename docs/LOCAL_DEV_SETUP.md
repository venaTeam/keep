# Local Development Setup for Keep

This guide helps you run Keep locally for testing real-time alerts (SSE).

## Prerequisites

- **Docker Desktop** (must be running)
- **Node.js** for the frontend

## Option 1: Kafka (recommended for production-like flow)

```powershell
# 1. Start Docker Desktop
# 2. Start the stack
.\scripts\run-kafka-dev.ps1

# 3. In another terminal, start the frontend
cd keep-ui
npm run dev

# 4. Open http://localhost:3000 and go to a preset (e.g. /alerts/feed)
# 5. Use the Test alerts button in the UI to simulate an alert
```

## Option 2: Redis (simpler, faster startup)

```powershell
# 1. Start Docker Desktop
# 2. Start the stack
.\scripts\run-redis-dev.ps1

# 3. In another terminal, start the frontend
cd keep-ui
npm run dev

# 4. Open http://localhost:3000 and go to a preset
# 5. Simulate an alert
Use the Test alerts button in the UI
```

## Option 3: Frontend only (backend already running)

If you have the backend running elsewhere (e.g. another Docker setup):

```powershell
cd keep-ui
npm run dev
# Use the Test alerts button in the UI to simulate an alert
```

Set `API_URL` if your backend is not at `http://localhost:8080`:

```powershell
$env:API_URL = "http://your-backend:port"
# Use the Test alerts button in the UI to simulate an alert
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Docker pipe not found" | Start Docker Desktop |
| "Connection refused" on simulate | Ensure backend is running; wait 30s after `docker compose up` |
| Alerts don't appear in real time | Check SSE connection in DevTools Network tab; ensure event handler is running |

## Files

- `docker-compose.kafka-dev.yml` - Kafka + backend + event handler
- `docker-compose-lite.yml` - Redis + backend + event handler
- Use the Test alerts button in the preset manager to simulate an alert
