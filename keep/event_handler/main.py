import logging
import uvicorn
from fastapi import FastAPI
from dotenv import find_dotenv, load_dotenv

import keep.api.logging
import keep.api.observability
from keep.api.core.config import config
from keep.event_handler.api.routes.v1 import health, metrics
from keep.event_handler.core.lifespan import lifespan

# Load environment variables
load_dotenv(find_dotenv())
keep.api.logging.setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Keep Event Handler",
    description="Microservice for handling background tasks and events",
    lifespan=lifespan,
)

# Include routers
app.include_router(health.router, prefix="/v1", tags=["health"])
app.include_router(metrics.router, prefix="/v1", tags=["metrics"])
# For backward compatibility / ease of use, logic at root is also handled in health router via @router.get("/")
app.include_router(health.router, tags=["root"])

if config("KEEP_OTEL_ENABLED", default="true", cast=bool):
    keep.api.observability.setup(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
