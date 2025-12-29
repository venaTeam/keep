import asyncio
import functools
import logging

from keep.api.tasks.process_event_task import process_event

logger = logging.getLogger(__name__)

async def process_event_wrapper(
    ctx: dict,
    tenant_id: str,
    provider_type: str,
    provider_id: str | None,
    fingerprint: str | None,
    api_key_name: str | None,
    trace_id: str | None,
    event: dict,
    notify_client: bool = True,
    timestamp_forced: str | None = None,
    provider_name: str | None = None,
):
    """
    Wrapper controller for processing events. 
    This is called by both the ARQ worker (ctx is populated) 
    and the Kafka Consumer (ctx is empty/dummy).
    """
    logger.info(
        f"Processing event: {trace_id}",
        extra={
            "tenant_id": tenant_id,
            "provider_type": provider_type,
            "provider_id": provider_id,
            "fingerprint": fingerprint,
            "trace_id": trace_id,
        },
    )

    # Prepare partial function for sync execution
    process_event_func_sync = functools.partial(
        process_event,
        ctx=ctx,
        tenant_id=tenant_id,
        provider_type=provider_type,
        provider_id=provider_id,
        fingerprint=fingerprint,
        api_key_name=api_key_name,
        trace_id=trace_id,
        event=event,
        notify_client=notify_client,
        timestamp_forced=timestamp_forced,
        provider_name=provider_name,
    )

    loop = asyncio.get_running_loop()
    
    # If in ARQ, use the provided thread pool. Else (Kafka), use default executor.
    executor = ctx.get("pool") if ctx else None
    
    resp = await loop.run_in_executor(executor, process_event_func_sync)
    
    logger.info(
        "Event processed successfully",
        extra={
            "tenant_id": tenant_id,
            "trace_id": trace_id,
        },
    )
    return resp
