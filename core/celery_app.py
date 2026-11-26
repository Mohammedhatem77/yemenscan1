"""
Celery Application Initialization & Configuration for YemenScan.

Provides a robust, distributed task queue backed by Redis with
JSON serialization, task idempotency, and graceful fallback.
"""

import os
from celery import Celery

def _resolve_redis_url() -> str:
    """Intelligently resolves Redis URL, auto-adapting localhost -> redis when inside Docker, or redis -> 127.0.0.1 when on host."""
    url = os.getenv("CELERY_BROKER_URL") or os.getenv("REDIS_URL")
    if not url:
        try:
            import socket
            socket.gethostbyname("redis")
            url = "redis://redis:6379/0"
        except Exception:
            url = "redis://127.0.0.1:6379/0"
    elif "localhost" in url or "127.0.0.1" in url:
        try:
            import socket
            socket.gethostbyname("redis")
            url = url.replace("localhost", "redis").replace("127.0.0.1", "redis")
        except Exception:
            pass
    return url

REDIS_URL = _resolve_redis_url()
RESULT_BACKEND = REDIS_URL

celery_app = Celery(
    "yemenscan",
    broker=REDIS_URL,
    backend=RESULT_BACKEND,
    include=["core.tasks"]
)

# Celery Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_ignore_result=True,      # Avoid result store reconnection loops in async web processes
    worker_send_task_events=True, # Worker emits real-time events (received, started, succeeded) for Flower
    task_send_sent_event=False,   # Keep False to prevent web HTTP handlers from blocking on event pubsub
    task_time_limit=3600,         # 1 hour hard limit per scan task
    task_soft_time_limit=3300,    # 55 minutes soft limit
    worker_prefetch_multiplier=1, # Fair task distribution among workers
    task_acks_late=True,          # Acknowledge tasks only after successful execution (resilience)
    result_expires=86400,         # Task results kept in Redis for 24 hours
)


def is_celery_broker_reachable(timeout: float = 1.0) -> bool:
    """Checks if Redis broker is reachable to allow graceful fallback."""
    try:
        import redis
        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=timeout)
        return bool(client.ping())
    except Exception:
        return False
