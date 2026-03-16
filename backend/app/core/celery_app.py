from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "cyberguard",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.services.scanner.tasks",
        "app.services.monitoring.tasks",
        "app.services.notifications.tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.services.scanner.tasks.*": {"queue": "scans"},
        "app.services.monitoring.tasks.*": {"queue": "monitoring"},
        "app.services.notifications.tasks.*": {"queue": "notifications"},
    },
    beat_schedule={
        "run-daily-monitoring": {
            "task": "app.services.monitoring.tasks.run_all_monitors",
            "schedule": crontab(hour=6, minute=0),
        },
        "check-ssl-expiry": {
            "task": "app.services.monitoring.tasks.check_ssl_expiry_alerts",
            "schedule": crontab(hour=7, minute=0),
        },
        "check-domain-expiry": {
            "task": "app.services.monitoring.tasks.check_domain_expiry_alerts",
            "schedule": crontab(hour=7, minute=30),
        },
        "cleanup-old-logs": {
            "task": "app.services.monitoring.tasks.cleanup_old_logs",
            "schedule": crontab(hour=2, minute=0, day_of_week=0),
        },
    },
)
