"""Celery beat schedule for periodic monitoring tasks."""
from celery.schedules import crontab

beat_schedule = {
    "check-new-kev-every-6-hours": {
        "task": "workers.check_new_kev",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "check-epss-changes-every-12-hours": {
        "task": "workers.check_epss_changes",
        "schedule": crontab(minute=30, hour="*/12"),
    },
    "refresh-stale-cves-daily": {
        "task": "workers.refresh_cve_cache",
        "schedule": crontab(minute=0, hour=2),
    },
}
