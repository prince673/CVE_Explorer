"""Background worker for continuous CVE monitoring."""
import asyncio
from datetime import datetime
from celery import shared_task
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/cve_explorer")
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


@shared_task(name="workers.check_new_kev")
def check_new_kev():
    """Check CISA KEV for new entries and generate alerts."""
    asyncio.run(_check_new_kev_async())


async def _check_new_kev_async():
    from ..services.cve_service import fetch_kev_catalog
    from ..models.cve import CVE
    from ..services.alert_service import create_alert

    kev = await fetch_kev_catalog()

    async with AsyncSessionLocal() as db:
        for cve_id, entry in kev.items():
            result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
            cve = result.scalar_one_or_none()
            if cve and not cve.in_kev:
                cve.in_kev = True
                cve.kev_due_date = entry.get("dueDate")
                await create_alert(db, alert_type="kev_update",
                    title=f"CVE {cve_id} added to CISA KEV",
                    message=f"Due date: {entry.get('dueDate', 'N/A')}",
                    severity="critical", cve_id=cve_id, source="CISA KEV")
        await db.commit()


@shared_task(name="workers.check_epss_changes")
def check_epss_changes():
    """Check for significant EPSS score changes."""
    asyncio.run(_check_epss_changes_async())


async def _check_epss_changes_async():
    from ..services.cve_service import fetch_epss
    from ..models.cve import CVE
    from ..services.alert_service import create_alert
    from sqlalchemy import and_

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CVE).where(
                and_(CVE.epss_probability.isnot(None), CVE.epss_probability >= 0.3)
            ).order_by(CVE.epss_probability.desc()).limit(50)
        )
        for cve in result.scalars().all():
            epss = await fetch_epss(cve.cve_id)
            if epss and epss.get("probability", 0) >= 0.7:
                old_prob = cve.epss_probability or 0
                new_prob = epss["probability"]
                if new_prob > old_prob * 1.2:
                    await create_alert(db, alert_type="epss_increase",
                        title=f"CVE {cve.cve_id} EPSS increased to {new_prob*100:.0f}%",
                        message=f"Probability rose from {old_prob*100:.0f}% to {new_prob*100:.0f}%",
                        severity="critical" if new_prob >= 0.7 else "high",
                        cve_id=cve.cve_id, source="EPSS")
                cve.epss_probability = new_prob
                cve.epss_percentile = epss.get("percentile")
        await db.commit()


@shared_task(name="workers.refresh_cve_cache")
def refresh_cve_cache():
    """Refresh stale CVE data from APIs."""
    asyncio.run(_refresh_cve_cache_async())


async def _refresh_cve_cache_async():
    from ..services.cve_service import get_or_create_cve
    from ..models.cve import CVE
    from datetime import timedelta

    async with AsyncSessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        result = await db.execute(
            select(CVE).where(CVE.updated_at < cutoff).order_by(CVE.updated_at.asc()).limit(10)
        )
        for cve in result.scalars().all():
            try:
                await get_or_create_cve(db, cve.cve_id)
            except Exception:
                pass
