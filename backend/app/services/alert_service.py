"""Alert management service."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..models.alert import Alert


async def get_alerts(
    db: AsyncSession,
    unread_only: bool = False,
    alert_type: str | None = None,
) -> list[Alert]:
    """Fetch alerts with optional filters."""
    query = select(Alert).order_by(Alert.created_at.desc())
    if unread_only:
        query = query.where(Alert.read == False)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_unread_count(db: AsyncSession) -> int:
    """Count unread alerts."""
    result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.read == False)
    )
    return result.scalar() or 0


async def mark_read(db: AsyncSession, alert_id: int) -> None:
    """Mark a single alert as read."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert:
        alert.read = True
        await db.commit()


async def mark_all_read(db: AsyncSession) -> None:
    """Mark all alerts as read."""
    result = await db.execute(select(Alert).where(Alert.read == False))
    for alert in result.scalars().all():
        alert.read = True
    await db.commit()


async def acknowledge_alert(db: AsyncSession, alert_id: int) -> None:
    """Acknowledge a single alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert:
        alert.acknowledged = True
        await db.commit()
