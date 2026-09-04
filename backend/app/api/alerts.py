"""Alert management routes."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..services import alert_service

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/")
async def list_alerts(
    unread_only: bool = Query(False),
    alert_type: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    alerts = await alert_service.get_alerts(db, unread_only=unread_only, alert_type=alert_type)
    return [_alert_to_dict(a) for a in alerts]


@router.get("/unread-count")
async def unread_count(db: AsyncSession = Depends(get_db)):
    return {"count": await alert_service.get_unread_count(db)}


@router.patch("/{alert_id}/read")
async def mark_read(alert_id: int, db: AsyncSession = Depends(get_db)):
    await alert_service.mark_read(db, alert_id)
    return {"ok": True}


@router.post("/read-all")
async def mark_all_read(db: AsyncSession = Depends(get_db)):
    await alert_service.mark_all_read(db)
    return {"ok": True}


@router.patch("/{alert_id}/acknowledge")
async def ack_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    await alert_service.acknowledge_alert(db, alert_id)
    return {"ok": True}


def _alert_to_dict(a) -> dict:
    return {
        "id": a.id, "alert_type": a.alert_type, "title": a.title,
        "message": a.message, "severity": a.severity, "cve_id": a.cve_id,
        "source": a.source, "read": a.read, "acknowledged": a.acknowledged,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
