"""Remediation tracking routes."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..database import get_db
from ..models.remediation import RemediationRecord
from ..schemas.remediation import RemediationBase, RemediationUpdate, RemediationResponse

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])

STATUSES = ["open", "assigned", "in_progress", "fixed", "verified", "closed"]
PRIORITIES = ["p1_critical", "p2_high", "p3_medium", "p4_low"]


@router.get("/{cve_id}")
async def get_remediation_for_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RemediationRecord).where(RemediationRecord.cve_id == cve_id).order_by(RemediationRecord.created_at.desc())
    )
    return [_record_to_dict(r) for r in result.scalars().all()]


@router.post("/")
async def create_remediation(data: RemediationBase, db: AsyncSession = Depends(get_db)):
    record = RemediationRecord(
        cve_id=data.cve_id, asset_id=data.asset_id, priority=data.priority,
        assigned_to=data.assigned_to, notes=data.notes, due_date=data.due_date,
        status="open",
        history=[{"action": "created", "timestamp": datetime.utcnow().isoformat()}],
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return _record_to_dict(record)


@router.patch("/{record_id}")
async def update_remediation(record_id: int, data: RemediationUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RemediationRecord).where(RemediationRecord.id == record_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    if data.status:
        record.status = data.status
        record.history = (record.history or []) + [
            {"action": f"status_changed_to_{data.status}", "timestamp": datetime.utcnow().isoformat()}
        ]
    if data.assigned_to is not None:
        record.assigned_to = data.assigned_to
    if data.notes is not None:
        record.notes = data.notes
    if data.due_date is not None:
        record.due_date = data.due_date
    await db.commit()
    await db.refresh(record)
    return _record_to_dict(record)


@router.get("/stats/overview")
async def get_remediation_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(RemediationRecord))).scalar() or 0
    closed = (await db.execute(select(func.count()).select_from(RemediationRecord).where(RemediationRecord.status.in_(["verified", "closed"])))).scalar() or 0
    open_count = (await db.execute(select(func.count()).select_from(RemediationRecord).where(RemediationRecord.status == "open"))).scalar() or 0
    in_progress = (await db.execute(select(func.count()).select_from(RemediationRecord).where(RemediationRecord.status == "in_progress"))).scalar() or 0
    return {"total": total, "closedCount": closed, "openCount": open_count, "inProgressCount": in_progress}


def _record_to_dict(r: RemediationRecord) -> dict:
    return {
        "id": r.id, "cve_id": r.cve_id, "asset_id": r.asset_id, "status": r.status,
        "priority": r.priority, "assigned_to": r.assigned_to, "notes": r.notes,
        "due_date": r.due_date.isoformat() if r.due_date else None,
        "history": r.history or [], "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }
