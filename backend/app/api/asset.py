"""Asset inventory management routes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..database import get_db
from ..models.asset import Asset, AssetSoftware
from ..schemas.asset import AssetCreate, AssetResponse
from ..services.correlation import find_cves_for_asset

router = APIRouter(prefix="/api/assets", tags=["Assets"])


@router.get("/")
async def list_assets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).order_by(Asset.created_at.desc()))
    assets = result.scalars().all()
    return [_asset_to_dict(a) for a in assets]


@router.post("/", response_model=AssetResponse)
async def create_asset(data: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset = Asset(
        name=data.name, asset_type=data.asset_type, hostname=data.hostname,
        ip_address=data.ip_address, environment=data.environment,
        internet_facing=data.internet_facing, criticality=data.criticality,
        owner=data.owner, tags=data.tags or [],
    )
    db.add(asset)
    await db.flush()
    for sw in data.software:
        db.add(AssetSoftware(
            asset_id=asset.id, name=sw.name, version=sw.version,
            cpe=sw.cpe, end_of_life=sw.end_of_life, eol_date=sw.eol_date,
        ))
    await db.commit()
    await db.refresh(asset)
    return _asset_to_dict(asset)


@router.delete("/{asset_id}")
async def delete_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.commit()
    return {"ok": True}


@router.get("/{asset_id}/cves")
async def get_asset_cves(asset_id: int, db: AsyncSession = Depends(get_db)):
    return await find_cves_for_asset(db, asset_id)


@router.get("/summary")
async def get_asset_summary(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset))
    assets = result.scalars().all()
    total = len(assets)
    internet_facing = sum(1 for a in assets if a.internet_facing)
    by_env = {}
    by_crit = {}
    total_sw = 0
    eol_sw = 0
    for a in assets:
        by_env[a.environment] = by_env.get(a.environment, 0) + 1
        by_crit[a.criticality] = by_crit.get(a.criticality, 0) + 1
        total_sw += len(a.software)
        eol_sw += sum(1 for s in a.software if s.end_of_life)
    return {
        "total": total, "internetFacing": internet_facing,
        "byEnvironment": by_env, "byCriticality": by_crit,
        "totalSoftware": total_sw, "eolSoftware": eol_sw,
    }


def _asset_to_dict(asset: Asset) -> dict:
    return {
        "id": asset.id, "name": asset.name, "asset_type": asset.asset_type,
        "hostname": asset.hostname, "ip_address": asset.ip_address,
        "environment": asset.environment, "internet_facing": asset.internet_facing,
        "criticality": asset.criticality, "owner": asset.owner, "tags": asset.tags,
        "software": [
            {"id": s.id, "name": s.name, "version": s.version, "cpe": s.cpe, "end_of_life": s.end_of_life, "eol_date": s.eol_date}
            for s in asset.software
        ],
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
    }
