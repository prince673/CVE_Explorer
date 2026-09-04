"""CVE lookup and intelligence routes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..services.cve_service import get_or_create_cve, fetch_all_enrichments
from ..services.risk_engine import calculate_risk_assessment
from ..services.correlation import find_affected_assets

router = APIRouter(prefix="/api/cve", tags=["CVE"])


@router.get("/{cve_id}")
async def lookup_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Full CVE lookup with structured intelligence and transparent risk assessment."""
    try:
        cve_data = await get_or_create_cve(db, cve_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    affected_assets = await find_affected_assets(db, cve_data)
    risk = calculate_risk_assessment(cve_data, affected_assets)

    return {
        **cve_data,
        "risk": risk,
        "affected_assets": affected_assets,
    }


@router.get("/{cve_id}/enrichments")
async def get_enrichments(cve_id: str):
    """Fetch raw enrichments (EPSS, KEV, exploits) for a CVE."""
    return await fetch_all_enrichments(cve_id)


@router.get("/{cve_id}/assets")
async def get_affected_assets(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Find assets affected by a CVE."""
    cve_data = await get_or_create_cve(db, cve_id)
    return await find_affected_assets(db, cve_data)
