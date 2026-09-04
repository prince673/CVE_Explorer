"""CVE lookup and intelligence routes."""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..services.cve_service import get_or_create_cve, fetch_cve_enrichments
from ..services.risk_engine import calculate_risk_score, calculate_exploitability, classify_severity_vs_risk
from ..services.correlation import find_affected_assets
from ..schemas.cve import CVEResponse

router = APIRouter(prefix="/api/cve", tags=["CVE"])


@router.get("/{cve_id}")
async def lookup_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Full CVE lookup with enrichment, risk scoring, and asset correlation."""
    try:
        cve_data = await get_or_create_cve(db, cve_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    enrichments = {
        "epss": {"probability": cve_data.get("epss_probability"), "percentile": cve_data.get("epss_percentile")} if cve_data.get("epss_probability") is not None else None,
        "kev": {"inCatalog": cve_data.get("in_kev", False), "dueDate": cve_data.get("kev_due_date")},
        "hasExploit": cve_data.get("has_exploit", False),
        "exploitSources": cve_data.get("exploit_sources", []),
    }

    risk = calculate_risk_score(cve_data, enrichments)
    exploitability = calculate_exploitability(cve_data, enrichments)
    affected_assets = await find_affected_assets(db, cve_data)

    if affected_assets:
        risk_with_assets = calculate_risk_score(cve_data, enrichments, affected_assets)
        risk.risk_score = risk_with_assets.risk_score
        risk.risk_factors = risk_with_assets.risk_factors

    return {
        "cve": cve_data,
        "enrichments": enrichments,
        "risk": {"risk_score": risk.risk_score, "risk_factors": risk.risk_factors},
        "exploitability": exploitability,
        "affectedAssets": affected_assets,
    }


@router.get("/{cve_id}/enrichments")
async def get_enrichments(cve_id: str):
    """Fetch only enrichments (EPSS, KEV, exploits) for a CVE."""
    return await fetch_cve_enrichments(cve_id)


@router.get("/{cve_id}/assets")
async def get_affected_assets(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Find assets affected by a CVE."""
    cve_data = await get_or_create_cve(db, cve_id)
    return await find_affected_assets(db, cve_data)
