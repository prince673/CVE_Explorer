"""Correlate CVEs with assets based on software inventory."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from ..models.asset import Asset, AssetSoftware


async def find_affected_assets(db: AsyncSession, cve_data: dict) -> list[dict]:
    """Find assets affected by a CVE based on software matching."""
    products = [p.lower() for p in (cve_data.get("products") or [])]
    description = (cve_data.get("description") or "").lower()

    result = await db.execute(
        select(Asset).join(AssetSoftware)
    )
    assets = result.scalars().all()

    affected = []
    seen_assets = set()

    for asset in assets:
        for sw in asset.software:
            sw_name_lower = sw.name.lower()
            matched = False
            reason = ""

            for product in products:
                if product in sw_name_lower or sw_name_lower in product:
                    matched = True
                    reason = f'Software "{sw.name}" matches affected product "{product}"'
                    break

            if not matched and sw_name_lower in description:
                matched = True
                reason = f'Software "{sw.name}" mentioned in CVE description'

            if matched and asset.id not in seen_assets:
                seen_assets.add(asset.id)
                affected.append({
                    "asset_id": asset.id,
                    "asset_name": asset.name,
                    "environment": asset.environment,
                    "criticality": asset.criticality,
                    "internet_facing": asset.internet_facing,
                    "software_name": sw.name,
                    "software_version": sw.version,
                    "match_reason": reason,
                })

    crit_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    affected.sort(key=lambda x: crit_order.get(x.get("criticality", "medium"), 2))
    return affected


async def find_cves_for_asset(db: AsyncSession, asset_id: int) -> list[dict]:
    """Find all CVEs affecting a specific asset."""
    result = await db.execute(
        select(AssetSoftware).where(AssetSoftware.asset_id == asset_id)
    )
    software_list = result.scalars().all()

    from ..models.cve import CVE
    affected_cves = []
    for sw in software_list:
        sw_lower = sw.name.lower()
        cve_result = await db.execute(
            select(CVE).where(
                or_(
                    CVE.products.op("@>")(f'["{sw.name}"]'),
                    CVE.description.ilike(f"%{sw_lower}%"),
                )
            )
        )
        for cve in cve_result.scalars().all():
            affected_cves.append({
                "cve_id": cve.cve_id,
                "cvss3_score": cve.cvss3_score,
                "severity": cve.severity,
                "risk_score": cve.risk_score,
                "software_match": sw.name,
            })

    return affected_cves
