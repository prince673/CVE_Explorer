"""Analytics and dashboard aggregation service."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..models.cve import CVE
from ..models.asset import Asset, AssetSoftware
from ..models.alert import Alert
from ..models.remediation import RemediationRecord


async def get_dashboard_stats(db: AsyncSession) -> dict:
    """Aggregate stats for the main dashboard."""
    total_cves = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    critical_cves = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.severity == "Critical")
    )).scalar() or 0
    high_cves = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.severity == "High")
    )).scalar() or 0

    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar() or 0
    internet_facing = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.internet_facing == True)
    )).scalar() or 0

    total_sw = (await db.execute(select(func.count()).select_from(AssetSoftware))).scalar() or 0
    eol_sw = (await db.execute(
        select(func.count()).select_from(AssetSoftware).where(AssetSoftware.end_of_life == True)
    )).scalar() or 0

    unread_alerts = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.read == False)
    )).scalar() or 0

    open_remediations = (await db.execute(
        select(func.count()).select_from(RemediationRecord).where(
            RemediationRecord.status.in_(["open", "assigned", "in_progress"])
        )
    )).scalar() or 0

    kev_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.in_kev == True)
    )).scalar() or 0

    exploit_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.has_exploit == True)
    )).scalar() or 0

    return {
        "totalCVEs": total_cves,
        "criticalCVEs": critical_cves,
        "highCVEs": high_cves,
        "totalAssets": total_assets,
        "internetFacingAssets": internet_facing,
        "totalSoftware": total_sw,
        "eolSoftware": eol_sw,
        "unreadAlerts": unread_alerts,
        "openRemediations": open_remediations,
        "kevEntries": kev_count,
        "exploitCount": exploit_count,
    }
