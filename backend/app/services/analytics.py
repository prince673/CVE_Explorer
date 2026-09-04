"""Analytics and dashboard aggregation service."""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..models.cve import CVE
from ..models.cvss import CvssScore
from ..models.epss import EpssScore
from ..models.kev import KevEntry
from ..models.exploit import ExploitSource
from ..models.asset import Asset, AssetSoftware
from ..models.alert import Alert
from ..models.remediation import RemediationRecord


async def get_dashboard_stats(db: AsyncSession) -> dict:
    total_cves = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0

    critical_cves = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.risk_level == "Critical")
    )).scalar() or 0
    high_cves = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.risk_level == "High")
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

    kev_count = (await db.execute(select(func.count()).select_from(KevEntry))).scalar() or 0
    exploit_count = (await db.execute(select(func.count()).select_from(ExploitSource))).scalar() or 0
    p1_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.priority == "P1")
    )).scalar() or 0
    p2_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.priority == "P2")
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
        "p1Count": p1_count,
        "p2Count": p2_count,
    }
