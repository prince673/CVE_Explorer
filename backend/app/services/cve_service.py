"""CVE data fetching, normalization, and caching from multiple sources."""
import httpx
import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..config import get_settings
from ..models.cve import CVE

settings = get_settings()

KEV_CACHE: dict = {}
KEV_CACHE_TIME: float = 0
KEV_TTL: float = 21600  # 6 hours


async def fetch_from_circl(cve_id: str) -> dict | None:
    """Fetch CVE from CIRCL API (primary source)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{settings.CIRCL_API}/cve/{cve_id}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("id"):
                    return _normalize_circl(data)
    except Exception:
        pass
    return None


async def fetch_from_nvd(cve_id: str) -> dict | None:
    """Fetch CVE from NVD API (fallback)."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(settings.NVD_API, params={"cveId": cve_id})
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return _normalize_nvd(vulns[0].get("cve", {}))
    except Exception:
        pass
    return None


async def fetch_cve(cve_id: str) -> dict:
    """Fetch CVE from best available source."""
    result = await fetch_from_circl(cve_id)
    if result:
        return result
    result = await fetch_from_nvd(cve_id)
    if result:
        return result
    raise ValueError(f"CVE {cve_id} not found in any database.")


async def fetch_epss(cve_id: str) -> dict | None:
    """Fetch EPSS score from FIRST.org."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(settings.EPSS_API, params={"cve": cve_id})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data"):
                    item = data["data"][0]
                    return {
                        "probability": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
    except Exception:
        pass
    return None


async def fetch_kev_catalog() -> dict:
    """Fetch CISA KEV catalog (cached)."""
    global KEV_CACHE, KEV_CACHE_TIME
    import time
    if KEV_CACHE and (time.time() - KEV_CACHE_TIME) < KEV_TTL:
        return KEV_CACHE
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(settings.KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                KEV_CACHE = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
                KEV_CACHE_TIME = time.time()
                return KEV_CACHE
    except Exception:
        pass
    return KEV_CACHE


async def fetch_exploits(cve_id: str) -> list[dict]:
    """Search for public exploits on GitHub."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{cve_id} exploit", "sort": "stars", "per_page": 5},
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    {"url": item["html_url"], "stars": item.get("stargazers_count", 0)}
                    for item in data.get("items", [])[:5]
                ]
    except Exception:
        pass
    return []


async def fetch_cve_enrichments(cve_id: str) -> dict:
    """Fetch all enrichments for a CVE in parallel."""
    epss_task, kev_task, exploit_task = await asyncio.gather(
        fetch_epss(cve_id),
        fetch_kev_catalog(),
        fetch_exploits(cve_id),
    )
    kev_entry = kev_task.get(cve_id)
    return {
        "epss": epss_task,
        "kev": {
            "inCatalog": kev_entry is not None,
            "dueDate": kev_entry.get("dueDate") if kev_entry else None,
            "knownRansomwareCampaignUse": kev_entry.get("knownRansomwareCampaignUse", "Unknown") if kev_entry else "Unknown",
        } if kev_entry else {"inCatalog": False},
        "hasExploit": len(exploit_task) > 0,
        "exploitSources": exploit_task,
    }


async def get_or_create_cve(db: AsyncSession, cve_id: str) -> dict:
    """Get CVE from DB cache or fetch from APIs, then store."""
    # Check DB first
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    db_cve = result.scalar_one_or_none()

    if db_cve and db_cve.updated_at:
        age_hours = (datetime.utcnow() - db_cve.updated_at).total_seconds() / 3600
        if age_hours < 24:
            return _cve_to_dict(db_cve)

    # Fetch from APIs
    cve_data = await fetch_cve(cve_id)
    enrichments = await fetch_cve_enrichments(cve_id)
    epss = enrichments.get("epss") or {}
    kev = enrichments.get("kev") or {}
    merged = {
        **cve_data,
        "epss_probability": epss.get("probability"),
        "epss_percentile": epss.get("percentile"),
        "in_kev": kev.get("inCatalog", False),
        "kev_due_date": kev.get("dueDate"),
        "has_exploit": enrichments.get("hasExploit", False),
        "exploit_sources": enrichments.get("exploitSources", []),
    }

    if db_cve:
        for key, value in merged.items():
            if hasattr(db_cve, key):
                setattr(db_cve, key, value)
        db_cve.updated_at = datetime.utcnow()
    else:
        db_cve = CVE(cve_id=cve_id, **merged)
        db.add(db_cve)

    await db.commit()
    return _cve_to_dict(db_cve)


def _normalize_circl(data: dict) -> dict:
    """Normalize CIRCL API response to our schema."""
    summary = data.get("summary", {})
    return {
        "description": summary.get("description", data.get("summary", "")),
        "published_date": _parse_date(data.get("Published")),
        "modified_date": _parse_date(data.get("Modified")),
        "cvss3_score": data.get("cvss3") or data.get("cvss", {}).get("score") if isinstance(data.get("cvss"), dict) else None,
        "cvss2_score": data.get("cvss", {}).get("score") if isinstance(data.get("cvss"), dict) else None,
        "severity": _severity_from_cvss(data.get("cvss3") or (data.get("cvss", {}).get("score") if isinstance(data.get("cvss"), dict) else None)),
        "cwes": [c.get("name", c) if isinstance(c, dict) else c for c in (data.get("cwe") or [])],
        "products": data.get("vulnerable_product_list") or [],
        "references": data.get("references") or [],
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
    }


def _normalize_nvd(data: dict) -> dict:
    """Normalize NVD API response to our schema."""
    descriptions = data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("language") == "en"), "")

    metrics = data.get("metrics", {})
    cvss31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else None
    cvss30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else None
    cvss2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else None

    cvss3_data = (cvss31 or cvss30 or {}).get("cvssData", {})
    cvss2_data = (cvss2 or {}).get("cvssData", {})

    weaknesses = data.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    configs = data.get("configurations", [])
    products = []
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        products.append(f"{parts[3]}:{parts[4]}")

    references = [r.get("url", "") for r in data.get("references", [])]

    return {
        "description": desc,
        "published_date": _parse_date(data.get("published")),
        "modified_date": _parse_date(data.get("lastModified")),
        "cvss3_score": cvss3_data.get("baseScore"),
        "cvss2_score": cvss2_data.get("baseScore"),
        "severity": _severity_from_cvss(cvss3_data.get("baseScore") or cvss2_data.get("baseScore")),
        "cwes": cwes,
        "products": products,
        "references": references,
        "attack_vector": cvss3_data.get("attackVector"),
        "attack_complexity": cvss3_data.get("attackComplexity"),
        "privileges_required": cvss3_data.get("privilegesRequired"),
        "user_interaction": cvss3_data.get("userInteraction"),
    }


def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        try:
            return datetime.strptime(date_str[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


def _severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"


def _cve_to_dict(cve: CVE) -> dict:
    return {c.key: getattr(cve, c.key) for c in CVE.__table__.columns}
