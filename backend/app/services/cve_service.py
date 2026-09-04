"""CVE data fetching, normalization, and storage across separate intelligence tables."""
import httpx
import asyncio
import time
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..config import get_settings
from ..models.cve import CVE
from ..models.cvss import CvssScore
from ..models.epss import EpssScore
from ..models.kev import KevEntry
from ..models.exploit import ExploitSource

settings = get_settings()

KEV_CACHE: dict = {}
KEV_CACHE_TIME: float = 0
KEV_TTL: float = 21600


async def fetch_from_circl(cve_id: str) -> dict | None:
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
    result = await fetch_from_circl(cve_id)
    if result:
        return result
    result = await fetch_from_nvd(cve_id)
    if result:
        return result
    raise ValueError(f"CVE {cve_id} not found in any database.")


async def fetch_epss_score(cve_id: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(settings.EPSS_API, params={"cve": cve_id})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data"):
                    item = data["data"][0]
                    return {
                        "score": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
    except Exception:
        pass
    return None


async def fetch_kev_catalog() -> dict:
    global KEV_CACHE, KEV_CACHE_TIME
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
                    {
                        "url": item["html_url"],
                        "name": item.get("name", ""),
                        "stars": item.get("stargazers_count", 0),
                        "source_type": "github",
                    }
                    for item in data.get("items", [])[:5]
                ]
    except Exception:
        pass
    return []


async def fetch_all_enrichments(cve_id: str) -> dict:
    """Fetch EPSS, KEV, and exploits in parallel."""
    epss_data, kev_catalog, exploit_data = await asyncio.gather(
        fetch_epss_score(cve_id),
        fetch_kev_catalog(),
        fetch_exploits(cve_id),
    )
    kev_entry = kev_catalog.get(cve_id)
    return {
        "epss": epss_data,
        "kev": kev_entry,
        "exploits": exploit_data,
    }


async def _upsert_cvss(db: AsyncSession, cve_id: str, scores: list[dict]):
    """Insert or update CVSS scores for a CVE."""
    for s in scores:
        existing = (await db.execute(
            select(CvssScore).where(
                CvssScore.cve_id == cve_id, CvssScore.version == s["version"]
            )
        )).scalar_one_or_none()
        if existing:
            for k, v in s.items():
                setattr(existing, k, v)
            existing.updated_at = datetime.utcnow()
        else:
            db.add(CvssScore(cve_id=cve_id, **s))


async def _upsert_epss(db: AsyncSession, cve_id: str, data: dict | None):
    """Insert or update EPSS score for a CVE."""
    if not data:
        return
    existing = (await db.execute(
        select(EpssScore).where(EpssScore.cve_id == cve_id)
    )).scalar_one_or_none()
    if existing:
        existing.score = data["score"]
        existing.percentile = data["percentile"]
        existing.calculated_at = datetime.utcnow()
        existing.updated_at = datetime.utcnow()
    else:
        db.add(EpssScore(cve_id=cve_id, score=data["score"], percentile=data["percentile"]))


async def _upsert_kev(db: AsyncSession, cve_id: str, data: dict | None):
    """Insert or update KEV entry for a CVE."""
    if not data:
        return
    existing = (await db.execute(
        select(KevEntry).where(KevEntry.cve_id == cve_id)
    )).scalar_one_or_none()
    fields = {
        "vendor": data.get("vendorProject"),
        "product": data.get("product"),
        "vulnerability_name": data.get("vulnerabilityName"),
        "date_added": data.get("dateAdded"),
        "short_description": data.get("shortDescription"),
        "required_action": data.get("requiredAction"),
        "due_date": data.get("dueDate"),
        "known_ransomware_campaign_use": data.get("knownRansomwareCampaignUse"),
        "notes": data.get("notes"),
    }
    if existing:
        for k, v in fields.items():
            setattr(existing, k, v)
        existing.last_updated = datetime.utcnow()
    else:
        db.add(KevEntry(cve_id=cve_id, **fields))


async def _upsert_exploits(db: AsyncSession, cve_id: str, exploits: list[dict]):
    """Replace exploit sources for a CVE."""
    for e in (await db.execute(
        select(ExploitSource).where(ExploitSource.cve_id == cve_id)
    )).scalars().all():
        db.delete(e)
    await db.flush()
    seen_urls = set()
    for e in exploits:
        if e["url"] not in seen_urls:
            seen_urls.add(e["url"])
            db.add(ExploitSource(
                cve_id=cve_id,
                url=e["url"],
                name=e.get("name", ""),
                source_type=e.get("source_type", "github"),
                stars=e.get("stars", 0),
            ))


async def get_or_create_cve(db: AsyncSession, cve_id: str) -> dict:
    """Fetch CVE from APIs, populate all intelligence tables, return assembled dict."""
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    db_cve = result.scalar_one_or_none()

    if db_cve and db_cve.updated_at:
        age_hours = (datetime.utcnow() - db_cve.updated_at).total_seconds() / 3600
        if age_hours < 24:
            return await _assemble_cve_dict(db, db_cve)

    cve_data = await fetch_cve(cve_id)
    enrichments = await fetch_all_enrichments(cve_id)

    if db_cve:
        for key in ("description", "published_date", "modified_date", "cwes", "products", "references"):
            if key in cve_data:
                setattr(db_cve, key, cve_data[key])
        db_cve.updated_at = datetime.utcnow()
    else:
        db_cve = CVE(
            cve_id=cve_id,
            description=cve_data.get("description"),
            published_date=cve_data.get("published_date"),
            modified_date=cve_data.get("modified_date"),
            cwes=cve_data.get("cwes", []),
            products=cve_data.get("products", []),
            references=cve_data.get("references", []),
        )
        db.add(db_cve)

    await db.flush()

    await _upsert_cvss(db, cve_id, cve_data.get("cvss_scores", []))
    await _upsert_epss(db, cve_id, enrichments.get("epss"))
    await _upsert_kev(db, cve_id, enrichments.get("kev"))
    await _upsert_exploits(db, cve_id, enrichments.get("exploits", []))

    await db.commit()
    return await _assemble_cve_dict(db, db_cve)


async def _assemble_cve_dict(db: AsyncSession, cve: CVE) -> dict:
    """Read CVE + all related tables and return a flat dict for the API."""
    cvss_list = list(
        (await db.execute(
            select(CvssScore).where(CvssScore.cve_id == cve.cve_id)
        )).scalars().all()
    )
    epss = (await db.execute(
        select(EpssScore).where(EpssScore.cve_id == cve.cve_id)
    )).scalar_one_or_none()
    kev = (await db.execute(
        select(KevEntry).where(KevEntry.cve_id == cve.cve_id)
    )).scalar_one_or_none()
    exploits = list(
        (await db.execute(
            select(ExploitSource).where(ExploitSource.cve_id == cve.cve_id)
        )).scalars().all()
    )

    best_cvss = max((s for s in cvss_list if s.score is not None), key=lambda s: s.score, default=None)

    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
        "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
        "cwes": list(dict.fromkeys(cve.cwes or [])),
        "products": list(dict.fromkeys(cve.products or [])),
        "references": list(dict.fromkeys(cve.references or [])),
        "cvss_scores": [
            {
                "version": s.version,
                "score": s.score,
                "severity": s.severity,
                "vector_string": s.vector_string,
                "attack_vector": s.attack_vector,
                "attack_complexity": s.attack_complexity,
                "privileges_required": s.privileges_required,
                "user_interaction": s.user_interaction,
                "scope": s.scope,
                "confidentiality": s.confidentiality,
                "integrity": s.integrity,
                "availability": s.availability,
            }
            for s in sorted(cvss_list, key=lambda x: x.version, reverse=True)
        ],
        "best_cvss": {
            "version": best_cvss.version if best_cvss else None,
            "score": best_cvss.score if best_cvss else None,
            "severity": best_cvss.severity if best_cvss else None,
            "vector_string": best_cvss.vector_string if best_cvss else None,
        } if best_cvss else None,
        "epss": {
            "score": epss.score,
            "percentile": epss.percentile,
            "calculated_at": epss.calculated_at.isoformat() if epss and epss.calculated_at else None,
        } if epss else None,
        "kev": {
            "vendor": kev.vendor,
            "product": kev.product,
            "vulnerability_name": kev.vulnerability_name,
            "date_added": kev.date_added,
            "due_date": kev.due_date,
            "required_action": kev.required_action,
            "known_ransomware_campaign_use": kev.known_ransomware_campaign_use,
            "short_description": kev.short_description,
        } if kev else None,
        "exploits": [
            {"url": e.url, "name": e.name, "source_type": e.source_type, "stars": e.stars}
            for e in exploits
        ],
    }


def _normalize_circl(data: dict) -> dict:
    summary = data.get("summary", {})
    cvss_data = data.get("cvss") if isinstance(data.get("cvss"), dict) else {}
    cvss3_score = data.get("cvss3") or cvss_data.get("score")
    cvss2_score = cvss_data.get("score")
    best_score = cvss3_score or cvss2_score

    cvss_scores = []
    if cvss3_score is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": cvss3_score,
            "severity": _severity_from_cvss(cvss3_score),
            "vector_string": data.get("cvss3-vector") or data.get("cvss", {}).get("vector") if isinstance(data.get("cvss"), dict) else None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality": None,
            "integrity": None,
            "availability": None,
        })
    if cvss2_score is not None:
        cvss_scores.append({
            "version": "2.0",
            "score": cvss2_score,
            "severity": _severity_from_cvss(cvss2_score),
            "vector_string": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality": None,
            "integrity": None,
            "availability": None,
        })

    return {
        "description": summary.get("description", data.get("summary", "")),
        "published_date": _parse_date(data.get("Published")),
        "modified_date": _parse_date(data.get("Modified")),
        "cvss_scores": cvss_scores,
        "cwes": [c.get("name", c) if isinstance(c, dict) else c for c in (data.get("cwe") or [])],
        "products": data.get("vulnerable_product_list") or [],
        "references": data.get("references") or [],
    }


def _normalize_nvd(data: dict) -> dict:
    descriptions = data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("language") == "en"), "")

    metrics = data.get("metrics", {})
    cvss31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else None
    cvss30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else None
    cvss2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else None

    cvss_scores = []
    for entry, ver in [(cvss31, "3.1"), (cvss30, "3.0"), (cvss2, "2.0")]:
        if entry:
            cd = entry.get("cvssData", {})
            cvss_scores.append({
                "version": ver,
                "score": cd.get("baseScore") or entry.get("baseScore"),
                "severity": _severity_from_cvss(cd.get("baseScore") or entry.get("baseScore")),
                "vector_string": cd.get("vectorString") or entry.get("vectorString"),
                "attack_vector": cd.get("attackVector"),
                "attack_complexity": cd.get("attackComplexity"),
                "privileges_required": cd.get("privilegesRequired"),
                "user_interaction": cd.get("userInteraction"),
                "scope": cd.get("scope"),
                "confidentiality": cd.get("confidentialityImpact"),
                "integrity": cd.get("integrityImpact"),
                "availability": cd.get("availabilityImpact"),
            })

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
        "cvss_scores": cvss_scores,
        "cwes": cwes,
        "products": products,
        "references": references,
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
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
