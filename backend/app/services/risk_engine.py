"""Explainable risk scoring engine combining CVSS, EPSS, KEV, exploits, and asset context."""
from ..models.cve import CVE
from ..schemas.cve import CVERisk

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}
ATTACK_VECTORS = {"NETWORK": 10, "ADJACENT_NETWORK": 6, "LOCAL": 4, "PHYSICAL": 2}
EXPLOITABILITY_FACTORS = {
    "no_known_exploits": 0,
    "public_exploit_available": 10,
    "actively_exploited": 20,
    "kev_catalog_entry": 25,
}


def calculate_risk_score(cve_data: dict, enrichments: dict, assets: list[dict] | None = None) -> CVERisk:
    """Calculate explainable risk score 0-100."""
    factors = {}

    # CVSS severity factor
    cvss = cve_data.get("cvss3_score") or cve_data.get("cvss2_score") or 0
    severity = cve_data.get("severity", "Low")
    factors["cvss_severity"] = {"value": SEVERITY_WEIGHTS.get(severity, 0), "label": f"CVSS {severity} ({cvss}/10)"}

    # EPSS factor
    epss = enrichments.get("epss", {})
    prob = epss.get("probability", 0)
    if prob >= 0.7:
        factors["epss"] = {"value": 20, "label": f"EPSS {prob*100:.0f}% - high exploitation probability"}
    elif prob >= 0.4:
        factors["epss"] = {"value": 12, "label": f"EPSS {prob*100:.0f}% - moderate probability"}
    elif prob >= 0.1:
        factors["epss"] = {"value": 5, "label": f"EPSS {prob*100:.0f}% - low probability"}
    else:
        factors["epss"] = {"value": 0, "label": f"EPSS {prob*100:.0f}% - minimal probability"}

    # KEV factor
    kev = enrichments.get("kev", {})
    if kev.get("inCatalog"):
        factors["kev"] = {"value": 25, "label": "CISA Known Exploited Vulnerability"}
    else:
        factors["kev"] = {"value": 0, "label": "Not in CISA KEV catalog"}

    # Exploit availability
    if enrichments.get("hasExploit"):
        sources = enrichments.get("exploitSources", [])
        top = sources[0] if sources else {}
        stars = top.get("stars", 0)
        if stars > 100:
            factors["exploit"] = {"value": 15, "label": f"High-star exploit ({stars} stars)"}
        else:
            factors["exploit"] = {"value": 10, "label": "Public exploit code available"}
    else:
        factors["exploit"] = {"value": 0, "label": "No known public exploits"}

    # Attack vector
    av = (cve_data.get("attack_vector") or "").upper()
    factors["attack_vector"] = {"value": ATTACK_VECTORS.get(av, 0), "label": f"Attack vector: {av or 'unknown'}"}

    # Asset context
    if assets:
        internet_facing = sum(1 for a in assets if a.get("internet_facing"))
        critical_assets = sum(1 for a in assets if a.get("criticality") == "critical")
        asset_score = min(15, internet_facing * 5 + critical_assets * 5)
        factors["asset_exposure"] = {
            "value": asset_score,
            "label": f"{len(assets)} affected assets ({internet_facing} internet-facing, {critical_assets} critical)"
        }
    else:
        factors["asset_exposure"] = {"value": 0, "label": "No asset correlation data"}

    total = min(100, sum(f["value"] for f in factors.values()))

    return CVERisk(
        risk_score=total,
        risk_factors=factors,
    )


def calculate_exploitability(cve_data: dict, enrichments: dict) -> dict:
    """Calculate exploitability assessment."""
    score = 0
    factors = []

    if cve_data.get("attack_vector", "").upper() == "NETWORK":
        score += 15
        factors.append("Network-accessible")
    if cve_data.get("attack_complexity", "").upper() == "LOW":
        score += 10
        factors.append("Low attack complexity")
    if cve_data.get("privileges_required", "").upper() == "NONE":
        score += 10
        factors.append("No privileges required")
    if cve_data.get("user_interaction", "").upper() == "NONE":
        score += 5
        factors.append("No user interaction needed")
    if enrichments.get("epss", {}).get("probability", 0) >= 0.5:
        score += 15
        factors.append("High EPSS probability")
    if enrichments.get("kev", {}).get("inCatalog"):
        score += 20
        factors.append("In CISA KEV catalog")
    if enrichments.get("hasExploit"):
        score += 15
        factors.append("Public exploit available")

    score = min(100, score)

    if score >= 70: level = "Critical"
    elif score >= 50: level = "High"
    elif score >= 25: level = "Medium"
    else: level = "Low"

    return {"score": score, "level": level, "factors": factors}


def classify_severity_vs_risk(cve_data: dict, risk, exploitability) -> dict:
    """Compare technical severity vs organizational risk."""
    cvss = cve_data.get("cvss3_score") or cve_data.get("cvss2_score") or 0
    risk_score = risk.risk_score
    severity_label = cve_data.get("severity", "Unknown")

    divergence = abs(risk_score - (cvss * 10))

    if risk_score > cvss * 10:
        interpretation = f"Organizational risk ({risk_score}/100) exceeds technical severity ({cvss}/10) due to active exploitation signals."
    elif risk_score < cvss * 10:
        interpretation = f"Organizational risk ({risk_score}/100) is lower than technical severity ({cvss}/10), possibly due to limited exploitation evidence."
    else:
        interpretation = f"Technical severity and organizational risk are aligned at {cvss}/10."

    if risk_score >= 60:
        recommendation = "PRIORITY: This vulnerability should be remediated urgently."
    elif risk_score >= 30:
        recommendation = "SCHEDULE: Plan remediation within standard patch cycle."
    else:
        recommendation = "MONITOR: Track for changes in exploitation status."

    return {
        "technicalSeverity": severity_label,
        "cvssScore": cvss,
        "organizationalRisk": risk.risk_level if hasattr(risk, 'risk_level') else "Unknown",
        "riskScore": risk_score,
        "hasDivergence": divergence > 25,
        "divergence": round(divergence),
        "interpretation": interpretation,
        "recommendation": recommendation,
    }
