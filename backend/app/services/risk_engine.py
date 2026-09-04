"""Transparent risk-prioritization engine.

Combines CVSS (severity) + EPSS (exploitation likelihood) + KEV (confirmed exploitation)
+ exploit availability + asset context to produce a P1–P4 priority with human-readable reasons.

Each signal contributes independently to the score and produces a written justification.
"""


def calculate_risk_assessment(
    cve_data: dict,
    affected_assets: list[dict] | None = None,
) -> dict:
    """Produce a full risk assessment from the assembled CVE data dict.

    The cve_data dict should contain:
        best_cvss: { score, severity, version }
        epss: { score, percentile } | null
        kev: { vendor, product, due_date, ... } | null
        exploits: [{ url, name, stars }] | []

    Returns:
        {
            "score": 0-100,
            "level": "Critical" | "High" | "Medium" | "Low",
            "priority": "P1" | "P2" | "P3" | "P4",
            "signals": [
                { "name": str, "label": str, "value": float, "max": float, "weight": str },
                ...
            ],
            "reasons": [ str, ... ],
            "recommendation": str,
        }
    """
    signals = []
    reasons = []
    total = 0

    cvss = cve_data.get("best_cvss") or {}
    cvss_score = cvss.get("score") or 0
    severity = cvss.get("severity") or "Unknown"

    epss = cve_data.get("epss") or {}
    epss_score = epss.get("score") or 0

    kev = cve_data.get("kev")
    has_kev = kev is not None

    exploits = cve_data.get("exploits") or []
    has_exploit = len(exploits) > 0
    top_stars = exploits[0].get("stars", 0) if exploits else 0

    # --- 1. CVSS severity (max 25 points) ---
    cvss_max = 25
    cvss_points = round((cvss_score / 10) * cvss_max)
    total += cvss_points
    signals.append({
        "name": "cvss",
        "label": f"CVSS {severity} ({cvss_score}/10)",
        "value": cvss_points,
        "max": cvss_max,
        "weight": "25%",
    })
    if cvss_score >= 9.0:
        reasons.append("Critical technical severity (CVSS >= 9.0)")
    elif cvss_score >= 7.0:
        reasons.append("High technical severity (CVSS >= 7.0)")
    elif cvss_score >= 4.0:
        reasons.append("Moderate technical severity (CVSS >= 4.0)")
    else:
        reasons.append("Low technical severity")

    # --- 2. EPSS exploitation probability (max 20 points) ---
    epss_max = 20
    epss_points = round(epss_score * epss_max)
    total += epss_points
    pct_label = f"{epss_score * 100:.0f}%"
    if epss_score >= 0.7:
        signals.append({"name": "epss", "label": f"EPSS {pct_label} — Very High", "value": epss_points, "max": epss_max, "weight": "20%"})
        reasons.append(f"Very high exploitation probability (EPSS {pct_label})")
    elif epss_score >= 0.4:
        signals.append({"name": "epss", "label": f"EPSS {pct_label} — High", "value": epss_points, "max": epss_max, "weight": "20%"})
        reasons.append(f"High exploitation probability (EPSS {pct_label})")
    elif epss_score >= 0.1:
        signals.append({"name": "epss", "label": f"EPSS {pct_label} — Moderate", "value": epss_points, "max": epss_max, "weight": "20%"})
        reasons.append(f"Moderate exploitation probability (EPSS {pct_label})")
    else:
        signals.append({"name": "epss", "label": f"EPSS {pct_label} — Low", "value": epss_points, "max": epss_max, "weight": "20%"})
        reasons.append(f"Low exploitation probability (EPSS {pct_label})")

    # --- 3. KEV confirmed exploitation (max 25 points) ---
    kev_max = 25
    kev_points = kev_max if has_kev else 0
    total += kev_points
    if has_kev:
        signals.append({"name": "kev", "label": "CISA KEV — Confirmed exploited", "value": kev_points, "max": kev_max, "weight": "25%"})
        reasons.append("Confirmed exploitation in the wild (CISA KEV catalog)")
    else:
        signals.append({"name": "kev", "label": "Not in CISA KEV", "value": 0, "max": kev_max, "weight": "25%"})

    # --- 4. Public exploit availability (max 15 points) ---
    exploit_max = 15
    if has_exploit and top_stars > 100:
        exploit_points = exploit_max
        reasons.append(f"Widely available exploit code ({top_stars} stars)")
    elif has_exploit:
        exploit_points = 10
        reasons.append("Public exploit code available")
    else:
        exploit_points = 0
    total += exploit_points
    signals.append({
        "name": "exploit",
        "label": f"{len(exploits)} exploit source{'s' if len(exploits) != 1 else ''}" if has_exploit else "No public exploits",
        "value": exploit_points,
        "max": exploit_max,
        "weight": "15%",
    })

    # --- 5. Asset exposure (max 15 points) ---
    asset_max = 15
    if affected_assets:
        n_total = len(affected_assets)
        n_internet = sum(1 for a in affected_assets if a.get("internet_facing"))
        n_critical = sum(1 for a in affected_assets if a.get("criticality") == "critical")
        asset_points = min(asset_max, n_internet * 5 + n_critical * 5)
        total += asset_points
        signals.append({
            "name": "asset",
            "label": f"{n_total} assets ({n_internet} internet-facing, {n_critical} critical)",
            "value": asset_points,
            "max": asset_max,
            "weight": "15%",
        })
        if n_internet:
            reasons.append(f"Internet-facing assets exposed ({n_internet})")
        if n_critical:
            reasons.append(f"Critical business assets affected ({n_critical})")
    else:
        signals.append({"name": "asset", "label": "No asset data", "value": 0, "max": asset_max, "weight": "15%"})

    # --- Final score ---
    score = min(100, total)

    if score >= 80:
        level, priority = "Critical", "P1"
    elif score >= 60:
        level, priority = "High", "P2"
    elif score >= 35:
        level, priority = "Medium", "P3"
    else:
        level, priority = "Low", "P4"

    if priority == "P1":
        recommendation = "Remediate immediately. Patch affected systems or apply mitigating controls without delay."
    elif priority == "P2":
        recommendation = "Remediate urgently. Schedule patching within the current security cycle."
    elif priority == "P3":
        recommendation = "Remediate in standard cycle. Include in next regular patch window."
    else:
        recommendation = "Monitor. Track for changes in exploitation status or asset exposure."

    return {
        "score": score,
        "level": level,
        "priority": priority,
        "signals": signals,
        "reasons": reasons,
        "recommendation": recommendation,
    }
