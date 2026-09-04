"""CVE response schemas — structured intelligence shape."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CvssVersion(BaseModel):
    version: str
    score: Optional[float] = None
    severity: Optional[str] = None
    vector_string: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None
    availability: Optional[str] = None


class BestCvss(BaseModel):
    version: Optional[str] = None
    score: Optional[float] = None
    severity: Optional[str] = None
    vector_string: Optional[str] = None


class EpssData(BaseModel):
    score: Optional[float] = None
    percentile: Optional[float] = None
    calculated_at: Optional[str] = None


class KevData(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    required_action: Optional[str] = None
    known_ransomware_campaign_use: Optional[str] = None
    short_description: Optional[str] = None


class ExploitInfo(BaseModel):
    url: str
    name: Optional[str] = None
    source_type: Optional[str] = None
    stars: int = 0


class RiskSignal(BaseModel):
    name: str
    label: str
    value: float
    max: float
    weight: str


class RiskAssessment(BaseModel):
    score: int
    level: str
    priority: str  # P1, P2, P3, P4
    signals: list[RiskSignal]
    reasons: list[str]
    recommendation: str


class CVEResponse(BaseModel):
    cve_id: str
    description: Optional[str] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    cwes: list[str] = []
    products: list[str] = []
    references: list[str] = []
    cvss_scores: list[CvssVersion] = []
    best_cvss: Optional[BestCvss] = None
    epss: Optional[EpssData] = None
    kev: Optional[KevData] = None
    exploits: list[ExploitInfo] = []
    risk: Optional[RiskAssessment] = None
    affected_assets: list[dict] = []
