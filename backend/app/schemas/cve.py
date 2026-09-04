from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    cvss2_score: Optional[float] = None
    cvss3_score: Optional[float] = None
    cvss4_score: Optional[float] = None
    severity: Optional[str] = None
    cwes: list[str] = []
    products: list[str] = []
    references: list[str] = []


class CVEEnrichment(BaseModel):
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    kev_due_date: Optional[str] = None
    has_exploit: bool = False
    exploit_sources: list[str] = []


class CVERisk(BaseModel):
    risk_score: Optional[float] = None
    risk_factors: dict = {}


class CVEResponse(CVEBase, CVEEnrichment, CVERisk):
    id: int
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    classification: Optional[str] = None
    classification_confidence: Optional[float] = None
    classification_evidence: list[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
