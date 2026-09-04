from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy import JSON

from ..database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    cvss2_score = Column(Float, nullable=True)
    cvss3_score = Column(Float, nullable=True)
    cvss4_score = Column(Float, nullable=True)
    severity = Column(String(10), nullable=True)
    attack_vector = Column(String(20), nullable=True)
    attack_complexity = Column(String(20), nullable=True)
    privileges_required = Column(String(20), nullable=True)
    user_interaction = Column(String(20), nullable=True)
    cwes = Column(JSON, default=list)
    products = Column(JSON, default=list)
    references = Column(JSON, default=list)
    epss_probability = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    in_kev = Column(Boolean, default=False)
    kev_due_date = Column(String(20), nullable=True)
    has_exploit = Column(Boolean, default=False)
    exploit_sources = Column(JSON, default=list)
    risk_score = Column(Float, nullable=True)
    risk_factors = Column(JSON, default=dict)
    classification = Column(String(50), nullable=True)
    classification_confidence = Column(Float, nullable=True)
    classification_evidence = Column(JSON, default=list)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<CVE {self.cve_id}>"
