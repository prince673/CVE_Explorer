"""CVSS score model — stores all CVSS versions for a CVE."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, func

from ..database import Base


class CvssScore(Base):
    __tablename__ = "cvss_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), index=True, nullable=False)
    version = Column(String(10), nullable=False)  # "2.0", "3.0", "3.1", "4.0"
    score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)
    vector_string = Column(String(300), nullable=True)
    attack_vector = Column(String(20), nullable=True)
    attack_complexity = Column(String(20), nullable=True)
    privileges_required = Column(String(20), nullable=True)
    user_interaction = Column(String(20), nullable=True)
    scope = Column(String(20), nullable=True)
    confidentiality = Column(String(20), nullable=True)
    integrity = Column(String(20), nullable=True)
    availability = Column(String(20), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<CvssScore {self.cve_id} v{self.version}={self.score}>"
