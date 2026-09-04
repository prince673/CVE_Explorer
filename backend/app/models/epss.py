"""EPSS score model — stores exploitation probability predictions."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, func

from ..database import Base


class EpssScore(Base):
    __tablename__ = "epss_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), index=True, unique=True, nullable=False)
    score = Column(Float, nullable=True)        # probability 0.0–1.0
    percentile = Column(Float, nullable=True)    # 0.0–1.0
    model_version = Column(String(50), nullable=True)
    calculated_at = Column(DateTime, server_default=func.now())
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<EpssScore {self.cve_id} score={self.score}>"
