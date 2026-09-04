"""CVE core model — stores only vulnerability metadata."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy import JSON
from sqlalchemy.orm import relationship

from ..database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    cwes = Column(JSON, default=list)
    products = Column(JSON, default=list)
    references = Column(JSON, default=list)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    priority = Column(String(5), nullable=True)  # P1, P2, P3, P4
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<CVE {self.cve_id}>"
