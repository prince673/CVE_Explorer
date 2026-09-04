from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSON

from ..database import Base


class RemediationRecord(Base):
    __tablename__ = "remediation_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), index=True, nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    status = Column(String(20), nullable=False)
    priority = Column(String(20), nullable=False)
    assigned_to = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)
    due_date = Column(DateTime, nullable=True)
    history = Column(JSON, default=list)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<RemediationRecord {self.cve_id} - {self.status}>"
