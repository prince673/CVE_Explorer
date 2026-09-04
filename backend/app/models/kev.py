"""CISA KEV entry model — known exploited vulnerabilities catalog."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, func

from ..database import Base


class KevEntry(Base):
    __tablename__ = "kev_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), index=True, unique=True, nullable=False)
    vendor = Column(String(100), nullable=True)
    product = Column(String(200), nullable=True)
    vulnerability_name = Column(String(500), nullable=True)
    date_added = Column(String(30), nullable=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(String(500), nullable=True)
    due_date = Column(String(30), nullable=True)
    known_ransomware_campaign_use = Column(String(20), nullable=True)
    notes = Column(Text, nullable=True)
    last_updated = Column(DateTime, server_default=func.now())
    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self) -> str:
        return f"<KevEntry {self.cve_id} - {self.vendor}/{self.product}>"
