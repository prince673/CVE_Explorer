from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy import JSON

from ..database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(50), nullable=False)
    title = Column(String(300), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    cve_id = Column(String(20), nullable=True, index=True)
    source = Column(String(50), nullable=True)
    read = Column(Boolean, default=False)
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self) -> str:
        return f"<Alert {self.alert_type} - {self.title}>"
