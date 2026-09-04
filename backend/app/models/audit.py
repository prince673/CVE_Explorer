from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSON

from ..database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(100), nullable=True)
    detail = Column(Text, nullable=True)
    user_name = Column(String(100), default="system")
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} - {self.entity_type}>"
