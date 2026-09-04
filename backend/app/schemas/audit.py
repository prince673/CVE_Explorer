from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AuditLogEntry(BaseModel):
    action: str
    entity_type: str
    entity_id: Optional[str] = None
    detail: Optional[str] = None
    user_name: str = "system"
    metadata: dict = {}
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
