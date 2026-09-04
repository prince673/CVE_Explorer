from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    alert_type: str
    title: str
    message: str
    severity: str
    cve_id: Optional[str] = None
    source: Optional[str] = None
    read: bool = False
    acknowledged: bool = False
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
