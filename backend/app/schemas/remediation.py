from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RemediationBase(BaseModel):
    cve_id: str
    asset_id: Optional[int] = None
    priority: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    due_date: Optional[datetime] = None


class RemediationUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    due_date: Optional[datetime] = None


class RemediationResponse(RemediationBase):
    id: int
    status: str
    history: list = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
