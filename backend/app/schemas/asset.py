from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AssetBase(BaseModel):
    name: str
    asset_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: str
    internet_facing: bool = False
    criticality: str
    owner: Optional[str] = None
    tags: list[str] = []


class AssetSoftwareBase(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    end_of_life: bool = False
    eol_date: Optional[str] = None


class AssetCreate(AssetBase):
    software: list[AssetSoftwareBase] = []


class AssetResponse(AssetBase):
    id: int
    software: list[AssetSoftwareBase] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AffectedAsset(BaseModel):
    asset_id: int
    asset_name: str
    software_name: str
    match_reason: str
