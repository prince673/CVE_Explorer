from __future__ import annotations

from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy import JSON
from sqlalchemy.orm import relationship

from ..database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    asset_type = Column(String(50), nullable=False)
    hostname = Column(String(200), nullable=True)
    ip_address = Column(String(50), nullable=True)
    environment = Column(String(20), nullable=False)
    internet_facing = Column(Boolean, default=False)
    criticality = Column(String(20), nullable=False)
    owner = Column(String(100), nullable=True)
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    software = relationship("AssetSoftware", back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Asset {self.name}>"


class AssetSoftware(Base):
    __tablename__ = "asset_software"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    name = Column(String(200), nullable=False)
    version = Column(String(50), nullable=True)
    cpe = Column(String(300), nullable=True)
    end_of_life = Column(Boolean, default=False)
    eol_date = Column(String(20), nullable=True)

    asset = relationship("Asset", back_populates="software")

    def __repr__(self) -> str:
        return f"<AssetSoftware {self.name} {self.version}>"
