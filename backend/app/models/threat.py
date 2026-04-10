import ipaddress
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

class Threat(BaseModel):
    ip: str
    abuse_confidence_score: int = Field(..., ge=0, le=100)
    category: str = Field(default="Threat Intel")
    last_reported_at: Optional[datetime] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    risk_score: int = Field(default=0, ge=0, le=100)
    threat_score: int = Field(default=0, ge=0, le=100)
    threat_level: str = Field(default="observed")
    scoring_method: str = Field(default="heuristic_v1")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class ThreatFeedMeta(BaseModel):
    source: str
    cached: bool
    generated_at: datetime
    count_total: int = Field(..., ge=0)
    count_mapped: int = Field(..., ge=0)


class ThreatFeedResponse(BaseModel):
    data: list[Threat]
    meta: ThreatFeedMeta
