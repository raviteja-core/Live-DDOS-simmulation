from fastapi import APIRouter, HTTPException, Query
from app.models.threat import ThreatFeedResponse
from app.services.abuseipdb import UpstreamThreatDataUnavailable, get_threats

router = APIRouter()

@router.get("/threats", response_model=ThreatFeedResponse)
async def get_threat_data(limit: int = Query(100, ge=1, le=1000)):
    try:
        return await get_threats(limit)
    except UpstreamThreatDataUnavailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
