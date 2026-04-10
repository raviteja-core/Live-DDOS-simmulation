import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, List, Optional

import httpx

from app.models.threat import Threat, ThreatFeedMeta, ThreatFeedResponse
from app.services.geolocation import enrich_threats_with_coordinates
from app.services.scoring import score_threats

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
BLOCKLIST_LAST_URL = "https://api.blocklist.de/getlast.php"
REQUEST_TIMEOUT_SECONDS = 10
DEFAULT_CONFIDENCE_MINIMUM = 25
DEFAULT_THREAT_CACHE_TTL_SECONDS = 300
DEFAULT_BLOCKLIST_LOOKBACK_SECONDS = 3600

logger = logging.getLogger(__name__)
PLACEHOLDER_API_KEYS = {
    "",
    "your_api_key_here",
    "your_abuseipdb_api_key_here",
}
_THREAT_CACHE: dict[str, Any] = {
    "response": None,
}


class UpstreamThreatDataUnavailable(Exception):
    pass


def _abuseipdb_headers(api_key: Optional[str] = None) -> dict[str, str]:
    return {
        "Key": api_key or "",
        "Accept": "application/json",
    }


def _request_timeout() -> httpx.Timeout:
    return httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=3.0)


def parse_last_reported_at(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_threat_item(item: dict[str, Any]) -> Optional[Threat]:
    ip_address = item.get("ipAddress")
    abuse_score = item.get("abuseConfidenceScore")

    if not ip_address or abuse_score is None:
        logger.warning("Skipping AbuseIPDB item with missing required fields: %s", item)
        return None

    category = item.get("usageType") or item.get("domain") or "Threat Intel"

    try:
        return Threat(
            ip=ip_address,
            abuse_confidence_score=int(abuse_score),
            category=category,
            last_reported_at=parse_last_reported_at(item.get("lastReportedAt")),
        )
    except ValueError:
        logger.warning("Skipping AbuseIPDB item with invalid values: %s", item)
        return None


def _extract_ip_from_line(line: str) -> Optional[str]:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    if not match:
        return None
    return match.group(0)


def _blocklist_score_seed(index: int) -> int:
    if index < 12:
        return 94 - (index % 4)
    if index < 60:
        return 86 - ((index - 12) // 8)
    if index < 150:
        return 74 - ((index - 60) // 15)
    return max(42, 58 - ((index - 150) // 18))


def parse_blocklist_lines(payload: str, limit: int) -> List[Threat]:
    threats: List[Threat] = []
    seen_ips: set[str] = set()

    for line in payload.splitlines():
        ip_address = _extract_ip_from_line(line)
        if not ip_address or ip_address in seen_ips:
            continue

        seen_ips.add(ip_address)
        try:
            threats.append(
                Threat(
                    ip=ip_address,
                    abuse_confidence_score=_blocklist_score_seed(len(threats)),
                    category="Blocklist.de Recent Attacker",
                    last_reported_at=datetime.now(timezone.utc),
                )
            )
        except ValueError:
            logger.warning("Skipping blocklist.de line with invalid IP: %s", line)
            continue

        if len(threats) >= limit:
            break

    return threats


async def fetch_blocklist_data(limit: int = 100) -> List[Threat]:
    params = {
        "time": int(os.getenv("BLOCKLIST_LOOKBACK_SECONDS", DEFAULT_BLOCKLIST_LOOKBACK_SECONDS)),
    }
    try:
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            response = await client.get(BLOCKLIST_LAST_URL, params=params)
        response.raise_for_status()
        return parse_blocklist_lines(response.text, limit)
    except httpx.TimeoutException as exc:
        logger.warning("blocklist.de request timed out: %s", exc)
        raise UpstreamThreatDataUnavailable("blocklist.de request timed out") from exc
    except httpx.HTTPError as exc:
        logger.warning("blocklist.de request failed: %s", exc)
        raise UpstreamThreatDataUnavailable("blocklist.de request failed") from exc


def merge_threat_feeds(*feeds: List[Threat]) -> List[Threat]:
    merged_by_ip: dict[str, Threat] = {}

    for feed in feeds:
        for threat in feed:
            existing = merged_by_ip.get(threat.ip)
            if existing is None:
                merged_by_ip[threat.ip] = threat
                continue

            merged_by_ip[threat.ip] = existing.model_copy(
                update={
                    "abuse_confidence_score": max(
                        existing.abuse_confidence_score, threat.abuse_confidence_score
                    ),
                    "category": existing.category
                    if existing.category == threat.category
                    else f"{existing.category} + {threat.category}",
                    "last_reported_at": max(
                        filter(None, [existing.last_reported_at, threat.last_reported_at]),
                        default=existing.last_reported_at or threat.last_reported_at,
                    ),
                    "latitude": existing.latitude if existing.latitude is not None else threat.latitude,
                    "longitude": existing.longitude if existing.longitude is not None else threat.longitude,
                }
            )

    return list(merged_by_ip.values())


def _cache_ttl_seconds() -> int:
    return int(os.getenv("THREAT_CACHE_TTL_SECONDS", DEFAULT_THREAT_CACHE_TTL_SECONDS))


def _is_cache_fresh(requested_limit: int) -> bool:
    cached_response: Optional[ThreatFeedResponse] = _THREAT_CACHE["response"]
    if cached_response is None or len(cached_response.data) < requested_limit:
        return False

    age_seconds = (datetime.now(timezone.utc) - cached_response.meta.generated_at).total_seconds()
    return age_seconds < _cache_ttl_seconds()


def _build_feed_response(
    threats: List[Threat],
    *,
    source: str,
    cached: bool,
    generated_at: Optional[datetime] = None,
) -> ThreatFeedResponse:
    generated_at = generated_at or datetime.now(timezone.utc)
    count_mapped = sum(
        1 for threat in threats if threat.latitude is not None and threat.longitude is not None
    )
    return ThreatFeedResponse(
        data=threats,
        meta=ThreatFeedMeta(
            source=source,
            cached=cached,
            generated_at=generated_at,
            count_total=len(threats),
            count_mapped=count_mapped,
        ),
    )


def _set_cache(response: ThreatFeedResponse) -> None:
    _THREAT_CACHE["response"] = response


def _slice_response(response: ThreatFeedResponse, limit: int, *, cached: bool) -> ThreatFeedResponse:
    sliced_threats = response.data[:limit]
    return _build_feed_response(
        sliced_threats,
        source=response.meta.source,
        cached=cached,
        generated_at=response.meta.generated_at,
    )

async def fetch_abuseipdb_data(api_key: str, limit: int = 100) -> List[Threat]:
    params = {
        "limit": limit,
        "confidenceMinimum": int(os.getenv("ABUSEIPDB_CONFIDENCE_MINIMUM", DEFAULT_CONFIDENCE_MINIMUM)),
    }
    try:
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            response = await client.get(
                ABUSEIPDB_API_URL,
                headers=_abuseipdb_headers(api_key),
                params=params,
            )
        response.raise_for_status()
        data = response.json()
        threats = []
        for item in data.get("data", []):
            threat = parse_threat_item(item)
            if threat is not None:
                threats.append(threat)

        return threats
    except httpx.TimeoutException as exc:
        logger.warning("AbuseIPDB request timed out: %s", exc)
        raise UpstreamThreatDataUnavailable("Threat feed request timed out") from exc
    except httpx.HTTPError as exc:
        logger.warning("AbuseIPDB request failed: %s", exc)
        raise UpstreamThreatDataUnavailable("Threat feed request failed") from exc
    except ValueError as exc:
        logger.warning("AbuseIPDB response parsing failed: %s", exc)
        raise UpstreamThreatDataUnavailable("Threat feed response parsing failed") from exc

def get_mock_data() -> List[Threat]:
    return [
        Threat(
            ip="8.8.8.8",
            abuse_confidence_score=85,
            category="DDoS",
            last_reported_at=datetime.now(timezone.utc),
            latitude=37.751,
            longitude=-97.822,
        ),
        Threat(
            ip="1.1.1.1",
            abuse_confidence_score=90,
            category="Spam",
            last_reported_at=datetime.now(timezone.utc),
            latitude=-33.494,
            longitude=143.2104,
        ),
    ]

async def _refresh_threats(limit: int) -> ThreatFeedResponse:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    abuseipdb_threats: List[Threat] = []
    blocklist_threats: List[Threat] = []
    sources: list[str] = []
    errors: list[str] = []

    if api_key and api_key not in PLACEHOLDER_API_KEYS:
        try:
            abuseipdb_threats = await fetch_abuseipdb_data(api_key, limit)
            if abuseipdb_threats:
                sources.append("abuseipdb")
        except UpstreamThreatDataUnavailable as exc:
            errors.append(str(exc))

    try:
        blocklist_threats = await fetch_blocklist_data(limit)
        if blocklist_threats:
            sources.append("blocklist")
    except UpstreamThreatDataUnavailable as exc:
        errors.append(str(exc))

    threats = merge_threat_feeds(abuseipdb_threats, blocklist_threats)

    if not threats:
        cached_response: Optional[ThreatFeedResponse] = _THREAT_CACHE["response"]
        if cached_response is not None:
            logger.warning("Threat providers returned no usable threats. Keeping cached threat set.")
            return _slice_response(cached_response, limit, cached=True)
        if errors:
            raise UpstreamThreatDataUnavailable("; ".join(errors))
        threats = get_mock_data()
        sources = ["mock"]

    source = "+".join(sources) if sources else "mock"
    threats = enrich_threats_with_coordinates(threats)
    threats = score_threats(threats)
    response = _build_feed_response(threats, source=source, cached=False)
    _set_cache(response)
    return response


async def get_threats(limit: int = 100) -> ThreatFeedResponse:
    if _is_cache_fresh(limit):
        cached_response: ThreatFeedResponse = _THREAT_CACHE["response"]
        return _slice_response(cached_response, limit, cached=True)

    try:
        response = await _refresh_threats(limit)
        return _slice_response(response, limit, cached=response.meta.cached)
    except UpstreamThreatDataUnavailable:
        cached_response: Optional[ThreatFeedResponse] = _THREAT_CACHE["response"]
        if cached_response is not None:
            logger.warning("Threat refresh failed. Serving stale cached threats instead.")
            return _slice_response(cached_response, limit, cached=True)
        raise
