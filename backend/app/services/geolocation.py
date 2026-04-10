import ipaddress
import logging
import os
from typing import Iterable, List, Optional

from app.config import get_default_geolite2_db_path
from app.models.threat import Threat

logger = logging.getLogger(__name__)
_GEO_READER = None
_GEO_READER_PATH: Optional[str] = None
_GEOLOCATION_CACHE: dict[str, tuple[Optional[float], Optional[float]]] = {}

try:
    import geoip2.database
    import geoip2.errors
except ModuleNotFoundError:  # pragma: no cover
    geoip2 = None


def get_geolite2_db_path() -> str:
    return os.getenv("GEOLITE2_DB_PATH", str(get_default_geolite2_db_path()))


def is_public_ip(ip_address: str) -> bool:
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return parsed_ip.is_global


def _get_geo_reader():
    global _GEO_READER, _GEO_READER_PATH

    if geoip2 is None:
        return None

    db_path = get_geolite2_db_path()
    if not os.path.exists(db_path):
        logger.warning("GeoLite2 database not found at %s", db_path)
        return None

    if _GEO_READER is not None and _GEO_READER_PATH == db_path:
        return _GEO_READER

    try:
        _GEO_READER = geoip2.database.Reader(db_path)
        _GEO_READER_PATH = db_path
    except (FileNotFoundError, OSError) as exc:
        logger.warning("Unable to open GeoLite2 database at %s: %s", db_path, exc)
        _GEO_READER = None
        _GEO_READER_PATH = None

    return _GEO_READER


def lookup_coordinates(ip_address: str) -> tuple[Optional[float], Optional[float]]:
    if not is_public_ip(ip_address):
        return None, None

    if ip_address in _GEOLOCATION_CACHE:
        return _GEOLOCATION_CACHE[ip_address]

    if geoip2 is None:
        logger.warning("geoip2 is not installed. Returning empty coordinates for %s", ip_address)
        return None, None

    reader = _get_geo_reader()
    if reader is None:
        return None, None

    try:
        response = reader.city(ip_address)
    except (FileNotFoundError, OSError, geoip2.errors.AddressNotFoundError) as exc:
        logger.warning("Geo lookup failed for %s: %s", ip_address, exc)
        return None, None

    coordinates = (response.location.latitude, response.location.longitude)
    _GEOLOCATION_CACHE[ip_address] = coordinates
    return coordinates


def enrich_threat_with_coordinates(threat: Threat) -> Threat:
    latitude, longitude = lookup_coordinates(threat.ip)
    if latitude is None or longitude is None:
        latitude = threat.latitude
        longitude = threat.longitude
    return threat.model_copy(update={"latitude": latitude, "longitude": longitude})


def enrich_threats_with_coordinates(threats: Iterable[Threat]) -> List[Threat]:
    return [enrich_threat_with_coordinates(threat) for threat in threats]
