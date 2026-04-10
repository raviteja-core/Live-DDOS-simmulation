import os
import unittest
from unittest.mock import patch

from app.models.threat import Threat
from app.services import geolocation


class GeolocationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        geolocation._GEOLOCATION_CACHE.clear()
        geolocation._GEO_READER = None
        geolocation._GEO_READER_PATH = None

    def test_public_ip_detection(self) -> None:
        self.assertTrue(geolocation.is_public_ip("8.8.8.8"))
        self.assertFalse(geolocation.is_public_ip("192.168.1.1"))
        self.assertFalse(geolocation.is_public_ip("not-an-ip"))

    def test_lookup_coordinates_returns_none_for_private_ip(self) -> None:
        latitude, longitude = geolocation.lookup_coordinates("192.168.1.1")
        self.assertIsNone(latitude)
        self.assertIsNone(longitude)

    def test_lookup_coordinates_returns_none_when_database_is_missing(self) -> None:
        with patch.dict(os.environ, {"GEOLITE2_DB_PATH": "/tmp/missing.mmdb"}, clear=False):
            latitude, longitude = geolocation.lookup_coordinates("8.8.8.8")

        self.assertIsNone(latitude)
        self.assertIsNone(longitude)

    def test_enrich_threat_with_coordinates_updates_model(self) -> None:
        threat = Threat(ip="8.8.8.8", abuse_confidence_score=95, category="Threat Intel")

        with patch("app.services.geolocation.lookup_coordinates", return_value=(37.751, -97.822)):
            enriched = geolocation.enrich_threat_with_coordinates(threat)

        self.assertEqual(enriched.latitude, 37.751)
        self.assertEqual(enriched.longitude, -97.822)

    def test_enrich_threat_with_coordinates_preserves_existing_fallback_coordinates(self) -> None:
        threat = Threat(
            ip="8.8.8.8",
            abuse_confidence_score=95,
            category="Threat Intel",
            latitude=10.0,
            longitude=20.0,
        )

        with patch("app.services.geolocation.lookup_coordinates", return_value=(None, None)):
            enriched = geolocation.enrich_threat_with_coordinates(threat)

        self.assertEqual(enriched.latitude, 10.0)
        self.assertEqual(enriched.longitude, 20.0)

    def test_default_geolite2_path_points_to_project_data_directory(self) -> None:
        default_path = geolocation.get_geolite2_db_path()
        self.assertTrue(default_path.endswith("data/GeoLite2-City.mmdb"))

    def test_lookup_coordinates_uses_in_memory_cache(self) -> None:
        mock_reader = unittest.mock.Mock()
        mock_reader.city.return_value.location.latitude = 37.0
        mock_reader.city.return_value.location.longitude = -122.0

        with patch("app.services.geolocation._get_geo_reader", return_value=mock_reader):
            first_lookup = geolocation.lookup_coordinates("8.8.8.8")
            second_lookup = geolocation.lookup_coordinates("8.8.8.8")

        self.assertEqual(first_lookup, (37.0, -122.0))
        self.assertEqual(second_lookup, (37.0, -122.0))
        self.assertEqual(mock_reader.city.call_count, 1)


if __name__ == "__main__":
    unittest.main()
