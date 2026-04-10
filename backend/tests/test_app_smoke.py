import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.config import load_env_file
from app.main import app
from app.models.threat import Threat
from app.routers.health import health_check
from app.routers.threats import get_threat_data
from app.services.abuseipdb import UpstreamThreatDataUnavailable


class AppSmokeTests(unittest.TestCase):
    def test_expected_routes_are_registered(self) -> None:
        routes = {route.path for route in app.routes}
        self.assertIn("/", routes)
        self.assertIn("/health", routes)
        self.assertIn("/threats", routes)

    def test_health_handler_returns_ok(self) -> None:
        result = asyncio.run(health_check())
        self.assertEqual(result, {"status": "ok"})

    def test_threats_handler_returns_service_data(self) -> None:
        fake_data = {
            "data": [
                {
                    "ip": "8.8.8.8",
                    "abuse_confidence_score": 99,
                    "category": "Threat Intel",
                    "last_reported_at": None,
                    "latitude": 12.34,
                    "longitude": 56.78,
                    "risk_score": 98,
                    "threat_score": 98,
                    "threat_level": "critical",
                    "scoring_method": "heuristic_v1",
                }
            ],
            "meta": {
                "source": "mock",
                "cached": False,
                "generated_at": "2026-04-04T00:00:00Z",
                "count_total": 1,
                "count_mapped": 1,
            },
        }

        with patch("app.routers.threats.get_threats", return_value=fake_data):
            result = asyncio.run(get_threat_data(limit=1))

        self.assertEqual(result, fake_data)

    def test_load_env_file_sets_api_key_from_local_env_file(self) -> None:
        os.environ.pop("ABUSEIPDB_API_KEY", None)
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("ABUSEIPDB_API_KEY=test-key\n", encoding="utf-8")
            load_env_file(env_path=env_path, override=True)

        self.assertEqual(os.getenv("ABUSEIPDB_API_KEY"), "test-key")

    def test_threats_endpoint_returns_502_when_upstream_is_unavailable_and_no_cache_exists(self) -> None:
        with patch(
            "app.routers.threats.get_threats",
            side_effect=UpstreamThreatDataUnavailable("Threat feed request timed out"),
        ):
            with self.assertRaises(HTTPException) as exc_info:
                asyncio.run(get_threat_data(limit=1))

        self.assertEqual(exc_info.exception.status_code, 502)
        self.assertEqual(exc_info.exception.detail, "Threat feed request timed out")

    def test_threats_endpoint_rejects_invalid_limit(self) -> None:
        threats_route = next(route for route in app.routes if route.path == "/threats")
        limit_param = threats_route.dependant.query_params[0]
        metadata = {type(item).__name__: item for item in limit_param.field_info.metadata}

        self.assertEqual(metadata["Ge"].ge, 1)
        self.assertEqual(metadata["Le"].le, 1000)

    def test_threat_model_rejects_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            Threat(ip="not-an-ip", abuse_confidence_score=140)


if __name__ == "__main__":
    unittest.main()
