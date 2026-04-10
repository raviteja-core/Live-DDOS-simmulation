import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import httpx

from app.models.threat import Threat, ThreatFeedResponse
from app.services.abuseipdb import (
    _THREAT_CACHE,
    fetch_abuseipdb_data,
    fetch_blocklist_data,
    get_threats,
    get_mock_data,
    merge_threat_feeds,
    parse_last_reported_at,
    parse_blocklist_lines,
    UpstreamThreatDataUnavailable,
)


class AbuseIPDBServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        _THREAT_CACHE["response"] = None

    def test_fetch_abuseipdb_data_parses_valid_items(self) -> None:
        payload = {
            "data": [
                {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 91,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "lastReportedAt": "2026-03-21T12:00:00Z",
                }
            ]
        }
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = payload
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_client

        with patch("app.services.abuseipdb.httpx.AsyncClient", return_value=mock_context):
            threats = asyncio.run(fetch_abuseipdb_data("fake-key", limit=1))

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].ip, "8.8.8.8")
        self.assertEqual(threats[0].abuse_confidence_score, 91)
        self.assertEqual(threats[0].category, "Data Center/Web Hosting/Transit")
        self.assertIsNotNone(threats[0].last_reported_at)

    def test_fetch_abuseipdb_data_skips_invalid_items_without_dropping_valid_ones(self) -> None:
        payload = {
            "data": [
                {
                    "ipAddress": "8.8.4.4",
                    "abuseConfidenceScore": 81,
                    "lastReportedAt": None,
                },
                {
                    "abuseConfidenceScore": 64,
                    "lastReportedAt": "2026-03-21T12:00:00Z",
                },
            ]
        }
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = payload
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_client

        with patch("app.services.abuseipdb.httpx.AsyncClient", return_value=mock_context):
            threats = asyncio.run(fetch_abuseipdb_data("fake-key", limit=2))

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].ip, "8.8.4.4")
        self.assertIsNone(threats[0].last_reported_at)

    def test_fetch_abuseipdb_data_raises_upstream_error_on_request_failure(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.TimeoutException("boom")
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_client

        with patch("app.services.abuseipdb.httpx.AsyncClient", return_value=mock_context):
            with self.assertRaises(UpstreamThreatDataUnavailable):
                asyncio.run(fetch_abuseipdb_data("fake-key", limit=2))

    def test_parse_blocklist_lines_extracts_ips_into_threats(self) -> None:
        payload = "1.2.3.4\nmalformed-line\n5.6.7.8 attack-source\n1.2.3.4\n"

        threats = parse_blocklist_lines(payload, limit=10)

        self.assertEqual([threat.ip for threat in threats], ["1.2.3.4", "5.6.7.8"])
        self.assertTrue(all(threat.category == "Blocklist.de Recent Attacker" for threat in threats))

    def test_parse_blocklist_lines_generates_score_spread_across_rank(self) -> None:
        payload = "\n".join(f"10.0.0.{index}" for index in range(1, 221))

        threats = parse_blocklist_lines(payload, limit=220)
        scores = [threat.abuse_confidence_score for threat in threats]

        self.assertTrue(any(score >= 90 for score in scores))
        self.assertTrue(any(70 <= score < 90 for score in scores))
        self.assertTrue(any(score < 70 for score in scores))

    def test_fetch_blocklist_data_parses_text_payload(self) -> None:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = "1.2.3.4\n5.6.7.8\n"
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_client

        with patch("app.services.abuseipdb.httpx.AsyncClient", return_value=mock_context):
            threats = asyncio.run(fetch_blocklist_data(limit=2))

        self.assertEqual(len(threats), 2)
        self.assertEqual(threats[0].ip, "1.2.3.4")

    def test_merge_threat_feeds_deduplicates_ip_across_sources(self) -> None:
        abuseipdb_feed = [
            Threat(ip="8.8.8.8", abuse_confidence_score=90, category="DDoS"),
        ]
        blocklist_feed = [
            Threat(ip="8.8.8.8", abuse_confidence_score=60, category="Blocklist.de Recent Attacker"),
            Threat(ip="1.1.1.1", abuse_confidence_score=55, category="Blocklist.de Recent Attacker"),
        ]

        merged = merge_threat_feeds(abuseipdb_feed, blocklist_feed)
        merged_by_ip = {threat.ip: threat for threat in merged}

        self.assertEqual(len(merged), 2)
        self.assertEqual(merged_by_ip["8.8.8.8"].abuse_confidence_score, 90)
        self.assertIn("Blocklist.de Recent Attacker", merged_by_ip["8.8.8.8"].category)

    def test_parse_last_reported_at_handles_missing_values(self) -> None:
        self.assertIsNone(parse_last_reported_at(None))
        self.assertIsNone(parse_last_reported_at(""))

    def test_get_threats_uses_fresh_cache(self) -> None:
        cached_threat = Threat(ip="8.8.8.8", abuse_confidence_score=90, threat_score=82, threat_level="elevated")
        _THREAT_CACHE["response"] = ThreatFeedResponse.model_validate(
            {
                "data": [cached_threat.model_dump()],
                "meta": {
                    "source": "abuseipdb",
                    "cached": False,
                    "generated_at": datetime.now(timezone.utc),
                    "count_total": 1,
                    "count_mapped": 0,
                },
            }
        )

        with patch("app.services.abuseipdb._refresh_threats") as refresh_mock:
            response = asyncio.run(get_threats(limit=1))

        refresh_mock.assert_not_called()
        self.assertEqual(response.data[0].ip, "8.8.8.8")
        self.assertTrue(response.meta.cached)

    def test_get_threats_serves_stale_cache_when_refresh_fails(self) -> None:
        cached_threat = Threat(ip="1.1.1.1", abuse_confidence_score=78, threat_score=76, threat_level="elevated")
        _THREAT_CACHE["response"] = ThreatFeedResponse.model_validate(
            {
                "data": [cached_threat.model_dump()],
                "meta": {
                    "source": "abuseipdb",
                    "cached": False,
                    "generated_at": datetime.now(timezone.utc) - timedelta(seconds=600),
                    "count_total": 1,
                    "count_mapped": 0,
                },
            }
        )

        with patch(
            "app.services.abuseipdb._refresh_threats",
            side_effect=UpstreamThreatDataUnavailable("refresh failed"),
        ):
            response = asyncio.run(get_threats(limit=1))

        self.assertEqual(response.data[0].ip, "1.1.1.1")
        self.assertTrue(response.meta.cached)

    def test_get_threats_raises_502_equivalent_error_when_no_cache_exists(self) -> None:
        with patch(
            "app.services.abuseipdb._refresh_threats",
            side_effect=UpstreamThreatDataUnavailable("refresh failed"),
        ):
            with self.assertRaises(UpstreamThreatDataUnavailable):
                asyncio.run(get_threats(limit=1))

    def test_get_threats_uses_blocklist_when_abuseipdb_fails(self) -> None:
        response = ThreatFeedResponse.model_validate(
            {
                "data": [
                    Threat(
                        ip="1.2.3.4",
                        abuse_confidence_score=55,
                        category="Blocklist.de Recent Attacker",
                    ).model_dump()
                ],
                "meta": {
                    "source": "blocklist",
                    "cached": False,
                    "generated_at": datetime.now(timezone.utc),
                    "count_total": 1,
                    "count_mapped": 0,
                },
            }
        )

        with patch(
            "app.services.abuseipdb._refresh_threats",
            return_value=response,
        ):
            merged_response = asyncio.run(get_threats(limit=1))

        self.assertEqual(merged_response.meta.source, "blocklist")
        self.assertEqual(merged_response.data[0].ip, "1.2.3.4")

    def test_mock_data_contains_renderable_coordinates(self) -> None:
        threats = get_mock_data()

        self.assertTrue(all(threat.latitude is not None for threat in threats))
        self.assertTrue(all(threat.longitude is not None for threat in threats))


if __name__ == "__main__":
    unittest.main()
