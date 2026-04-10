import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.models.threat import Threat
from app.services.scoring import (
    calibrate_threat_scores,
    calculate_heuristic_score,
    get_threat_level,
    score_threat,
    score_threats,
)


class ScoringServiceTests(unittest.TestCase):
    def test_heuristic_score_rewards_severity_and_recency(self) -> None:
        threat = Threat(
            ip="8.8.8.8",
            abuse_confidence_score=92,
            category="DDoS",
            last_reported_at=datetime.now(timezone.utc) - timedelta(hours=2),
            latitude=37.77,
            longitude=-122.41,
        )

        score = calculate_heuristic_score(threat)

        self.assertGreaterEqual(score, 90)
        self.assertEqual(get_threat_level(score), "critical")

    def test_heuristic_score_decreases_for_old_low_signal_threats(self) -> None:
        threat = Threat(
            ip="4.4.4.4",
            abuse_confidence_score=42,
            category="Generic Hosting",
            last_reported_at=datetime.now(timezone.utc) - timedelta(days=12),
        )

        score = calculate_heuristic_score(threat)

        self.assertLess(score, 45)
        self.assertEqual(get_threat_level(score), "observed")

    def test_heuristic_score_keeps_mid_signal_threats_in_elevated_band(self) -> None:
        threat = Threat(
            ip="5.5.5.5",
            abuse_confidence_score=84,
            category="Spam",
            last_reported_at=datetime.now(timezone.utc) - timedelta(hours=4),
            latitude=12.0,
            longitude=15.0,
        )

        score = calculate_heuristic_score(threat)

        self.assertGreaterEqual(score, 70)
        self.assertLess(score, 90)
        self.assertEqual(get_threat_level(score), "elevated")

    def test_score_threat_uses_heuristic_scoring(self) -> None:
        threat = Threat(
            ip="1.1.1.1",
            abuse_confidence_score=88,
            category="Spam",
            last_reported_at=datetime.now(timezone.utc),
        )

        scored = score_threat(threat, scoring_mode="heuristic")

        self.assertEqual(scored.scoring_method, "heuristic_v1")
        self.assertEqual(scored.risk_score, calculate_heuristic_score(threat))
        self.assertEqual(scored.threat_score, scored.risk_score)

    def test_unsupported_scoring_mode_falls_back_to_heuristic(self) -> None:
        threat = Threat(
            ip="9.9.9.9",
            abuse_confidence_score=90,
            category="Botnet",
            last_reported_at=datetime.now(timezone.utc),
            latitude=10.0,
            longitude=20.0,
        )

        scored = score_threat(threat, scoring_mode="ml")

        self.assertEqual(scored.scoring_method, "heuristic_v1")
        self.assertGreaterEqual(scored.threat_score, 70)
        self.assertIn(scored.threat_level, {"critical", "elevated"})

    def test_score_is_bounded_for_extreme_inputs(self) -> None:
        threat = Threat(
            ip="7.7.7.7",
            abuse_confidence_score=100,
            category="DDoS botnet malware",
            last_reported_at=datetime.now(timezone.utc) - timedelta(hours=1),
            latitude=30.0,
            longitude=40.0,
        )

        scored = score_threat(threat)

        self.assertGreaterEqual(scored.risk_score, 0)
        self.assertLessEqual(scored.risk_score, 100)

    def test_score_threats_reads_scoring_mode_from_environment(self) -> None:
        threats = [
            Threat(ip="8.8.4.4", abuse_confidence_score=78, category="DDoS", latitude=1.0, longitude=2.0)
        ]

        with patch.dict(os.environ, {"SCORING_MODE": "heuristic"}, clear=False):
            scored = score_threats(threats)

        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0].scoring_method, "heuristic_v1")
        self.assertGreater(scored[0].threat_score, 0)

    def test_calibration_spreads_batch_across_all_threat_levels(self) -> None:
        threats = [
            Threat(ip=f"8.8.8.{index}", abuse_confidence_score=90 - index, category="DDoS")
            for index in range(1, 21)
        ]
        scored = [score_threat(threat) for threat in threats]

        calibrated = calibrate_threat_scores(scored)
        levels = {threat.threat_level for threat in calibrated}

        self.assertEqual(levels, {"critical", "elevated", "observed"})

    def test_calibration_preserves_raw_risk_score_and_changes_display_score(self) -> None:
        threats = [
            Threat(ip=f"9.9.9.{index}", abuse_confidence_score=80 - index, category="Spam")
            for index in range(1, 6)
        ]

        calibrated = calibrate_threat_scores([score_threat(threat) for threat in threats])

        self.assertTrue(all(threat.risk_score >= 0 for threat in calibrated))
        self.assertTrue(all(threat.threat_score >= 0 for threat in calibrated))
        self.assertTrue(any(threat.risk_score != threat.threat_score for threat in calibrated))


if __name__ == "__main__":
    unittest.main()
