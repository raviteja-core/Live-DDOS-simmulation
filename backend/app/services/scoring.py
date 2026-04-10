import logging
import os
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from app.models.threat import Threat

logger = logging.getLogger(__name__)
SCORING_MODE_ALIASES = {
    "auto": "heuristic",
    "ml": "heuristic",
    "hybrid": "heuristic",
    "rule_based": "heuristic",
}


CATEGORY_WEIGHTS = {
    "ddos": 18,
    "botnet": 14,
    "malware": 13,
    "phishing": 12,
    "bruteforce": 10,
    "spam": 8,
    "scanner": 7,
    "proxy": 6,
    "hosting": 5,
}

THREAT_LEVEL_BOUNDS = (
    (90, "critical"),
    (70, "elevated"),
    (0, "observed"),
)
CRITICAL_SHARE = 0.2
ELEVATED_SHARE = 0.35


def get_threat_level(score: int) -> str:
    for minimum_score, label in THREAT_LEVEL_BOUNDS:
        if score >= minimum_score:
            return label
    return "observed"


def _hours_since_last_report(last_reported_at: Optional[datetime]) -> Optional[float]:
    if last_reported_at is None:
        return None

    if last_reported_at.tzinfo is None:
        last_reported_at = last_reported_at.replace(tzinfo=timezone.utc)

    delta = datetime.now(timezone.utc) - last_reported_at.astimezone(timezone.utc)
    return max(delta.total_seconds() / 3600, 0.0)


def _category_weight(category: str) -> int:
    normalized = category.lower()
    for keyword, weight in CATEGORY_WEIGHTS.items():
        if keyword in normalized:
            return weight
    return 4


def calculate_heuristic_score(threat: Threat) -> int:
    abuse_score = float(threat.abuse_confidence_score)
    category_signal = _category_weight(threat.category)
    score = abuse_score * 0.72
    score += max(category_signal - 4, 0) * 0.9

    hours_since_report = _hours_since_last_report(threat.last_reported_at)
    if hours_since_report is not None:
        if hours_since_report <= 1:
            score += 12
        elif hours_since_report <= 6:
            score += 8
        elif hours_since_report <= 24:
            score += 5
        elif hours_since_report <= 72:
            score += 2
        elif hours_since_report >= 168:
            score -= 10

    if threat.latitude is not None and threat.longitude is not None:
        score += 1

    if abuse_score >= 95:
        score += 7
    elif abuse_score >= 85:
        score += 4
    elif abuse_score <= 40:
        score -= 8
    elif abuse_score <= 60:
        score -= 3

    return max(0, min(100, round(score)))


def _calibrated_score_for_rank(index: int, total: int) -> int:
    if total <= 0:
        return 0

    critical_count = max(1, round(total * CRITICAL_SHARE))
    elevated_count = max(1, round(total * ELEVATED_SHARE))
    observed_count = max(total - critical_count - elevated_count, 1)

    if index < critical_count:
        if critical_count == 1:
            return 96
        step = min(index, critical_count - 1)
        return max(90, 96 - round((step / (critical_count - 1)) * 6))

    elevated_index = index - critical_count
    if elevated_index < elevated_count:
        if elevated_count == 1:
            return 80
        step = min(elevated_index, elevated_count - 1)
        return max(70, 88 - round((step / (elevated_count - 1)) * 18))

    observed_index = index - critical_count - elevated_count
    if observed_count == 1:
        return 60
    step = min(observed_index, observed_count - 1)
    return max(35, 68 - round((step / (observed_count - 1)) * 33))


def calibrate_threat_scores(threats: Iterable[Threat]) -> List[Threat]:
    threat_list = list(threats)
    ranked = sorted(
        threat_list,
        key=lambda threat: (
            threat.risk_score,
            threat.abuse_confidence_score,
            1 if threat.last_reported_at is not None else 0,
        ),
        reverse=True,
    )

    calibrated_by_ip: dict[str, Threat] = {}
    total = len(ranked)
    for index, threat in enumerate(ranked):
        calibrated_score = _calibrated_score_for_rank(index, total)
        calibrated_by_ip[threat.ip] = threat.model_copy(
            update={
                "threat_score": calibrated_score,
                "threat_level": get_threat_level(calibrated_score),
            }
        )

    return [calibrated_by_ip[threat.ip] for threat in threat_list]


def normalize_scoring_mode(scoring_mode: str) -> str:
    normalized = scoring_mode.lower().strip()
    if normalized in {"", "heuristic"}:
        return "heuristic"
    if normalized in SCORING_MODE_ALIASES:
        return SCORING_MODE_ALIASES[normalized]

    logger.warning(
        "Unsupported scoring mode '%s' requested. Falling back to heuristic scoring.",
        scoring_mode,
    )
    return "heuristic"


def score_threat(threat: Threat, scoring_mode: str = "heuristic") -> Threat:
    scoring_mode = normalize_scoring_mode(scoring_mode)

    threat_score = calculate_heuristic_score(threat)

    return threat.model_copy(
        update={
            "risk_score": threat_score,
            "threat_score": threat_score,
            "threat_level": get_threat_level(threat_score),
            "scoring_method": "heuristic_v1",
        }
    )


def score_threats(threats: Iterable[Threat]) -> List[Threat]:
    scoring_mode = normalize_scoring_mode(os.getenv("SCORING_MODE", "heuristic"))
    scored = [score_threat(threat, scoring_mode=scoring_mode) for threat in threats]
    return calibrate_threat_scores(scored)
