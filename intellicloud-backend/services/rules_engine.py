import yaml
import re
import os
from pathlib import Path

_RULES_PATH = Path(__file__).parent.parent / "rules" / "rules.yaml"

def _load_rules() -> list[dict]:
    try:
        with open(_RULES_PATH) as f:
            return yaml.safe_load(f) or []
    except Exception as e:
        print(f"[rules] Failed to load rules: {e}")
        return []

def evaluate_rules(packet: dict, client_id=None) -> list[dict]:
    """
    Evaluate a scored packet against the rules file.
    Returns a list of triggered rule dicts (may be empty).
    """
    rules = _load_rules()
    triggered = []

    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    pkt_level = severity_rank.get((packet.get("level") or "low").lower(), 1)

    for rule in rules:
        rule_id = rule.get("id", "unknown")
        when = rule.get("when", {})

        # Check threat_level_gte
        min_rank = severity_rank.get(
            str(when.get("threat_level_gte", "")).lower().replace("3", "high").replace("2", "medium"), 0
        )
        if when.get("threat_level_gte") and pkt_level < min_rank:
            continue

        # Check ua_regex against dns or reason fields
        ua_regex = when.get("ua_regex")
        if ua_regex:
            haystack = f"{packet.get('dns','')} {packet.get('reason','')}"
            if not re.search(ua_regex, haystack, re.IGNORECASE):
                continue

        # Check detection_type match
        detection_type = when.get("detection_type")
        if detection_type and packet.get("detection_type") != detection_type:
            continue

        # Rule matched
        triggered.append({
            "rule_id": rule_id,
            "severity": rule.get("severity", "medium"),
            "title": rule.get("title", rule_id),
            "actions": rule.get("actions", []),
        })

    return triggered