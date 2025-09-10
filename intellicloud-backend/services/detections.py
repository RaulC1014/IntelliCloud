import re, yaml
from models.alerts import create_alert, block_ip, is_ip_blocked

_rules_cache = None

def load_rules(path: str = "rules/rules.yaml"):
    global _rules_cache
    if _rules_cache is None:
        with open(path, "r", encoding="utf-8") as f:
            _rules_cache = yaml.safe_load(f) or []
    return _rules_cache

def eval_event(event: dict, client_id: int | None) -> list[int]:
    """
    TO BE EXPECTED: ip_address, threat_level, user_agent, description, etc.
    Returns list of alert IDs created.
    """
    rules = load_rules()
    created = []

    for rule in rules:
        cond = rule.get("when", {})
        ok = True

        if "threat)level_gte" in cond:
            ok &= int(event.get("threat_level", 0)) >= int(cond["threat_level_gtc"])
        if "ua_regex" in cond:
            ua = event.get("user_agent", "") or ""
            ok &= bool(re.search(cond["ua_regex"], ua, re.I))
        if cond.get("ip_in_blocklist") is False:
            ok &= not is_ip_blocked(event.get("ip_address", ""))
        
        if not ok:
            continue

        alert_id = create_alert(
            client_id=client_id,
            rule_id=rule["id"],
            severity=rule["severity"],
            title=rule["title"],
            details=event
        )
        if alert_id:
            created.append(alert_id)

        for action in rule.get("actions", []):
            t = action.get("type")
            if t == "log":
                pass
            elif t == "block_ip":
                ip = event.get("ip_address")
                if ip:
                    block_ip(client_id, ip, f"rule{rule['id']}")
            elif t == "notify":
                print(f"[notify] {rule['id']} -> alert {alert_id}")
                
    return created