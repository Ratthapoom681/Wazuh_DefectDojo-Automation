from .config import AppConfig
from .models import WazuhAlert

def determine_owner_group(alert: WazuhAlert, config: AppConfig) -> str:
    alert_groups = [g.lower() for g in alert.rule.groups]
    
    for rule in config.routing_rules:
        for match in rule.match_rule_groups:
            if match.lower() in alert_groups:
                return rule.owner_group
                
    return config.default_owner_group