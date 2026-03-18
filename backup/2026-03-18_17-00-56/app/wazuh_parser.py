import hashlib
import json
from .models import WazuhAlert

def map_severity(level: int) -> str:
    if level <= 4: return "Low"
    if level <= 7: return "Medium"
    if level <= 10: return "High"
    return "Critical"

def generate_dedup_key(alert: WazuhAlert) -> str:
    # Stable key based on rule, agent, location, and relevant data points
    base = f"{alert.rule.id}-{alert.agent.id}-{alert.location}"
    
    if alert.data:
        # Add CVE or IP to dedup key if available to separate distinct events under the same rule
        if "vulnerability" in alert.data and "cve" in alert.data["vulnerability"]:
            base += f"-{alert.data['vulnerability']['cve']}"
        elif "srcip" in alert.data:
            base += f"-{alert.data['srcip']}"
            
    return hashlib.md5(base.encode()).hexdigest()

def generate_markdown_description(alert: WazuhAlert) -> str:
    desc = f"### Wazuh Alert Summary\n\n"
    desc += f"**Description:** {alert.rule.description}\n"
    desc += f"**Rule ID:** {alert.rule.id} (Level {alert.rule.level})\n"
    desc += f"**Agent:** {alert.agent.name} ({alert.agent.id})\n"
    desc += f"**Location:** {alert.location}\n\n"
    
    if alert.full_log:
        desc += f"**Full Log:**\n```text\n{alert.full_log}\n```\n\n"
        
    desc += f"**Raw JSON Payload:**\n```json\n{json.dumps(alert.raw_payload, indent=2)}\n```\n"
    return desc