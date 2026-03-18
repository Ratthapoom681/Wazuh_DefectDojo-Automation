import logging
from fastapi import FastAPI, Request, BackgroundTasks
from .config import load_config, DOJO_URL, DOJO_API_KEY
from .models import WazuhAlert
from .wazuh_parser import generate_dedup_key, map_severity, generate_markdown_description
from .routing import determine_owner_group
from .assignment import init_db, get_next_user
from .defectdojo_client import DefectDojoClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Wazuh to DefectDojo Integrator")
config = load_config()
dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY)
DEFAULT_FOUND_BY_TEST_TYPE_ID = 1

@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("Service started. Database initialized.")

def process_alert(raw_payload: dict):
    # 1. Parse Alert
    try:
        alert = WazuhAlert(**raw_payload, raw_payload=raw_payload)
    except Exception as e:
        logger.error(f"Failed to parse alert: {e}")
        return

    # 2. Routing
    owner_group = determine_owner_group(alert, config)
    group_config = config.teams.get(owner_group)
    
    # 3. Determine active users
    if group_config is None:
        logger.warning(
            "Owner group '%s' is not defined in config.yaml teams. Falling back to unassigned finding.",
            owner_group,
        )
        active_users = []
        fallback_user = None
        assignment_error = True
    else:
        active_users = [u for u in group_config.users if dd_client.is_user_active(u)]
        fallback_user = group_config.fallback_user
        assignment_error = False
    
    assigned_user = None
    
    if active_users:
        assigned_user = get_next_user(owner_group, active_users)
    else:
        assigned_user = fallback_user
        assignment_error = True

    assigned_user_obj = dd_client.get_user(assigned_user) if assigned_user else None
    assigned_user_id = assigned_user_obj["id"] if assigned_user_obj else None

    # 4. Prepare Finding Payload
    test_id = dd_client.ensure_context()
    dedup_key = generate_dedup_key(alert)
    
    tags = ["source:wazuh", f"wazuh_rule:{alert.rule.id}", f"owner_group:{owner_group}"]
    if alert.rule.groups:
        tags.append(f"wazuh_group:{alert.rule.groups[0]}")
    if assignment_error:
        tags.append("assignment_error")

    finding_data = {
        "test": test_id,
        "title": f"[Wazuh] {alert.rule.description} on {alert.agent.name}",
        "description": generate_markdown_description(alert),
        "severity": map_severity(alert.rule.level),
        "numerical_severity": alert.rule.level,
        "active": True,
        "verified": True,
        "tags": tags,
        "found_by": [DEFAULT_FOUND_BY_TEST_TYPE_ID],
        "unique_id_from_tool": dedup_key
    }
    
    # Optional natively supported assignee field in modern DefectDojo
    if assigned_user_id:
        finding_data["reviewer"] = assigned_user_id

    assign_note = f"Automated Routing: Mapped to group '{owner_group}'. Assigned to user '{assigned_user}'."

    # 5. Push to DefectDojo
    try:
        dd_client.push_finding(finding_data, assign_note)
        logger.info(f"Processed rule {alert.rule.id} -> DD Finding (Dedup: {dedup_key}) assigned to {assigned_user}")
    except Exception as e:
        logger.error(f"Failed to push finding to DefectDojo: {e}")

@app.post("/webhook")
async def wazuh_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    # Execute synchronously in background to release webhook instantly
    background_tasks.add_task(process_alert, payload)
    return {"status": "accepted"}
