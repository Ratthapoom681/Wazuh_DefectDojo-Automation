import logging
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from .config import AppConfig, load_config, save_config, DOJO_URL, DOJO_API_KEY
from .matching import build_alert_match_tokens, rule_matches
from .models import WazuhAlert
from .wazuh_parser import (
    generate_dedup_key,
    generate_impact,
    generate_markdown_description,
    generate_mitigation,
    map_severity,
)
from .routing import determine_owner_group
from .assignment import init_db, get_assigned_user, get_next_user, remember_assignment
from .defectdojo_client import DefectDojoClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Wazuh to DefectDojo Integrator")
config = load_config()
dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo)
DEFAULT_FOUND_BY_TEST_TYPE_ID = 1


def reload_runtime_config(new_config: AppConfig) -> None:
    global config, dd_client
    config = new_config
    dd_client = DefectDojoClient(DOJO_URL, DOJO_API_KEY, config.defectdojo)


def build_tags(alert: WazuhAlert, owner_group: str, assignment_error: bool) -> list[str]:
    tags = ["source:wazuh", f"wazuh_rule:{alert.rule.id}", f"owner_group:{owner_group}"]
    alert_tokens = build_alert_match_tokens(alert)

    for group in alert.rule.groups:
        normalized_group = group.strip().lower().replace(" ", "-").replace(",", "-").replace("\"", "")
        tags.append(f"wazuh_group:{normalized_group}")

    for tag_rule in config.tag_rules:
        if any(rule_matches(match, alert_tokens) for match in tag_rule.match_rule_groups):
            tags.extend(tag_rule.tags)

    if assignment_error:
        tags.append("assignment_error")

    # Keep tags stable and avoid duplicates when multiple rules map to the same label.
    return list(dict.fromkeys(tags))


def get_test_category(tags: list[str]) -> str:
    for tag, test_name in config.categories.tag_to_test.items():
        if tag in tags:
            return test_name
    return config.categories.default_test


def get_endpoint_host(alert: WazuhAlert) -> str | None:
    if alert.agent.ip:
        return alert.agent.ip

    if alert.agent.name:
        return alert.agent.name

    if alert.manager and alert.manager.get("name"):
        return str(alert.manager["name"])

    return None

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
    tags = build_tags(alert, owner_group, assignment_error=False)
    test_category = get_test_category(tags)
    
    # 3. Prepare DefectDojo test context and determine active users
    context = dd_client.ensure_context(test_category)
    test_id = context["test_id"]
    product_id = context["product_id"]
    dedup_key = generate_dedup_key(alert)
    existing_finding = dd_client.get_finding_by_dedup(dedup_key)

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
    stored_user = get_assigned_user(dedup_key, active_users)
    
    if existing_finding:
        assigned_user = stored_user
        assignment_error = False
    elif stored_user:
        assigned_user = stored_user
    elif active_users:
        assigned_user = get_next_user(owner_group, active_users)
    else:
        assigned_user = fallback_user
        assignment_error = True

    assigned_user_obj = dd_client.get_user(assigned_user) if assigned_user else None
    assigned_user_id = assigned_user_obj["id"] if assigned_user_obj else None
    remember_assignment(dedup_key, owner_group, assigned_user)

    # 4. Prepare Finding Payload
    tags = build_tags(alert, owner_group, assignment_error)

    finding_data = {
        "test": test_id,
        "title": f"[Wazuh] {alert.rule.description} on {alert.agent.name}",
        "description": generate_markdown_description(alert),
        "impact": generate_impact(alert),
        "mitigation": generate_mitigation(alert),
        "severity": map_severity(alert.rule.level),
        "numerical_severity": alert.rule.level,
        "under_review": True,
        "active": True,
        "verified": True,
        "tags": tags,
        "found_by": [DEFAULT_FOUND_BY_TEST_TYPE_ID],
        "unique_id_from_tool": dedup_key
    }
    
    # DefectDojo uses reviewers as the assigned-user field.
    if assigned_user_id:
        finding_data["reviewers"] = [assigned_user_id]

    assign_note = f"Automated Routing: Mapped to group '{owner_group}'. Assigned to user '{assigned_user}'."
    endpoint_id = None
    endpoint_host = get_endpoint_host(alert)
    if endpoint_host:
        endpoint_id = dd_client.ensure_endpoint(endpoint_host, product_id)
    else:
        logger.warning("No usable endpoint host found for alert %s", alert.id)

    # 5. Push to DefectDojo
    try:
        dd_client.push_finding(
            finding_data,
            assign_note,
            existing_finding=existing_finding,
            endpoint_id=endpoint_id,
        )
        logger.info(f"Processed rule {alert.rule.id} -> DD Finding (Dedup: {dedup_key}) assigned to {assigned_user}")
    except Exception as e:
        logger.error(f"Failed to push finding to DefectDojo: {e}")

@app.post("/webhook")
async def wazuh_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    # Execute synchronously in background to release webhook instantly
    background_tasks.add_task(process_alert, payload)
    return {"status": "accepted"}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Wazuh to DefectDojo Admin</title>
  <style>
    :root {
      --bg: #f3efe7;
      --panel: #fffaf2;
      --ink: #1f2937;
      --muted: #6b7280;
      --accent: #0f766e;
      --border: #d6d3d1;
    }
    body { margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, #f7f3eb, #efe7da); color: var(--ink); }
    .shell { max-width: 1200px; margin: 0 auto; padding: 24px; }
    .hero { margin-bottom: 20px; }
    .hero h1 { margin: 0 0 8px; font-size: 36px; }
    .hero p { margin: 0; color: var(--muted); }
    .grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 20px; }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 18px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
    .card h2 { margin-top: 0; font-size: 22px; }
    label { display: block; font-size: 14px; margin-bottom: 6px; color: var(--muted); }
    input, textarea, select { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); font: inherit; background: white; }
    textarea { min-height: 120px; resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
    .stack { display: grid; gap: 12px; }
    .actions { display: flex; gap: 10px; margin-top: 16px; }
    button { border: 0; border-radius: 999px; padding: 10px 16px; font: inherit; cursor: pointer; }
    .primary { background: var(--accent); color: white; }
    .ghost { background: #e7e5e4; color: var(--ink); }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 13px; }
    .status { margin-top: 12px; font-size: 14px; color: var(--muted); min-height: 20px; }
    .list { max-height: 700px; overflow: auto; background: white; border: 1px solid var(--border); border-radius: 12px; padding: 12px; }
    .list h3 { margin: 16px 0 8px; font-size: 16px; }
    .list h3:first-child { margin-top: 0; }
    .pill { display: inline-block; margin: 4px 6px 0 0; padding: 4px 8px; border-radius: 999px; background: #ecfeff; color: #155e75; font-size: 12px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .row { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <h1>Wazuh to DefectDojo Admin</h1>
      <p>Edit local integration config and compare it against live DefectDojo objects.</p>
    </div>
    <div class="grid">
      <section class="card">
        <h2>Config</h2>
        <div class="stack">
          <div class="row">
            <div><label>Product Type</label><input id="productTypeName" /></div>
            <div><label>Product Type Description</label><input id="productTypeDescription" /></div>
          </div>
          <div class="row">
            <div><label>Product</label><input id="productName" /></div>
            <div><label>Product Description</label><input id="productDescription" /></div>
          </div>
          <div class="row">
            <div><label>Engagement</label><input id="engagementName" /></div>
            <div><label>Engagement Status</label><input id="engagementStatus" /></div>
          </div>
          <div class="row">
            <div><label>Engagement Start</label><input id="engagementStart" /></div>
            <div><label>Engagement End</label><input id="engagementEnd" /></div>
          </div>
          <div class="row">
            <div><label>Test Title Prefix</label><input id="testTitlePrefix" /></div>
            <div><label>Test Type ID</label><input id="testTypeId" type="number" /></div>
          </div>
          <div class="row">
            <div><label>Default Test Category</label><input id="defaultTest" /></div>
            <div><label>Tag to Test Mapping (JSON)</label><textarea id="tagToTest"></textarea></div>
          </div>
          <div>
            <label>Teams (JSON)</label>
            <textarea id="teams"></textarea>
          </div>
          <div>
            <label>Routing Rules (JSON)</label>
            <textarea id="routingRules"></textarea>
          </div>
          <div>
            <label>Tag Rules (JSON)</label>
            <textarea id="tagRules"></textarea>
          </div>
        </div>
        <div class="actions">
          <button class="primary" onclick="saveConfig()">Save Config</button>
          <button class="ghost" onclick="loadAll()">Reload</button>
        </div>
        <div class="status" id="status"></div>
      </section>
      <aside class="card">
        <h2>Live DefectDojo Lists</h2>
        <div class="list" id="dojoLists">Loading...</div>
      </aside>
    </div>
  </div>
  <script>
    function pretty(value) {
      return JSON.stringify(value, null, 2);
    }
    async function loadConfig() {
      const res = await fetch('/admin/api/config');
      const cfg = await res.json();
      productTypeName.value = cfg.defectdojo.product_type.name;
      productTypeDescription.value = cfg.defectdojo.product_type.description || '';
      productName.value = cfg.defectdojo.product.name;
      productDescription.value = cfg.defectdojo.product.description || '';
      engagementName.value = cfg.defectdojo.engagement.name;
      engagementStatus.value = cfg.defectdojo.engagement.status;
      engagementStart.value = cfg.defectdojo.engagement.target_start;
      engagementEnd.value = cfg.defectdojo.engagement.target_end;
      testTitlePrefix.value = cfg.defectdojo.test.title_prefix;
      testTypeId.value = cfg.defectdojo.test.test_type_id;
      defaultTest.value = cfg.categories.default_test;
      tagToTest.value = pretty(cfg.categories.tag_to_test || {});
      teams.value = pretty(cfg.teams || {});
      routingRules.value = pretty(cfg.routing_rules || []);
      tagRules.value = pretty(cfg.tag_rules || []);
    }
    function renderList(title, items, labelKey='name') {
      const lines = [`<h3>${title}</h3>`];
      if (!items.length) {
        lines.push('<div class="pill">None</div>');
        return lines.join('');
      }
      for (const item of items) {
        const label = item[labelKey] || item.name || item.username || item.id;
        lines.push(`<div class="pill">${label}</div>`);
      }
      return lines.join('');
    }
    async function loadDojo() {
      const res = await fetch('/admin/api/dojo-options');
      const data = await res.json();
      dojoLists.innerHTML = [
        renderList('Product Types', data.product_types || []),
        renderList('Products', data.products || []),
        renderList('Engagements', data.engagements || []),
        renderList('Tests', data.tests || []),
        renderList('Users', data.users || [], 'username')
      ].join('');
    }
    async function loadAll() {
      status.textContent = 'Loading...';
      try {
        await Promise.all([loadConfig(), loadDojo()]);
        status.textContent = 'Config and live lists loaded.';
      } catch (err) {
        status.textContent = 'Failed to load admin data: ' + err;
      }
    }
    async function saveConfig() {
      status.textContent = 'Saving...';
      try {
        const payload = {
          defectdojo: {
            product_type: { name: productTypeName.value, description: productTypeDescription.value },
            product: { name: productName.value, description: productDescription.value },
            engagement: {
              name: engagementName.value,
              status: engagementStatus.value,
              target_start: engagementStart.value,
              target_end: engagementEnd.value
            },
            test: {
              title_prefix: testTitlePrefix.value,
              test_type_id: Number(testTypeId.value),
              target_start: engagementStart.value,
              target_end: engagementEnd.value
            }
          },
          categories: {
            default_test: defaultTest.value,
            tag_to_test: JSON.parse(tagToTest.value || '{}')
          },
          teams: JSON.parse(teams.value || '{}'),
          routing_rules: JSON.parse(routingRules.value || '[]'),
          tag_rules: JSON.parse(tagRules.value || '[]'),
          default_owner_group: Object.keys(JSON.parse(teams.value || '{}'))[0] || 'SecOps'
        };
        const res = await fetch('/admin/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || JSON.stringify(data));
        status.textContent = 'Config saved.';
      } catch (err) {
        status.textContent = 'Save failed: ' + err;
      }
    }
    loadAll();
  </script>
</body>
</html>
"""


@app.get("/admin/api/config")
async def admin_get_config():
    return JSONResponse(config.model_dump(mode="json"))


@app.post("/admin/api/config")
async def admin_save_config(request: Request):
    payload = await request.json()
    try:
        new_config = AppConfig(**payload)
        save_config(new_config)
        reload_runtime_config(new_config)
        return JSONResponse({"status": "saved"})
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)


@app.get("/admin/api/dojo-options")
async def admin_dojo_options():
    try:
        return JSONResponse(dd_client.get_admin_options())
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=502)
