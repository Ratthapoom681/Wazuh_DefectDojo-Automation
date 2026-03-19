const state = {
  config: null,
  options: null,
};

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  productTypeSelect: document.getElementById("productTypeSelect"),
  productTypeDescription: document.getElementById("productTypeDescription"),
  productSelect: document.getElementById("productSelect"),
  productDescription: document.getElementById("productDescription"),
  engagementSelect: document.getElementById("engagementSelect"),
  engagementStatus: document.getElementById("engagementStatus"),
  engagementStart: document.getElementById("engagementStart"),
  engagementEnd: document.getElementById("engagementEnd"),
  testTitlePrefix: document.getElementById("testTitlePrefix"),
  testTypeId: document.getElementById("testTypeId"),
  threatHuntingTest: document.getElementById("threatHuntingTest"),
  vulnerabilityTest: document.getElementById("vulnerabilityTest"),
  defaultTest: document.getElementById("defaultTest"),
  teams: document.getElementById("teams"),
  routingRules: document.getElementById("routingRules"),
  tagRules: document.getElementById("tagRules"),
  inventory: document.getElementById("inventory"),
};

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}

function populateSelect(select, items, currentValue, labelKey = "name") {
  select.innerHTML = "";
  const values = new Set();
  for (const item of items) {
    const value = item[labelKey] || item.name || item.username || item.id;
    if (value == null || values.has(String(value))) continue;
    values.add(String(value));
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = String(value);
    if (String(value) === String(currentValue)) option.selected = true;
    select.appendChild(option);
  }
  if (!values.has(String(currentValue)) && currentValue) {
    const option = document.createElement("option");
    option.value = String(currentValue);
    option.textContent = String(currentValue);
    option.selected = true;
    select.appendChild(option);
  }
}

function renderPills(items, labelKey = "name") {
  if (!items?.length) return '<span class="pill">None</span>';
  return items.map((item) => {
    const label = item[labelKey] || item.name || item.username || item.id;
    return `<span class="pill">${label}</span>`;
  }).join("");
}

function renderInventory(options) {
  els.inventory.innerHTML = [
    ["Product Types", options.product_types],
    ["Products", options.products],
    ["Engagements", options.engagements],
    ["Tests", options.tests],
    ["Users", options.users, "username"],
  ].map(([title, items, labelKey]) => `
    <section class="inventory-group">
      <h3>${title}</h3>
      <div class="pills">${renderPills(items, labelKey)}</div>
    </section>
  `).join("");
}

function applyConfig() {
  const cfg = state.config;
  const options = state.options;
  populateSelect(els.productTypeSelect, options.product_types || [], cfg.defectdojo.product_type.name);
  populateSelect(els.productSelect, options.products || [], cfg.defectdojo.product.name);
  populateSelect(els.engagementSelect, options.engagements || [], cfg.defectdojo.engagement.name);

  els.productTypeDescription.value = cfg.defectdojo.product_type.description || "";
  els.productDescription.value = cfg.defectdojo.product.description || "";
  els.engagementStatus.value = cfg.defectdojo.engagement.status || "";
  els.engagementStart.value = cfg.defectdojo.engagement.target_start || "";
  els.engagementEnd.value = cfg.defectdojo.engagement.target_end || "";
  els.testTitlePrefix.value = cfg.defectdojo.test.title_prefix || "";
  els.testTypeId.value = cfg.defectdojo.test.test_type_id || 1;
  els.threatHuntingTest.value = cfg.categories.tag_to_test?.["threat-hunting"] || "Threat Hunting";
  els.vulnerabilityTest.value = cfg.categories.tag_to_test?.["vulnerability-detector"] || "Vulnerability Detector";
  els.defaultTest.value = cfg.categories.default_test || "General Monitoring";
  els.teams.value = pretty(cfg.teams || {});
  els.routingRules.value = pretty(cfg.routing_rules || []);
  els.tagRules.value = pretty(cfg.tag_rules || []);
  renderInventory(options);
}

function syncSelectedObjectDetails() {
  const productType = state.options.product_types?.find((item) => item.name === els.productTypeSelect.value);
  const product = state.options.products?.find((item) => item.name === els.productSelect.value);
  const engagement = state.options.engagements?.find((item) => item.name === els.engagementSelect.value);

  if (productType) {
    els.productTypeDescription.value = productType.description || "";
  }
  if (product) {
    els.productDescription.value = product.description || "";
  }
  if (engagement) {
    els.engagementStatus.value = engagement.status || "";
    els.engagementStart.value = engagement.target_start || "";
    els.engagementEnd.value = engagement.target_end || "";
  }
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || JSON.stringify(data));
  }
  return data;
}

async function loadAll() {
  setStatus("Loading...");
  try {
    const [config, options] = await Promise.all([
      fetchJson("/admin/api/config"),
      fetchJson("/admin/api/dojo-options"),
    ]);
    state.config = config;
    state.options = options;
    applyConfig();
    syncSelectedObjectDetails();
    hydrateCreateForms();
    setStatus("Config and live DefectDojo lists loaded.");
  } catch (error) {
    setStatus(`Failed to load admin data: ${error}`, true);
  }
}

function hydrateCreateForms() {
  const productTypeId = state.options.product_types?.find((item) => item.name === els.productTypeSelect.value)?.id;
  const productId = state.options.products?.find((item) => item.name === els.productSelect.value)?.id;
  const engagementId = state.options.engagements?.find((item) => item.name === els.engagementSelect.value)?.id;

  document.querySelector('form[data-object-type="product"] input[name="prod_type"]').value = productTypeId || "";
  document.querySelector('form[data-object-type="engagement"] input[name="product"]').value = productId || "";
  document.querySelector('form[data-object-type="test"] input[name="engagement"]').value = engagementId || "";
  document.querySelector('form[data-object-type="test"] input[name="test_type"]').value = els.testTypeId.value || 1;
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const currentTeams = JSON.parse(els.teams.value || "{}");
    const payload = {
      defectdojo: {
        product_type: {
          name: els.productTypeSelect.value,
          description: els.productTypeDescription.value,
        },
        product: {
          name: els.productSelect.value,
          description: els.productDescription.value,
        },
        engagement: {
          name: els.engagementSelect.value,
          status: els.engagementStatus.value,
          target_start: els.engagementStart.value,
          target_end: els.engagementEnd.value,
        },
        test: {
          title_prefix: els.testTitlePrefix.value,
          test_type_id: Number(els.testTypeId.value),
          target_start: els.engagementStart.value,
          target_end: els.engagementEnd.value,
        },
      },
      categories: {
        tag_to_test: {
          "threat-hunting": els.threatHuntingTest.value,
          "vulnerability-detector": els.vulnerabilityTest.value,
        },
        default_test: els.defaultTest.value,
      },
      teams: currentTeams,
      routing_rules: JSON.parse(els.routingRules.value || "[]"),
      tag_rules: JSON.parse(els.tagRules.value || "[]"),
      default_owner_group: state.config.default_owner_group || Object.keys(currentTeams)[0] || "SecOps",
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

function normalizeFormPayload(form) {
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {};
  for (const [key, value] of Object.entries(raw)) {
    if (value === "") continue;
    if (["prod_type", "product", "engagement", "test_type"].includes(key)) {
      payload[key] = Number(value);
    } else {
      payload[key] = value;
    }
  }
  return payload;
}

async function handleCreateForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const objectType = form.dataset.objectType;
  try {
    setStatus(`Creating ${objectType}...`);
    const payload = normalizeFormPayload(form);
    await fetchJson(`/admin/api/dojo/${objectType}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    form.reset();
    setStatus(`Created ${objectType}.`);
    await loadAll();
  } catch (error) {
    setStatus(`Create failed: ${error}`, true);
  }
}

document.querySelectorAll(".create-card").forEach((form) => {
  form.addEventListener("submit", handleCreateForm);
});

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.productTypeSelect.addEventListener("change", () => { syncSelectedObjectDetails(); hydrateCreateForms(); });
els.productSelect.addEventListener("change", () => { syncSelectedObjectDetails(); hydrateCreateForms(); });
els.engagementSelect.addEventListener("change", () => { syncSelectedObjectDetails(); hydrateCreateForms(); });
els.testTypeId.addEventListener("change", hydrateCreateForms);

loadAll();
