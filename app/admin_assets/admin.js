const state = {
  config: null,
  options: null,
  wizard: {
    step: 0,
    data: {},
  },
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
  wizardForm: document.getElementById("wizardForm"),
  wizardTitle: document.getElementById("wizardTitle"),
  wizardFields: document.getElementById("wizardFields"),
  wizardBack: document.getElementById("wizardBack"),
  wizardNext: document.getElementById("wizardNext"),
  wizardFinish: document.getElementById("wizardFinish"),
  wizardSteps: Array.from(document.querySelectorAll(".wizard-step")),
};

const wizardSchemas = [
  {
    key: "product-type",
    title: "Step 1: Product Type",
    nextLabel: "Next: Product",
    fields: [
      { name: "name", label: "Product Type Name", placeholder: "Wazuh", required: true },
      { name: "description", label: "Product Type Description", placeholder: "Security Operations" },
    ],
  },
  {
    key: "product",
    title: "Step 2: Product",
    nextLabel: "Next: Engagement",
    fields: [
      { name: "name", label: "Product Name", placeholder: "Wazuh Endpoint Security", required: true },
      { name: "description", label: "Product Description", placeholder: "Continuous endpoint monitoring", required: true },
    ],
  },
  {
    key: "engagement",
    title: "Step 3: Engagement",
    nextLabel: "Next: Test",
    fields: [
      { name: "name", label: "Engagement Name", placeholder: "Continuous Monitoring", required: true },
      { name: "status", label: "Engagement Status", placeholder: "In Progress", required: true },
      { name: "target_start", label: "Target Start", placeholder: "2026-03-19", required: true },
      { name: "target_end", label: "Target End", placeholder: "2027-03-19", required: true },
    ],
  },
  {
    key: "test",
    title: "Step 4: Test",
    finishLabel: "Create Path",
    fields: [
      { name: "title", label: "Test Title", placeholder: "Wazuh Alerts - Threat Hunting", required: true },
      { name: "test_type", label: "Test Type ID", type: "number", placeholder: "1", required: true },
      { name: "target_start", label: "Test Start", placeholder: "2026-03-19T00:00:00Z", required: true },
      { name: "target_end", label: "Test End", placeholder: "2027-03-19T00:00:00Z", required: true },
    ],
  },
];

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

function wizardDefaults() {
  return {
    "product-type": {
      name: els.productTypeSelect.value || state.config?.defectdojo?.product_type?.name || "",
      description: els.productTypeDescription.value || state.config?.defectdojo?.product_type?.description || "",
    },
    product: {
      name: els.productSelect.value || state.config?.defectdojo?.product?.name || "",
      description: els.productDescription.value || state.config?.defectdojo?.product?.description || "",
    },
    engagement: {
      name: els.engagementSelect.value || state.config?.defectdojo?.engagement?.name || "",
      status: els.engagementStatus.value || state.config?.defectdojo?.engagement?.status || "In Progress",
      target_start: els.engagementStart.value || state.config?.defectdojo?.engagement?.target_start || "",
      target_end: els.engagementEnd.value || state.config?.defectdojo?.engagement?.target_end || "",
    },
    test: {
      title: `${els.testTitlePrefix.value || state.config?.defectdojo?.test?.title_prefix || "Wazuh Alerts"} - ${els.threatHuntingTest.value || "Threat Hunting"}`,
      test_type: String(els.testTypeId.value || state.config?.defectdojo?.test?.test_type_id || 1),
      target_start: state.config?.defectdojo?.test?.target_start || "",
      target_end: state.config?.defectdojo?.test?.target_end || "",
    },
  };
}

function resetWizard() {
  state.wizard.step = 0;
  state.wizard.data = wizardDefaults();
  renderWizard();
}

function renderWizard() {
  const schema = wizardSchemas[state.wizard.step];
  const stepData = state.wizard.data[schema.key] || {};

  els.wizardTitle.textContent = schema.title;
  els.wizardFields.innerHTML = schema.fields.map((field) => {
    const type = field.type || "text";
    const required = field.required ? "required" : "";
    const value = stepData[field.name] ?? "";
    return `
      <label class="field">
        <span>${field.label}</span>
        <input
          name="${field.name}"
          type="${type}"
          placeholder="${field.placeholder || ""}"
          value="${String(value).replace(/"/g, "&quot;")}"
          ${required}
        />
      </label>
    `;
  }).join("");

  els.wizardSteps.forEach((stepEl, index) => {
    stepEl.classList.toggle("active", index === state.wizard.step);
    stepEl.classList.toggle("complete", index < state.wizard.step);
  });

  els.wizardBack.hidden = state.wizard.step === 0;
  els.wizardNext.hidden = state.wizard.step === wizardSchemas.length - 1;
  els.wizardFinish.hidden = state.wizard.step !== wizardSchemas.length - 1;
  els.wizardNext.textContent = schema.nextLabel || "Next";
  els.wizardFinish.textContent = schema.finishLabel || "Create Path";
}

function persistWizardStep() {
  const schema = wizardSchemas[state.wizard.step];
  const inputs = Array.from(els.wizardFields.querySelectorAll("input"));
  const invalid = inputs.find((input) => !input.checkValidity());
  if (invalid) {
    invalid.reportValidity();
    return false;
  }

  const formData = Object.fromEntries(new FormData(els.wizardForm).entries());
  state.wizard.data[schema.key] = {
    ...(state.wizard.data[schema.key] || {}),
    ...formData,
  };
  return true;
}

function normalizeObjectPayload(objectType, payload) {
  const normalized = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value === "") continue;
    if (["prod_type", "product", "engagement", "test_type"].includes(key)) {
      normalized[key] = Number(value);
    } else {
      normalized[key] = value;
    }
  }

  if (objectType === "product-type") {
    delete normalized.prod_type;
  }

  return normalized;
}

function moveWizard(direction) {
  if (!persistWizardStep()) return;
  const nextStep = state.wizard.step + direction;
  if (nextStep < 0 || nextStep >= wizardSchemas.length) return;
  state.wizard.step = nextStep;
  renderWizard();
}

function updateDestinationPathFromCreated(created) {
  const { productType, product, engagement, test } = created;
  if (productType?.name) {
    els.productTypeDescription.value = productType.description || "";
  }
  if (product?.name) {
    els.productDescription.value = product.description || "";
  }
  if (engagement?.name) {
    els.engagementStatus.value = engagement.status || "";
    els.engagementStart.value = engagement.target_start || "";
    els.engagementEnd.value = engagement.target_end || "";
  }
  if (test?.test_type) {
    els.testTypeId.value = test.test_type;
  }

  state.config.defectdojo.product_type.name = productType?.name || state.config.defectdojo.product_type.name;
  state.config.defectdojo.product_type.description = productType?.description || state.config.defectdojo.product_type.description;
  state.config.defectdojo.product.name = product?.name || state.config.defectdojo.product.name;
  state.config.defectdojo.product.description = product?.description || state.config.defectdojo.product.description;
  state.config.defectdojo.engagement.name = engagement?.name || state.config.defectdojo.engagement.name;
  state.config.defectdojo.engagement.status = engagement?.status || state.config.defectdojo.engagement.status;
  state.config.defectdojo.engagement.target_start = engagement?.target_start || state.config.defectdojo.engagement.target_start;
  state.config.defectdojo.engagement.target_end = engagement?.target_end || state.config.defectdojo.engagement.target_end;
  state.config.defectdojo.test.test_type_id = Number(test?.test_type || state.config.defectdojo.test.test_type_id);

  populateSelect(els.productTypeSelect, state.options.product_types || [], state.config.defectdojo.product_type.name);
  populateSelect(els.productSelect, state.options.products || [], state.config.defectdojo.product.name);
  populateSelect(els.engagementSelect, state.options.engagements || [], state.config.defectdojo.engagement.name);
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
    resetWizard();
    setStatus("Config and live DefectDojo lists loaded.");
  } catch (error) {
    setStatus(`Failed to load admin data: ${error}`, true);
  }
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

async function createWizardPath(event) {
  event.preventDefault();
  if (!persistWizardStep()) return;

  const wizardData = state.wizard.data;
  const productTypePayload = normalizeObjectPayload("product-type", wizardData["product-type"] || {});
  const productPayload = normalizeObjectPayload("product", wizardData.product || {});
  const engagementPayload = normalizeObjectPayload("engagement", wizardData.engagement || {});
  const testPayload = normalizeObjectPayload("test", wizardData.test || {});

  try {
    setStatus("Creating Product Type -> Product -> Engagement -> Test...");
    const productType = await fetchJson("/admin/api/dojo/product-type", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(productTypePayload),
    });
    const product = await fetchJson("/admin/api/dojo/product", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...productPayload,
        prod_type: productType.id,
      }),
    });
    const engagement = await fetchJson("/admin/api/dojo/engagement", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...engagementPayload,
        product: product.id,
      }),
    });
    const test = await fetchJson("/admin/api/dojo/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...testPayload,
        engagement: engagement.id,
      }),
    });

    await loadAll();
    updateDestinationPathFromCreated({ productType, product, engagement, test });
    resetWizard();
    setStatus("Path created. Save Config if you want alerts to route to this new destination.");
  } catch (error) {
    setStatus(`Create path failed: ${error}`, true);
  }
}

els.wizardForm.addEventListener("submit", createWizardPath);
els.wizardBack.addEventListener("click", () => moveWizard(-1));
els.wizardNext.addEventListener("click", () => moveWizard(1));
els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.productTypeSelect.addEventListener("change", syncSelectedObjectDetails);
els.productSelect.addEventListener("change", syncSelectedObjectDetails);
els.engagementSelect.addEventListener("change", syncSelectedObjectDetails);

loadAll();
