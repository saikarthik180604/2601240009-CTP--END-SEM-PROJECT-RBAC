/* RBAC Manager front-end: plain JavaScript, no frameworks.
   - forms with data-api   -> POST JSON to the API
   - forms with data-get   -> GET request (results shown in a result box)
   - buttons with data-post -> POST the JSON in data-payload
   - hierarchy page        -> draws the role graph as nested lists */

// ---------------------------------------------------------------- helpers
function toast(message, kind) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = "toast show " + (kind || "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.className = "toast"; }, 3500);
}

async function api(url, method, payload) {
  const options = { method: method || "GET", headers: {} };
  if (payload !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  try {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { error: "Network error: " + err.message } };
  }
}

function collectForm(form) {
  const data = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.tagName === "SELECT" && el.multiple) {
      data[el.name] = Array.from(el.selectedOptions).map(o => o.value);
    } else if (el.name.endsWith("_id") && el.value !== "") {
      data[el.name] = Number(el.value);
    } else {
      data[el.name] = el.value;
    }
  }
  return data;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function reloadSoon() { setTimeout(() => window.location.reload(), 650); }

// -------------------------------------------------------- result renderers
function renderCheck(box, data) {
  box.replaceChildren();
  const badge = el("span", "badge " + (data.result === "ALLOW" ? "allow" : "deny"), data.result);
  badge.classList.add("big");
  box.append(badge, el("span", "", data.reason));
  box.append(el("div", "muted", `${data.username} | ${data.tenant} | ${data.permission}`));
}

function renderEffective(box, data) {
  box.replaceChildren();
  box.append(el("strong", "", `${data.user} in ${data.tenant}`));
  box.append(el("div", "muted", "Assigned roles: " + (data.assigned_roles.join(", ") || "none")));
  const list = el("ul");
  data.allowed.forEach(item => {
    const li = el("li");
    li.append(el("code", "perm", item.permission));
    li.append(document.createTextNode(" from " + item.source_role + (item.inherited ? " (inherited)" : "")));
    list.append(li);
  });
  if (!data.allowed.length) list.append(el("li", "muted", "No allowed permissions"));
  box.append(list);
  if (data.denied.length) {
    box.append(el("div", "", "Explicitly denied:"));
    const denied = el("ul");
    data.denied.forEach(p => { const li = el("li"); li.append(el("code", "perm", p)); denied.append(li); });
    box.append(denied);
  }
}

const renderers = { check: renderCheck, effective: renderEffective };

function showResult(form, response) {
  const box = document.getElementById(form.dataset.result);
  if (!box) return;
  box.hidden = false;
  box.classList.toggle("error", !response.ok);
  if (!response.ok) { box.textContent = response.data.error || "Request failed"; return; }
  renderers[form.dataset.render](box, response.data);
}

// -------------------------------------------------------- form + button hooks
document.querySelectorAll("form[data-api]").forEach(form => {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const response = await api(form.dataset.api, "POST", collectForm(form));
    if (form.dataset.result) showResult(form, response);
    if (!response.ok) { toast(response.data.error || "Request failed", "error"); return; }
    if (form.dataset.noReload === undefined) { toast("Saved", "success"); reloadSoon(); }
    else { toast("Done", "success"); }
  });
});

document.querySelectorAll("form[data-get]").forEach(form => {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const query = new URLSearchParams(collectForm(form)).toString();
    const response = await api(form.dataset.get + "?" + query, "GET");
    showResult(form, response);
    if (!response.ok) toast(response.data.error || "Request failed", "error");
  });
});

document.querySelectorAll("[data-post]").forEach(button => {
  button.addEventListener("click", async () => {
    const response = await api(button.dataset.post, "POST", JSON.parse(button.dataset.payload));
    if (!response.ok) { toast(response.data.error || "Request failed", "error"); return; }
    toast("Updated", "success");
    reloadSoon();
  });
});

// ------------------------------------------------------- audit log filter
document.querySelectorAll("[data-filter]").forEach(button => {
  button.addEventListener("click", () => {
    const wanted = button.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach(b => b.classList.toggle("active", b === button));
    document.querySelectorAll("#audit-table tbody tr[data-result]").forEach(row => {
      row.hidden = wanted !== "ALL" && row.dataset.result !== wanted;
    });
  });
});

// ------------------------------------------------------ hierarchy page
const tenantSelect = document.getElementById("tenant-select");

// Build nested <ul> lists. A role is drawn above the roles it inherits from.
function buildTree(roleIds, nodes, path) {
  const ul = el("ul");
  roleIds.forEach(id => {
    const node = nodes[id];
    const li = el("li");
    const box = el("div", "node" + (node.parents.length === 0 ? " base" : ""));
    box.append(el("strong", "", node.role_name));
    box.append(el("small", "", node.permissions.length + " direct permissions"));
    box.title = node.permissions.length
      ? "Own permissions: " + node.permissions.join(", ")
      : "No direct permissions";
    li.append(box);
    const next = node.parents.filter(p => !path.includes(p));   // cycle guard
    if (next.length) li.append(buildTree(next, nodes, path.concat(id)));
    ul.append(li);
  });
  return ul;
}

async function loadHierarchy() {
  const container = document.getElementById("hierarchy-tree");
  const response = await api("/api/hierarchy?tenant_id=" + tenantSelect.value);
  container.replaceChildren();
  if (!response.ok) { container.append(el("p", "empty", response.data.error || "Could not load hierarchy")); return; }

  const { nodes: nodeList, edges } = response.data;
  const nodes = {};
  nodeList.forEach(n => { nodes[n.role_id] = n; });

  // Top of the picture = roles that nobody inherits from (the most senior roles).
  const tops = nodeList.filter(n => n.children.length === 0).map(n => n.role_id);
  if (tops.length) container.append(buildTree(tops, nodes, []));
  else container.append(el("p", "empty", "This tenant has no roles yet."));

  // Edge list with remove buttons.
  const edgeBox = document.getElementById("edge-list");
  edgeBox.replaceChildren();
  edges.forEach(edge => {
    const row = el("div", "edge-row");
    row.append(el("span", "", `${edge.child_name} inherits from ${edge.parent_name}`));
    const remove = el("button", "btn btn-sm btn-danger", "Remove");
    remove.addEventListener("click", async () => {
      const result = await api("/api/hierarchy/remove", "POST",
        { child_role_id: edge.child_id, parent_role_id: edge.parent_id });
      if (!result.ok) { toast(result.data.error || "Request failed", "error"); return; }
      toast("Link removed", "success");
      loadHierarchy();
    });
    row.append(remove);
    edgeBox.append(row);
  });
  if (!edges.length) edgeBox.append(el("p", "empty", "No inheritance links yet."));

  // Fill the "add inheritance" selects with this tenant's roles.
  ["child-select", "parent-select"].forEach((id, index) => {
    const select = document.getElementById(id);
    select.replaceChildren();
    nodeList.forEach(n => select.append(new Option(n.role_name, n.role_id)));
    if (index === 1 && nodeList.length > 1) select.selectedIndex = 1;
  });
}

if (tenantSelect) {
  tenantSelect.addEventListener("change", loadHierarchy);
  loadHierarchy();
}
