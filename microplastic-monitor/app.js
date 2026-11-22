"use strict";

// Point this at the QuantLite API origin. Never put credentials or secrets here.
const API_BASE_URL = "http://localhost:8000";
const SESSION_COOKIE = "quantlite_session";
const CSRF_COOKIE = "quantlite_csrf";
const routeTitles = {
  overview: "My Dashboard", "image-analysis": "New Image Analysis", "live-analysis": "Live Analysis",
  map: "Monitoring Map", analytics: "My Analytics", reports: "My Reports", tests: "My Test History",
  profile: "My Profile", settings: "Settings", "admin-command": "Command Center",
  "admin-customers": "Customer Management", "admin-tests": "Test Records", "admin-regions": "Regional Intelligence",
  "admin-analytics": "Analytics", "admin-reports": "Reports", "admin-profile": "Founder Profile", "admin-settings": "Settings"
};
const customerNav = [
  ["overview", "◫", "My Dashboard"], ["image-analysis", "▧", "New Image Analysis"], ["live-analysis", "◎", "Live Analysis"],
  ["tests", "▦", "My Test History"], ["reports", "▤", "My Reports"], ["analytics", "▥", "My Analytics"],
  ["map", "⌖", "Monitoring Map"], ["profile", "◉", "My Profile"], ["settings", "⚙", "Settings"]
];
const adminNav = [
  ["admin-command", "◫", "Command Center"], ["admin-customers", "♙", "Customer Management"], ["admin-tests", "▦", "Test Records"],
  ["admin-regions", "⌖", "Regional Intelligence"], ["map", "⌖", "Monitoring Map"], ["admin-analytics", "▥", "Analytics"],
  ["admin-reports", "▤", "Reports"], ["admin-profile", "◉", "Founder Profile"], ["admin-settings", "⚙", "Settings"]
];

const authShell = document.getElementById("auth-shell");
const workspaceShell = document.getElementById("workspace-shell");
const authCards = [...document.querySelectorAll(".auth-card")];
const views = [...document.querySelectorAll("[data-view]")];
const navList = document.querySelector(".nav-list");
const sidebar = document.querySelector(".sidebar");
const menuToggle = document.getElementById("menu-toggle");
let sessionUser = null;
let csrfToken = "";
let selectedPortal = "CUSTOMER";
let currentCustomerOffset = 0;
let currentTestOffset = 0;
let toastTimer;
let leafletMap = null;
let leafletMarkers = null;

function readCookie(name) {
  const cookie = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
}

function safeText(value, fallback = "—") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function dateText(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

function toast(message, bad = false) {
  let node = document.getElementById("toast");
  if (!node) {
    node = document.createElement("div"); node.id = "toast"; node.className = "toast"; node.setAttribute("role", "status"); node.setAttribute("aria-live", "polite"); document.body.append(node);
  }
  node.textContent = message; node.classList.toggle("toast-error", bad); node.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => node.classList.remove("show"), 3800);
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (["POST", "PATCH", "DELETE"].includes(method) && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { ...options, method, headers, credentials: "include" });
  } catch {
    throw new Error("Could not reach the QuantLite API. Check that the backend is running.");
  }
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    let message = typeof data === "object" && data ? (data.detail || data.message || `Request failed (${response.status}).`) : `Request failed (${response.status}).`;
    if (Array.isArray(message)) message = message.map((issue) => `${Array.isArray(issue.loc) ? issue.loc.slice(-1)[0] : "Field"}: ${issue.msg || "Invalid value"}`).join("; ");
    if (response.status === 401 && sessionUser) await showSignedOut("Your session expired. Please sign in again.");
    throw new Error(message);
  }
  return data;
}

function setAuthCard(name) {
  authCards.forEach((card) => { card.hidden = card.id !== `auth-${name}`; });
  authShell.hidden = false; workspaceShell.hidden = true; sidebar.classList.remove("open");
  const focus = document.querySelector(`#auth-${name} input:not([type=checkbox]), #auth-${name} button:not([disabled])`);
  focus?.focus({ preventScroll: true });
}

function renderNavigation(role) {
  const items = role === "ADMIN" ? adminNav : customerNav;
  document.getElementById("nav-heading").textContent = role === "ADMIN" ? "FOUNDER PORTAL" : "CUSTOMER WORKSPACE";
  navList.replaceChildren(...items.map(([route, icon, title]) => {
    const link = document.createElement("a"); link.href = `#${route}`; link.className = "nav-link"; link.dataset.route = route;
    const mark = document.createElement("span"); mark.className = "nav-icon"; mark.textContent = icon;
    link.append(mark, document.createTextNode(title)); return link;
  }));
}

function renderRoute() {
  if (!sessionUser) return;
  const role = sessionUser.role;
  let route = location.hash.slice(1).split("?")[0];
  if (role === "ADMIN" && !route.startsWith("admin-") && route !== "map") route = "admin-command";
  if (role === "CUSTOMER" && route.startsWith("admin-")) route = "overview";
  if (!Object.hasOwn(routeTitles, route)) route = role === "ADMIN" ? "admin-command" : "overview";
  if (location.hash !== `#${route}`) history.replaceState(null, "", `#${route}`);
  views.forEach((view) => { view.hidden = view.dataset.view !== route; });
  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = link.dataset.route === route; link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  document.getElementById("crumb").textContent = routeTitles[route];
  document.title = `${routeTitles[route]} — QuantLite`;
  sidebar.classList.remove("open"); menuToggle.setAttribute("aria-expanded", "false");
  loadRouteData(route).catch((error) => toast(error.message, true));
}

async function showSignedOut(message = "") {
  sessionUser = null; csrfToken = ""; document.body.removeAttribute("data-role"); workspaceShell.hidden = true; sidebar.classList.remove("open");
  document.getElementById("login-message").textContent = message;
  document.getElementById("login-message").classList.toggle("success", !message);
  setAuthCard("login");
  const token = readCookie(CSRF_COOKIE); if (token) csrfToken = token;
}

function markService(online, message = "API unavailable") {
  const label = document.getElementById("auth-status"); const dot = document.getElementById("auth-status-dot");
  label.textContent = online ? "Backend online" : message;
  dot.style.background = online ? "#48a98c" : "#d39a55";
  document.getElementById("retry-service-inline").hidden = online;
  document.getElementById("top-status").textContent = online ? "Backend online" : "Backend unavailable";
  document.getElementById("side-status").textContent = online ? "Backend online" : "Backend unavailable";
}

async function initialize(authLink = false) {
  document.querySelector(".offline-api").textContent = `API: ${API_BASE_URL}`;
  markService(false, "Checking backend");
  try {
    const health = await api("/api/health");
    if (health.status !== "ok") throw new Error("Backend health check did not return an online status.");
    markService(true);
    if (authLink) return;
    try {
      const data = await api("/api/auth/me");
      sessionUser = data.user; csrfToken = readCookie(CSRF_COOKIE); enterWorkspace();
    } catch (error) {
      if (error.message.includes("Could not reach")) throw error;
      setAuthCard("login");
    }
  } catch (error) {
    markService(false);
    document.getElementById("offline-message").textContent = error.message;
    setAuthCard("login");
    setMessage("login-message", "Backend unavailable. Start the QuantLite API on port 8000, then select Retry.");
  }
}

async function refreshBackendStatus() {
  try {
    const health = await api("/api/health");
    if (health.status !== "ok") throw new Error("Backend health check failed");
    markService(true);
  } catch {
    markService(false);
  }
}
setInterval(() => { if (!document.hidden) refreshBackendStatus(); }, 15000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshBackendStatus(); });

function enterWorkspace() {
  if (!sessionUser) return;
  document.body.dataset.role = sessionUser.role;
  csrfToken = csrfToken || readCookie(CSRF_COOKIE);
  authShell.hidden = true; workspaceShell.hidden = false; renderNavigation(sessionUser.role);
  const profile = sessionUser.profile || {};
  const userName = profile.full_name || sessionUser.email;
  document.getElementById("sidebar-user-name").textContent = userName;
  document.getElementById("top-user-name").textContent = userName;
  document.getElementById("top-avatar").textContent = initials(userName);
  if (sessionUser.role === "ADMIN") {
    document.getElementById("admin-profile-name").textContent = userName;
    document.getElementById("admin-profile-email").textContent = sessionUser.email;
    document.getElementById("admin-profile-avatar").textContent = initials(userName);
  }
  renderRoute();
}

function initials(name) { return String(name || "QL").trim().split(/\s+/).slice(0, 2).map((x) => x[0]?.toUpperCase() || "").join("") || "QL"; }

function cell(value, className = "") { const td = document.createElement("td"); td.textContent = safeText(value); if (className) td.className = className; return td; }
function statusCell(value) { const td = document.createElement("td"); const tag = document.createElement("span"); tag.className = `status-label ${(value || "").toLowerCase()}`; tag.textContent = safeText(value); td.append(tag); return td; }
function emptyRow(body, colspan, message) { const tr = document.createElement("tr"); const td = cell(message, "table-empty"); td.colSpan = colspan; tr.append(td); body.replaceChildren(tr); }
function setMessage(id, text, success = false) { const node = document.getElementById(id); node.textContent = text; node.classList.toggle("success", success); }
function formObject(form) { return Object.fromEntries(new FormData(form).entries()); }

async function loadRouteData(route) {
  if (sessionUser.role === "CUSTOMER") {
    if (route === "overview") await loadCustomerDashboard();
    if (route === "tests") await loadCustomerTests();
    if (route === "profile") await loadProfile();
    if (route === "analytics") await loadCustomerAnalytics();
    if (route === "reports") await loadCustomerReports();
    if (route === "map") await loadMonitoringMap();
  } else {
    if (route === "admin-command") await loadAdminDashboard();
    if (route === "admin-customers") await loadAdminCustomers();
    if (route === "admin-tests") await loadAdminTests();
    if (route === "admin-regions") await loadAdminRegions();
    if (route === "admin-analytics") await loadAdminAnalytics();
    if (route === "admin-settings") await loadServiceStatus();
    if (route === "admin-profile") await loadAdminProfile();
    if (route === "admin-reports") await loadAdminReports();
    if (route === "map") await loadMonitoringMap();
  }
}

async function loadCustomerDashboard() {
  const data = await api("/api/customer/dashboard"); const profile = data.profile || {};
  document.getElementById("welcome-name").textContent = profile.full_name || "Customer";
  document.getElementById("welcome-org").textContent = profile.organization || "Personal workspace";
  document.getElementById("welcome-customer-id").textContent = profile.customer_id || "—";
  document.getElementById("customer-kpi-total").textContent = data.counts.total;
  document.getElementById("customer-kpi-completed").textContent = data.counts.completed;
  document.getElementById("customer-kpi-pending").textContent = data.counts.pending;
  const overviewNote = document.querySelector('[data-view="overview"] .hero-note');
  if (overviewNote) overviewNote.textContent = `${data.counts.total} sample record${data.counts.total === 1 ? "" : "s"}`;
  const body = document.getElementById("customer-recent-body");
  if (!data.recent_tests.length) emptyRow(body, 5, "No test records have been created in your account.");
  else body.replaceChildren(...data.recent_tests.map((test) => {
    const row = document.createElement("tr"); row.append(cell(test.id), cell(test.sample_reference), cell(test.sample_type), cell(dateText(test.created_at)), statusCell(test.status)); return row;
  }));
  const reportBody = document.getElementById("customer-dashboard-reports");
  if (!data.reports.length) emptyRow(reportBody, 4, "No report files have been generated for your account.");
  else reportBody.replaceChildren(...data.reports.map((report) => { const row = document.createElement("tr"); row.append(cell(report.id), cell(report.test_id), cell(dateText(report.created_at)), statusCell(report.status)); return row; }));
}

async function loadCustomerTests() {
  const data = await api(`/api/customer/tests?limit=50&offset=0`); const body = document.getElementById("customer-tests-body");
  document.getElementById("customer-test-total").textContent = `${data.total} RECORDS`;
  if (!data.items.length) return emptyRow(body, 5, "No test records belong to your account yet.");
  body.replaceChildren(...data.items.map((test) => {
    const row = document.createElement("tr");
    const idCell = document.createElement("td"); idCell.append(detailButton(test.id, () => showCustomerTest(test.id)));
    row.append(idCell, cell(test.sample_reference), cell(dateText(test.collected_at || test.created_at)), cell([test.city, test.region, test.state].filter(Boolean).join(", ")), statusCell(test.status));
    return row;
  }));
}

async function loadProfile() {
  const data = await api("/api/customer/profile"); const user = data; const profile = user.profile || {}; const form = document.getElementById("profile-form");
  for (const [key, value] of Object.entries({ ...profile, email: user.email })) { const input = form.elements.namedItem(key); if (input) input.value = value || ""; }
  document.getElementById("profile-display-name").textContent = profile.full_name || "Customer profile";
  document.getElementById("profile-customer-id").textContent = profile.customer_id || "Customer ID unavailable";
  document.getElementById("profile-avatar").textContent = initials(profile.full_name);
  document.getElementById("profile-verified").textContent = user.email_verified ? "EMAIL VERIFIED" : "EMAIL UNVERIFIED";
}

async function loadCustomerAnalytics() {
  const data = await api("/api/customer/analytics");
  const metrics = document.querySelector('[data-view="analytics"] .metric-cards');
  if (!metrics) return;
  const total = data.by_month.reduce((sum, item) => sum + item.count, 0);
  const cards = metrics.querySelectorAll(".metric-card b");
  if (cards[0]) cards[0].textContent = String(total);
  if (cards[1]) cards[1].textContent = String(data.by_status.find((x) => x.status === "COMPLETED")?.count || 0);
  const chart = document.querySelector('[data-view="analytics"] .chart-empty p');
  if (chart && total) chart.textContent = `${total} stored tests across ${data.by_month.length} calendar months. Detailed comparisons are in your test history.`;
}

async function loadCustomerReports() {
  const data = await api("/api/customer/reports"); const total = document.querySelector('[data-view="reports"] .history-panel .quiet-label');
  if (total) total.textContent = `${data.total} REPORTS`;
  const body = document.getElementById("customer-reports-body");
  if (!data.items.length) emptyRow(body, 4, "No report records belong to your account.");
  else body.replaceChildren(...data.items.map((report) => { const row = document.createElement("tr"); row.append(cell(report.id), cell(report.test_id), cell(dateText(report.created_at)), statusCell(report.status)); return row; }));
  const empty = document.querySelector('[data-view="reports"] .history-empty');
  if (empty) empty.textContent = data.total ? "Report file storage is not configured. Download actions are unavailable." : "Reports will be listed here once generated from verified records.";
}

async function loadAdminDashboard() {
  const data = await api("/api/admin/dashboard");
  for (const key of ["customers", "tests", "completed", "pending", "failed", "active_regions"]) {
    const node = document.querySelector(`[data-admin-kpi="${key}"]`); if (node) node.textContent = String(data.counts[key] ?? 0);
  }
  const customerBody = document.getElementById("admin-recent-customers");
  if (!data.recent_customers.length) emptyRow(customerBody, 4, "No customer accounts have registered.");
  else customerBody.replaceChildren(...data.recent_customers.map((user) => { const row = document.createElement("tr"); row.append(cell(user.full_name), cell(user.customer_id), cell([user.city, user.state].filter(Boolean).join(", ")), cell(dateText(user.created_at))); return row; }));
  const testBody = document.getElementById("admin-recent-tests");
  if (!data.recent_tests.length) emptyRow(testBody, 5, "No test records exist.");
  else testBody.replaceChildren(...data.recent_tests.map((test) => { const row = document.createElement("tr"); row.append(cell(test.id), cell(test.customer_name), cell([test.city, test.state].filter(Boolean).join(", ")), cell(dateText(test.created_at)), statusCell(test.status)); return row; }));
  const activity = document.getElementById("admin-activity");
  if (!data.activity.length) { activity.textContent = "No system activity recorded."; }
  else activity.replaceChildren(...data.activity.map((item) => { const line = document.createElement("div"); line.className = "activity-row"; const dot = document.createElement("i"); const text = document.createElement("div"); text.append(document.createTextNode(item.action.replaceAll("_", " "))); const time = document.createElement("small"); time.textContent = dateText(item.created_at); text.append(time); line.append(dot, text); return line; }));
}

function formQuery(form) {
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form)) if (String(value).trim()) params.set(key, String(value).trim());
  return params.toString();
}

async function loadAdminCustomers() {
  const form = document.getElementById("customer-filter-form"); const query = formQuery(form);
  const data = await api(`/api/admin/customers?limit=50&offset=${currentCustomerOffset}${query ? `&${query}` : ""}`);
  document.getElementById("admin-customer-total").textContent = `${data.total} CUSTOMERS`;
  const body = document.getElementById("admin-customers-body");
  if (!data.items.length) return emptyRow(body, 8, "No customer accounts match these filters.");
  body.replaceChildren(...data.items.map((user) => {
    const row = document.createElement("tr"); row.append(cell(user.full_name), cell(user.customer_id), cell(user.email), cell(user.organization), cell([user.city, user.state, user.region].filter(Boolean).join(", ")), cell(user.test_count), statusCell(user.account_status));
    const action = document.createElement("td"); const viewButton = detailButton("View", () => showCustomerDetail(user.user_id)); viewButton.classList.add("text-button");
    const button = document.createElement("button"); button.type = "button"; button.className = "text-button"; button.textContent = user.account_status === "ACTIVE" ? "Suspend" : "Activate";
    button.addEventListener("click", async () => {
      const next = user.account_status === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
      if (!window.confirm(`${next === "SUSPENDED" ? "Suspend" : "Activate"} ${user.full_name}'s account?`)) return;
      try { await api(`/api/admin/customers/${encodeURIComponent(user.user_id)}/status?status=${next}`, { method: "PATCH" }); toast("Customer account status updated."); await loadAdminCustomers(); }
      catch (error) { toast(error.message, true); }
    }); action.append(viewButton, document.createTextNode(" · "), button); row.append(action); return row;
  }));
}

async function loadAdminTests() {
  const form = document.getElementById("test-filter-form"); const query = formQuery(form);
  const data = await api(`/api/admin/tests?limit=50&offset=${currentTestOffset}${query ? `&${query}` : ""}`);
  document.getElementById("admin-test-total").textContent = `${data.total} RECORDS`;
  document.getElementById("tests-page-label").textContent = `Page ${Math.floor(currentTestOffset / 50) + 1} · ${data.total} records`;
  const body = document.getElementById("admin-tests-body");
  if (!data.items.length) return emptyRow(body, 7, "No test records match the selected filters.");
  body.replaceChildren(...data.items.map((test) => { const row = document.createElement("tr"); const idCell = document.createElement("td"); idCell.append(detailButton(test.id, () => showAdminTest(test.id))); row.append(idCell, cell(test.customer_name), cell(test.sample_reference), cell(dateText(test.collected_at || test.created_at)), cell([test.city, test.region, test.state].filter(Boolean).join(", ")), cell(test.sample_type), statusCell(test.status)); return row; }));
}

async function loadAdminRegions() {
  const form = document.getElementById("region-filter-form"); const query = formQuery(form);
  const data = await api(`/api/admin/regions${query ? `?${query}` : ""}`); const body = document.getElementById("regional-body");
  if (!data.items.length) return emptyRow(body, 5, "No stored test records match these geographic filters.");
  body.replaceChildren(...data.items.map((region) => { const row = document.createElement("tr"); row.append(cell(region.state), cell(region.district), cell(region.city), cell(region.region), cell(region.test_count)); return row; }));
}

async function loadAdminAnalytics() {
  const data = await api("/api/admin/analytics");
  fillTable("analytics-month-body", data.by_month, ["month", "count"]);
  fillTable("analytics-type-body", data.by_sample_type, ["sample_type", "count"]);
  fillTable("analytics-status-body", data.by_status, ["status", "count"]);
  fillTable("analytics-customer-body", data.by_customer, ["full_name", "customer_id", "count"]);
}

function fillTable(id, items, keys) {
  const body = document.getElementById(id); if (!items.length) return emptyRow(body, keys.length, "No records available.");
  body.replaceChildren(...items.map((item) => { const row = document.createElement("tr"); keys.forEach((key) => row.append(cell(item[key]))); return row; }));
}

async function loadServiceStatus() {
  const data = await api("/api/health"); document.getElementById("admin-db-status").textContent = `API available · ${data.storage}`;
}

async function loadAdminProfile() {
  const data = await api("/api/admin/profile"); const profile = data.profile || {};
  const form = document.getElementById("admin-profile-form"); form.elements.full_name.value = profile.full_name || "";
  document.getElementById("admin-profile-email-input").value = data.email || "";
  document.getElementById("admin-profile-name").textContent = profile.full_name || "Administrator";
  document.getElementById("admin-profile-email").textContent = data.email || "";
  document.getElementById("admin-profile-avatar").textContent = initials(profile.full_name);
}

async function loadAdminReports() {
  const data = await api("/api/admin/reports"); const total = document.getElementById("admin-report-total"); const body = document.getElementById("admin-reports-body");
  total.textContent = `${data.total} REPORTS`;
  if (!data.items.length) return emptyRow(body, 5, "No report records are stored.");
  body.replaceChildren(...data.items.map((report) => { const row = document.createElement("tr"); row.append(cell(report.id), cell(`${report.customer_name} · ${report.customer_id}`), cell(report.test_id), cell(dateText(report.created_at)), statusCell(report.status)); return row; }));
}

function detailButton(label, callback) {
  const button = document.createElement("button"); button.type = "button"; button.className = "table-link"; button.textContent = label; button.addEventListener("click", callback); return button;
}

function showDetail(title, data) {
  const dialog = document.getElementById("detail-dialog");
  document.getElementById("detail-dialog-title").textContent = title;
  const pre = document.createElement("pre"); pre.textContent = JSON.stringify(data, null, 2);
  document.getElementById("detail-dialog-body").replaceChildren(pre);
  if (!dialog.open) dialog.showModal();
}

async function showCustomerTest(testId) {
  try { showDetail("Test record", await api(`/api/customer/tests/${encodeURIComponent(testId)}`)); }
  catch (error) { toast(error.message, true); }
}
async function showAdminTest(testId) {
  try { showDetail("Platform test record", await api(`/api/admin/test-records/${encodeURIComponent(testId)}`)); }
  catch (error) { toast(error.message, true); }
}
async function showCustomerDetail(userId) {
  try { showDetail("Customer profile, tests and activity", await api(`/api/admin/customers/${encodeURIComponent(userId)}`)); }
  catch (error) { toast(error.message, true); }
}

async function loadMonitoringMap() {
  const query = formQuery(document.getElementById("map-filter-form"));
  const path = (sessionUser.role === "ADMIN" ? "/api/admin/map" : "/api/customer/map") + (query ? `?${query}` : "");
  const data = await api(path); const empty = document.getElementById("map-empty"); const count = document.getElementById("map-record-count");
  count.textContent = data.total ? `${data.total} mapped record${data.total === 1 ? "" : "s"}` : "No mapped records";
  if (!data.items.length) {
    document.getElementById("monitor-map").hidden = true; empty.hidden = false;
    empty.querySelector("h2").textContent = "No georeferenced records";
    empty.querySelector("p").textContent = "Records appear on the map only when their stored coordinates are present.";
    return;
  }
  if (!window.L) {
    empty.hidden = false; empty.querySelector("h2").textContent = "Map provider unavailable";
    empty.querySelector("p").textContent = "The map library did not load. Check network access and reload to view recorded coordinates.";
    return;
  }
  const mapNode = document.getElementById("monitor-map"); mapNode.hidden = false; empty.hidden = true;
  if (!leafletMap) {
    leafletMap = L.map(mapNode, { scrollWheelZoom: false });
    const tiles = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors' }).addTo(leafletMap);
    tiles.once("tileerror", () => {
      if (!leafletMap) return;
      leafletMap.remove(); leafletMap = null; leafletMarkers = null; mapNode.hidden = true; empty.hidden = false;
      empty.querySelector("h2").textContent = "Map service unavailable";
      empty.querySelector("p").textContent = "OpenStreetMap tiles could not be loaded. No map or location markers are displayed.";
    });
    leafletMarkers = L.featureGroup().addTo(leafletMap);
  }
  leafletMarkers.clearLayers();
  const points = [];
  for (const item of data.items) {
    if (typeof item.latitude !== "number" || typeof item.longitude !== "number") continue;
    const point = [item.latitude, item.longitude]; points.push(point);
    const marker = L.circleMarker(point, { radius: 6, color: "#146b70", weight: 2, fillColor: "#50b9b0", fillOpacity: .8 });
    const detail = sessionUser.role === "ADMIN" ? `${safeText(item.customer_id)} · ${safeText(item.status)}` : safeText(item.status);
    const popup = document.createElement("div");
    const reference = document.createElement("b"); reference.textContent = safeText(item.sample_reference || item.id);
    const description = document.createElement("div"); description.textContent = detail;
    popup.append(reference, description); marker.bindPopup(popup); leafletMarkers.addLayer(marker);
  }
  if (points.length) {
    leafletMap.fitBounds(leafletMarkers.getBounds().pad(.15), { maxZoom: 12 });
    setTimeout(() => leafletMap.invalidateSize(), 50);
  } else {
    mapNode.hidden = true; empty.hidden = false; empty.querySelector("h2").textContent = "No mappable coordinates";
  }
}

function parseHashAction() {
  const hash = location.hash.slice(1); const question = hash.indexOf("?");
  if (question < 0) return null;
  const action = hash.slice(0, question); const params = new URLSearchParams(hash.slice(question + 1));
  if (["verify", "reset-password"].includes(action)) return { action, token: params.get("token") || "" };
  return null;
}

async function handleAuthLink() {
  const action = parseHashAction(); if (!action) return false;
  if (action.action === "verify") {
    setAuthCard("verify");
    try { const result = await api("/api/auth/verify", { method: "POST", body: JSON.stringify({ token: action.token }) }); document.getElementById("verify-copy").textContent = result.message; document.getElementById("verify-copy").classList.add("form-message", "success"); }
    catch (error) { document.getElementById("verify-copy").textContent = error.message; }
  } else {
    setAuthCard("reset"); document.getElementById("reset-form").dataset.token = action.token;
  }
  return true;
}

document.querySelectorAll("[data-open-auth]").forEach((button) => button.addEventListener("click", () => {
  const target = button.dataset.openAuth;
  if (target === "forgot") document.getElementById("forgot-form").elements.email.value = document.getElementById("login-form").elements.email.value;
  if (target === "login" && parseHashAction()) history.replaceState(null, "", "#login");
  setAuthCard(target);
}));

document.querySelectorAll("[data-portal]").forEach((button) => button.addEventListener("click", () => {
  selectedPortal = button.dataset.portal;
  document.querySelectorAll("[data-portal]").forEach((item) => item.classList.toggle("selected", item === button));
  const mfaField = document.getElementById("mfa-field");
  mfaField.hidden = selectedPortal !== "ADMIN";
  document.getElementById("mfa-code").required = selectedPortal === "ADMIN";
  document.getElementById("mfa-code").value = "";
}));

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = form.querySelector('[type="submit"]');
  const credentials = formObject(form);
  if (selectedPortal !== "ADMIN" || !credentials.mfa_code) delete credentials.mfa_code;
  setMessage("login-message", "Signing in…"); button.disabled = true;
  try { const result = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ ...credentials, portal: selectedPortal }) });
    csrfToken = result.csrf_token || readCookie(CSRF_COOKIE); sessionUser = result.user; form.reset(); setMessage("login-message", "", true); enterWorkspace();
  } catch (error) { setMessage("login-message", error.message); }
  finally { button.disabled = false; }
});

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formObject(form); const button = form.querySelector('[type="submit"]');
  if (data.password !== data.confirm_password) return setMessage("register-message", "Passwords do not match.");
  if (data.organization === "") data.organization = null;
  setMessage("register-message", "Creating your customer account…"); button.disabled = true;
  try { const result = await api("/api/auth/register", { method: "POST", body: JSON.stringify(data) });
    const token = result.development_verification_token;
    if (token) {
      const message = document.getElementById("register-message"); message.textContent = `${result.message} `; message.classList.add("success");
      const link = document.createElement("a"); link.href = `#verify?token=${encodeURIComponent(token)}`; link.className = "link-button"; link.textContent = "Verify this development account"; message.append(link);
    }
    else setMessage("register-message", result.message, true);
    form.reset();
  } catch (error) { setMessage("register-message", error.message); }
  finally { button.disabled = false; }
});

document.getElementById("forgot-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { const result = await api("/api/auth/forgot-password", { method: "POST", body: JSON.stringify(formObject(form)) });
    const token = result.development_reset_token;
    if (token) {
      const message = document.getElementById("forgot-message"); message.textContent = `${result.message} `; message.classList.add("success");
      const link = document.createElement("a"); link.href = `#reset-password?token=${encodeURIComponent(token)}`; link.className = "link-button"; link.textContent = "Continue password reset"; message.append(link);
    } else setMessage("forgot-message", result.message, true);
  } catch (error) { setMessage("forgot-message", error.message); }
});

document.getElementById("reset-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formObject(form);
  if (data.password !== data.confirm_password) return setMessage("reset-message", "Passwords do not match.");
  data.token = form.dataset.token || "";
  try { const result = await api("/api/auth/reset-password", { method: "POST", body: JSON.stringify(data) }); setMessage("reset-message", result.message, true); }
  catch (error) { setMessage("reset-message", error.message); }
});

async function logout() {
  try { await api("/api/auth/logout", { method: "POST" }); }
  catch (error) { if (!error.message.includes("session")) toast(error.message, true); }
  await showSignedOut("You have signed out securely.");
}
document.getElementById("logout-button").addEventListener("click", logout);
document.getElementById("settings-logout").addEventListener("click", logout);
document.getElementById("admin-logout").addEventListener("click", logout);

document.getElementById("profile-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formObject(form); delete data.email;
  try { const result = await api("/api/customer/profile", { method: "PATCH", body: JSON.stringify(data) }); sessionUser = result; document.getElementById("sidebar-user-name").textContent = result.profile.full_name; document.getElementById("top-user-name").textContent = result.profile.full_name; setMessage("profile-message", "Profile updated.", true); }
  catch (error) { setMessage("profile-message", error.message); }
});

document.getElementById("admin-profile-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { const data = await api("/api/admin/profile", { method: "PATCH", body: JSON.stringify(formObject(form)) }); sessionUser = data; document.getElementById("admin-profile-name").textContent = data.profile.full_name; document.getElementById("sidebar-user-name").textContent = data.profile.full_name; document.getElementById("top-user-name").textContent = data.profile.full_name; document.getElementById("admin-profile-avatar").textContent = initials(data.profile.full_name); setMessage("admin-profile-message", "Profile updated.", true); }
  catch (error) { setMessage("admin-profile-message", error.message); }
});

document.getElementById("toggle-new-test").addEventListener("click", () => {
  const panel = document.getElementById("new-test-panel"); panel.hidden = !panel.hidden;
  document.getElementById("toggle-new-test").setAttribute("aria-expanded", String(!panel.hidden));
});
document.getElementById("new-test-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formObject(form);
  for (const key of ["sample_reference", "address", "collected_at", "latitude", "longitude"]) if (data[key] === "") data[key] = null;
  if (data.collected_at) data.collected_at = new Date(data.collected_at).toISOString();
  for (const key of ["latitude", "longitude"]) if (data[key] !== null) data[key] = Number(data[key]);
  try { const result = await api("/api/customer/tests", { method: "POST", body: JSON.stringify(data) }); form.reset(); setMessage("new-test-message", `Sample saved as ${result.test.id}. Analysis remains unavailable.`, true); await loadCustomerTests(); }
  catch (error) { setMessage("new-test-message", error.message); }
});

document.getElementById("customer-filter-form").addEventListener("submit", (event) => { event.preventDefault(); currentCustomerOffset = 0; loadAdminCustomers().catch((error) => toast(error.message, true)); });
document.getElementById("test-filter-form").addEventListener("submit", (event) => { event.preventDefault(); currentTestOffset = 0; loadAdminTests().catch((error) => toast(error.message, true)); });
document.getElementById("region-filter-form").addEventListener("submit", (event) => { event.preventDefault(); loadAdminRegions().catch((error) => toast(error.message, true)); });
document.getElementById("map-filter-form").addEventListener("submit", (event) => { event.preventDefault(); loadMonitoringMap().catch((error) => toast(error.message, true)); });
document.getElementById("tests-prev").addEventListener("click", () => { currentTestOffset = Math.max(0, currentTestOffset - 50); loadAdminTests().catch((error) => toast(error.message, true)); });
document.getElementById("tests-next").addEventListener("click", () => { currentTestOffset += 50; loadAdminTests().catch((error) => toast(error.message, true)); });
document.getElementById("export-tests").addEventListener("click", async () => {
  try {
    const query = formQuery(document.getElementById("test-filter-form"));
    const response = await fetch(`${API_BASE_URL}/api/admin/tests/export.csv${query ? `?${query}` : ""}`, { credentials: "include" });
    if (!response.ok) throw new Error("Export request was not authorized.");
    const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "quantlite-test-records.csv"; anchor.click(); URL.revokeObjectURL(url);
  } catch (error) { toast(error.message, true); }
});

menuToggle.addEventListener("click", () => { const open = sidebar.classList.toggle("open"); menuToggle.setAttribute("aria-expanded", String(open)); });
window.addEventListener("hashchange", async () => {
  if (!sessionUser) { await handleAuthLink(); return; }
  renderRoute();
});

const imageInput = document.getElementById("image-file");
const dropzone = document.getElementById("dropzone");
const previewWrap = document.getElementById("preview-wrap");
const previewImage = document.getElementById("image-preview");
let previewUrl = null;
function previewFile(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) return toast("Choose an image file to preview.", true);
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file); previewImage.src = previewUrl; previewImage.alt = `Local preview of ${file.name}`;
  document.getElementById("file-meta").textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB`;
  dropzone.hidden = true; previewWrap.hidden = false;
}
imageInput.addEventListener("change", () => previewFile(imageInput.files[0]));
document.getElementById("remove-image").addEventListener("click", () => { if (previewUrl) URL.revokeObjectURL(previewUrl); previewUrl = null; previewImage.removeAttribute("src"); imageInput.value = ""; previewWrap.hidden = true; dropzone.hidden = false; });
for (const name of ["dragenter", "dragover"]) dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.add("dragging"); });
for (const name of ["dragleave", "drop"]) dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.remove("dragging"); });
dropzone.addEventListener("drop", (event) => previewFile(event.dataTransfer.files[0]));

const cameraVideo = document.getElementById("camera-video"); let cameraStream = null;
async function startCamera() {
  const start = document.getElementById("camera-start"); const stop = document.getElementById("camera-stop");
  if (!navigator.mediaDevices?.getUserMedia) return setMessage("camera-message", "Camera preview requires a secure localhost connection or HTTPS.");
  start.disabled = true; start.textContent = "Requesting camera…";
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false }); cameraVideo.srcObject = cameraStream; cameraVideo.hidden = false; document.getElementById("camera-empty").hidden = true; document.getElementById("camera-state").textContent = "PREVIEW ACTIVE"; start.textContent = "Preview active"; stop.disabled = false; document.getElementById("camera-message").textContent = "Local preview only. No frames are sent to the server.";
  } catch (error) { start.disabled = false; start.textContent = "Start camera preview"; document.getElementById("camera-message").textContent = error.name === "NotAllowedError" ? "Camera permission was not granted." : "Camera could not be opened. Check the connected device."; }
}
function stopCamera() {
  cameraStream?.getTracks().forEach((track) => track.stop()); cameraStream = null; cameraVideo.srcObject = null; cameraVideo.hidden = true;
  document.getElementById("camera-empty").hidden = false; document.getElementById("camera-state").textContent = "CAMERA OFF";
  const start = document.getElementById("camera-start"); start.disabled = false; start.textContent = "Start camera preview"; document.getElementById("camera-stop").disabled = true;
  document.getElementById("camera-message").textContent = "Camera preview stopped. No frames were sent to a server.";
}
document.getElementById("camera-start").addEventListener("click", startCamera);
document.getElementById("camera-stop").addEventListener("click", stopCamera);
window.addEventListener("pagehide", () => { cameraStream?.getTracks().forEach((track) => track.stop()); if (previewUrl) URL.revokeObjectURL(previewUrl); });

document.getElementById("retry-service").addEventListener("click", initialize);
document.getElementById("retry-service-inline").addEventListener("click", initialize);
document.getElementById("detail-dialog-close").addEventListener("click", () => document.getElementById("detail-dialog").close());

(async function boot() {
  const authLink = await handleAuthLink();
  await initialize(authLink);
})();
