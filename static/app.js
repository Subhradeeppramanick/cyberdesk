/* CyberDesk frontend - talks to the local stdlib-Python API. */

const $ = (sel) => document.querySelector(sel);

async function api(path, options) {
  const resp = await fetch(path, options);
  return resp.json();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

/* ---------- Tabs ---------- */
function activateView(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("active", v.id === "view-" + name));
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    activateView(tab.dataset.view);
    history.replaceState(null, "", "#" + tab.dataset.view);
  });
});

if (location.hash && $("#view-" + location.hash.slice(1))) {
  activateView(location.hash.slice(1));
}

/* ---------- Dashboard ---------- */
async function loadDashboard() {
  const stats = await api("/api/stats");
  $("#stat-cards").innerHTML = [
    ["Total cases", stats.total],
    ["Open cases", stats.open],
    ["High priority", stats.by_priority["High"] || 0],
    ["Escalated", stats.by_status["Escalated"] || 0],
    ["Closed", stats.by_status["Closed"] || 0],
  ].map(([label, num]) =>
    `<div class="card"><div class="num">${num}</div><div class="label">${label}</div></div>`
  ).join("");

  renderBars("#chart-category", stats.by_category);
  renderBars("#chart-status", stats.by_status);
}

function renderBars(selector, counts) {
  const max = Math.max(1, ...Object.values(counts));
  $(selector).innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([label, count]) => `
      <div class="bar-row">
        <span class="bar-label">${escapeHtml(label)}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(count / max) * 100}%"></span></span>
        <span class="bar-count">${count}</span>
      </div>`).join("");
}

/* ---------- Cases ---------- */
let casesCache = [];

async function loadCases() {
  const data = await api("/api/cases");
  casesCache = data.cases;
  $("#case-rows").innerHTML = casesCache.map((c) => `
    <tr data-id="${escapeHtml(c.id)}">
      <td>${escapeHtml(c.id)}</td>
      <td>${escapeHtml(c.title)}</td>
      <td>${escapeHtml(c.category)}</td>
      <td><span class="pill pill-status">${escapeHtml(c.status)}</span></td>
      <td><span class="pill pill-${c.priority.toLowerCase()}">${escapeHtml(c.priority)}</span></td>
    </tr>`).join("");

  document.querySelectorAll("#case-rows tr").forEach((row) => {
    row.addEventListener("click", () => showCase(row.dataset.id, row));
  });
}

async function showCase(id, row) {
  document.querySelectorAll("#case-rows tr").forEach((r) => r.classList.remove("selected"));
  row.classList.add("selected");
  const c = await api("/api/case?id=" + encodeURIComponent(id));
  $("#case-detail").innerHTML = `
    <h2>${escapeHtml(c.id)} - ${escapeHtml(c.title)}</h2>
    <div class="case-meta">
      <span>Category: <strong>${escapeHtml(c.category)}</strong></span>
      <span>Status: ${escapeHtml(c.status)}</span>
      <span>Priority: ${escapeHtml(c.priority)}</span>
      <span>Filed: ${escapeHtml(c.filed_on)}</span>
      <span>Complainant (fictional): ${escapeHtml(c.complainant)}, ${escapeHtml(c.city)}</span>
    </div>
    <div class="narrative">${escapeHtml(c.narrative)}</div>
    <h2>Evidence timeline</h2>
    <ul class="timeline">
      ${c.timeline.map((t) => `
        <li><span class="when">${escapeHtml(t.date)}</span><br>${escapeHtml(t.event)}</li>`).join("")}
    </ul>`;
}

/* ---------- Triage ---------- */
$("#triage-run").addEventListener("click", async () => {
  const text = $("#triage-input").value.trim();
  const box = $("#triage-result");
  if (!text) { box.innerHTML = `<p class="error-text">Paste a complaint narrative first.</p>`; return; }
  box.innerHTML = `<p>Analysing...</p>`;
  const r = await api("/api/triage", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({text}),
  });
  if (r.error) { box.innerHTML = `<p class="error-text">${escapeHtml(r.error)}</p>`; return; }

  const iocs = r.iocs || {};
  const iocRows = [
    ["URLs / domains", iocs.urls], ["IP addresses", iocs.ips],
    ["UPI handles", iocs.upi_handles], ["Emails", iocs.emails],
    ["Phones", iocs.phones], ["IFSC codes", iocs.ifsc_codes],
  ].filter(([, items]) => items && items.length);

  box.innerHTML = `
    <div class="result-box">
      <h3>Routing decision</h3>
      <table>
        <tr><td>Category</td><td><strong>${escapeHtml(r.category)}</strong></td></tr>
        <tr><td>Confidence</td><td>${escapeHtml(r.confidence)} (rules-based, fully explainable)</td></tr>
        <tr><td>Why</td><td>${escapeHtml(r.blurb)}</td></tr>
        <tr><td>Matched keywords</td><td>${(r.matched_keywords || [])
          .map((k) => `<span class="kw">${escapeHtml(k)}</span>`).join("") || "none"}</td></tr>
      </table>
    </div>
    ${iocRows.length ? `
    <div class="result-box">
      <h3>Extracted indicators of compromise</h3>
      <table>${iocRows.map(([label, items]) =>
        `<tr><td>${label}</td><td>${items.map(escapeHtml).join("<br>")}</td></tr>`).join("")}
      </table>
    </div>` : ""}`;
});

/* ---------- URL analyser ---------- */
$("#url-run").addEventListener("click", async () => {
  const url = $("#url-input").value.trim();
  const box = $("#url-result");
  if (!url) { box.innerHTML = `<p class="error-text">Enter a URL first.</p>`; return; }
  box.innerHTML = `<p>Analysing (live DNS/TLS checks can take a few seconds)...</p>`;
  const r = await api("/api/analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url}),
  });
  if (r.error) { box.innerHTML = `<p class="error-text">${escapeHtml(r.error)}</p>`; return; }

  const cls = r.verdict === "LIKELY PHISHING" ? "verdict-bad"
            : r.verdict === "SUSPICIOUS" ? "verdict-warn" : "verdict-safe";

  box.innerHTML = `
    <div class="result-box">
      <h3>Verdict: <span class="${cls}">${escapeHtml(r.verdict)}</span> (score ${r.score})</h3>
      ${r.signals.length ? `<table>${r.signals.map((s) =>
        `<tr><td>+${s.points} ${escapeHtml(s.signal)}</td><td>${escapeHtml(s.detail)}</td></tr>`).join("")}
        </table>` : "<p>No structural red flags found.</p>"}
      <p class="src-note">Method: ${escapeHtml(r.method)}</p>
    </div>
    ${r.dns ? `
    <div class="result-box">
      <h3>DNS (live)</h3>
      ${r.dns.live
        ? `<p>Resolves to: ${r.dns.addresses.map(escapeHtml).join(", ") || "no addresses"}</p>`
        : `<p class="error-text">${escapeHtml(r.dns.error || "lookup unavailable")}</p>`}
    </div>` : ""}
    ${r.tls ? `
    <div class="result-box">
      <h3>TLS certificate (live)</h3>
      ${r.tls.live
        ? `<table>
             <tr><td>Issuer</td><td>${escapeHtml(r.tls.issuer)}</td></tr>
             <tr><td>Expires</td><td>${escapeHtml(r.tls.valid_to)} (${r.tls.days_left} days left)</td></tr>
           </table>`
        : `<p class="error-text">${escapeHtml(r.tls.error)}</p>`}
    </div>` : ""}`;
});

/* ---------- IFSC ---------- */
$("#ifsc-run").addEventListener("click", async () => {
  const code = $("#ifsc-input").value.trim();
  const box = $("#ifsc-result");
  if (!code) { box.innerHTML = `<p class="error-text">Enter an IFSC first.</p>`; return; }
  box.innerHTML = `<p>Looking up...</p>`;
  const r = await api("/api/ifsc?code=" + encodeURIComponent(code));

  if (!r.found) {
    box.innerHTML = `<div class="result-box"><p class="error-text">${escapeHtml(r.error)}</p>
      <p class="src-note">Source: ${escapeHtml(r.source)}</p></div>`;
    return;
  }
  box.innerHTML = `
    <div class="result-box">
      <h3>${escapeHtml(r.bank)} - ${escapeHtml(r.branch)}</h3>
      <table>
        <tr><td>IFSC</td><td>${escapeHtml(r.ifsc)} (format valid: ${r.valid_format})</td></tr>
        <tr><td>City / State</td><td>${escapeHtml(r.city)}, ${escapeHtml(r.state)}</td></tr>
        <tr><td>Address</td><td>${escapeHtml(r.address)}</td></tr>
        <tr><td>Payment rails</td><td>${["UPI","NEFT","RTGS","IMPS"].filter((k) => r[k.toLowerCase()]).join(", ")}</td></tr>
      </table>
      <p class="src-note">Source: ${escapeHtml(r.source)}</p>
    </div>`;
});

/* ---------- boot ---------- */
loadDashboard();
loadCases();
