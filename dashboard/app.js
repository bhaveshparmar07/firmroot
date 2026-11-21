/* Firmroot dashboard — reads the 3 committed scan report.json files. */

const SAMPLES = [
  { id: "eds5000", label: "EDS5000 v2.3.0.0R7 (Lantronix)", path: "../findings/eds5000/report.json" },
  { id: "jwnr",    label: "JWNR2000v3 v1.0.0.32 (TBS)",   path: "../findings/jwnr/report.json" },
  { id: "xr1000",  label: "XR1000 V1.0.64.18 (D-Link)",   path: "../findings/xr1000/report.json" },
];

const SEV = {
  Critical: "var(--crit)", High: "var(--high)",
  Medium: "var(--med)", Low: "var(--low)",
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function findingCard(ev, tri) {
  const sev = tri?.priority ?? "Low";
  const sevColor = SEV[sev] ?? SEV.Low;
  const card = document.createElement("article");
  card.className = "finding-card";
  card.style.setProperty("--sev-color", sevColor);

  const net = (ev.matched_network_symbols ?? []).map(s => `<span class="sym-tag net">${esc(s)}</span>`).join("");
  const wr  = (ev.matched_file_write_symbols ?? []).map(s => `<span class="sym-tag wr">${esc(s)}</span>`).join("");
  const sources = (ev.sources ?? []).map(s => `<code>${esc(s)}</code>`).join(" ");

  const supp = ev.supplementary ?? {};
  const suppBits = [];
  if (supp.versions) suppBits.push(`<h4>Versions</h4><p>${esc(JSON.stringify(supp.versions))}</p>`);
  if (supp.possible_hardcoded_credentials?.length)
    suppBits.push(`<h4>Credential-like strings</h4><ul>${supp.possible_hardcoded_credentials.map(c => `<li><code>${esc(c)}</code></li>`).join("")}</ul>`);

  card.innerHTML = `
    <div class="finding-head">
      <div>
        <div class="finding-title">${esc(tri?.title ?? ev.type)}</div>
        <div class="finding-sub">
          <code>${esc(ev.binary)}</code> · runs as <code>${esc(ev.user)}</code>
          ${ev.setuid_bit ? "· setuid" : ""}
        </div>
      </div>
      <span class="sev-badge" style="background:${sevColor}">${esc(sev)}</span>
    </div>
    <div class="lifecycle">
      <div class="lifecycle-col">
        <div class="evidence-block">
          <h4>Evidence — symbol buckets</h4>
          <div class="sym-tags">${net}${wr}</div>
          <div class="sources">${sources}</div>
        </div>
        <h4>Explanation</h4>
        <p>${esc(tri?.explanation ?? "")}</p>
        ${suppBits.join("")}
      </div>
      <div class="lifecycle-col">
        <h4>Attack scenario</h4>
        <p>${esc(tri?.attack_scenario ?? "")}</p>
        <h4>Permanent fix</h4>
        <p>${esc(tri?.permanent_fix ?? "")}</p>
        <h4>Immediate mitigation</h4>
        <p>${esc(tri?.immediate_mitigation ?? "")}</p>
        <h4>Compromise indicators</h4>
        <p>${esc(tri?.compromise_indicators ?? "")}</p>
      </div>
    </div>`;
  return card;
}

async function loadSample(sample) {
  $("error-state").classList.add("hidden");
  try {
    const res = await fetch(sample.path, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const report = await res.json();
    render(report, sample);
  } catch (e) {
    $("empty-state").classList.add("hidden");
    $("scan-header").classList.add("hidden");
    $("scan-summary").classList.add("hidden");
    $("findings-list").innerHTML = "";
    const err = $("error-state");
    err.textContent = `Failed to load scan: ${e.message}`;
    err.classList.remove("hidden");
  }
}

function render(report, sample) {
  $("empty-state").classList.add("hidden");
  $("error-state").classList.add("hidden");
  $("scan-header").classList.remove("hidden");

  $("fw-name").textContent = sample.label;
  $("svc-count").textContent = `${report.services_enumerated} services`;
  $("bin-count").textContent = `${report.binaries_analyzed} binaries analyzed`;
  $("findings-count").textContent = `${report.findings.length} candidate findings`;
  $("fw-sha").textContent = `sha256 ${report.sha256.slice(0, 24)}…`;

  const summary = report.gemini?.scan_summary;
  if (summary) {
    $("scan-summary").textContent = summary;
    $("scan-summary").classList.remove("hidden");
  } else {
    $("scan-summary").classList.add("hidden");
  }

  // Highest-severity finding drives the risk number — traceable to a
  // real gemini priority field, not a synthetic metric.
  const prio = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const triage = new Map((report.gemini?.findings ?? []).map(f => [f.finding_id, f]));
  const worst = Math.max(0, ...(report.gemini?.findings ?? []).map(f => prio[f.priority] ?? 0));
  const scoreEl = $("risk-score");
  scoreEl.textContent = ["—", "Low", "Medium", "High", "Critical"][worst] ?? "—";
  scoreEl.style.color = ["var(--low)", "var(--low)", "var(--med)", "var(--high)", "var(--crit)"][worst];
  $("risk-caption").textContent = "top finding severity";

  const list = $("findings-list");
  list.innerHTML = "";
  for (const ev of report.findings) {
    list.appendChild(findingCard(ev, triage.get(ev.finding_id)));
  }
}

function init() {
  const sel = $("sample-select");
  for (const s of SAMPLES) {
    const o = document.createElement("option");
    o.value = s.id; o.textContent = s.label;
    sel.appendChild(o);
  }
  const load = () => loadSample(SAMPLES.find(s => s.id === sel.value));
  $("load-btn").addEventListener("click", load);
  sel.addEventListener("change", load);
  load(); // default: first sample populated on first load
}

document.addEventListener("DOMContentLoaded", init);
