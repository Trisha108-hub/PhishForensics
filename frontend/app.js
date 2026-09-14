// =====================================================================
// PhishForensics frontend logic
// =====================================================================

let attachFiles = [];
let qrFile = null;
let employeeCount = 0;
let lastIncident = null;
let questionnaireResponseCount = 0;

function apiBase() { return document.getElementById("apiBase").value.replace(/\/$/, ""); }

// Keep the first screen focused on the two supported workflows. The employee
// questionnaire is part of Full Case Analysis, not a separate product mode.
const questionnaireTab = document.getElementById("tab-questionnaire");
if (questionnaireTab) {
  questionnaireTab.classList.remove("hidden");
  document.getElementById("tab-case").appendChild(questionnaireTab);
}
["case", "triage"].forEach((tab) => document.getElementById("tab-" + tab).classList.add("hidden"));

function selectWorkflow(mode) {
  document.getElementById("landing").classList.add("hidden");
  document.getElementById("modeHeader").classList.remove("hidden");
  document.getElementById("modeLabel").textContent = mode === "case"
    ? "WORKFLOW // FULL CASE ANALYSIS"
    : mode === "triage"
      ? "WORKFLOW // QUICK TRIAGE"
      : "WORKFLOW // QUESTIONNAIRE";
  document.querySelectorAll("nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === mode);
  });
  ["case", "triage", "questionnaire"].forEach((tab) => {
    document.getElementById("tab-" + tab).classList.toggle("hidden", tab !== mode);
  });
  if (questionnaireTab) questionnaireTab.classList.toggle("hidden", mode !== "case");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => selectWorkflow(button.dataset.mode));
});
document.getElementById("backToLanding").addEventListener("click", () => {
  document.getElementById("landing").classList.remove("hidden");
  document.getElementById("modeHeader").classList.add("hidden");
  ["case", "triage", "questionnaire"].forEach((tab) => {
    document.getElementById("tab-" + tab).classList.add("hidden");
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
});

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function normalizeQuestionnaireRecords(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.responses)) return data.responses;
  if (Array.isArray(data?.employees)) return data.employees;
  if (Array.isArray(data?.employeeResponses)) return data.employeeResponses;
  if (data && typeof data === "object" && (data.employeeId || data.answers)) return [data];
  throw new Error("Expected a JSON array of employee responses, or an object with responses/employees/employeeResponses.");
}

function loadQuestionnaireRecords(records) {
  document.getElementById("employeeList").innerHTML = "";
  records.forEach((rec) => addEmployeeCard(rec));
}

function downloadTextFile(filename, content, type = "application/json") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// --------------------- Tab switching ---------------------
document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (document.getElementById("landing").classList.contains("hidden") === false) {
      selectWorkflow(btn.dataset.tab);
      return;
    }
    document.querySelectorAll("nav button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    ["case", "triage", "questionnaire"].forEach((t) => {
      document.getElementById("tab-" + t).classList.toggle("hidden", t !== btn.dataset.tab);
    });
  });
});

// --------------------- File drop handling ---------------------
function setupDrop(dropId, inputId, onFiles, multiple) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  drop.addEventListener("click", () => input.click());
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.style.borderColor = "var(--accent)"; });
  drop.addEventListener("dragleave", () => { drop.style.borderColor = "var(--border)"; });
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.style.borderColor = "var(--border)";
    onFiles(multiple ? Array.from(e.dataTransfer.files) : [e.dataTransfer.files[0]]);
  });
  input.addEventListener("change", (e) => onFiles(Array.from(e.target.files)));
}

setupDrop("attachDrop", "attachInput", (files) => {
  attachFiles.push(...files);
  renderAttachChips();
}, true);

function renderAttachChips() {
  const el = document.getElementById("attachChips");
  el.innerHTML = attachFiles.map((f, i) =>
    `<span class="file-chip">${f.name} (${(f.size/1024).toFixed(1)} KB) <a href="#" onclick="removeAttach(${i});return false;" style="color:var(--red);">remove</a></span>`
  ).join("");
}
function removeAttach(i) { attachFiles.splice(i, 1); renderAttachChips(); }

setupDrop("qrDrop", "qrInput", (files) => {
  qrFile = files[0];
  document.getElementById("qrChip").innerHTML = qrFile ? `<span class="file-chip">${qrFile.name}</span>` : "";
}, false);

// --------------------- Employee questionnaire cards ---------------------
function addEmployeeCard(prefill) {
  employeeCount++;
  const id = "emp_" + employeeCount;
  const p = prefill || {};
  const a = p.answers || {};
  const r = a.questionnaireRatings || {};
  const wrap = document.createElement("div");
  wrap.className = "employee-card";
  wrap.id = id;
  wrap.innerHTML = `
    <div class="row">
      <div><label>Employee ID</label><input type="text" class="f-employeeId" value="${escapeHtml(p.employeeId)}" placeholder="emp001"></div>
      <div><label>Department</label><input type="text" class="f-department" value="${escapeHtml(p.department)}" placeholder="Finance"></div>
      <div><label>Role</label><input type="text" class="f-role" value="${escapeHtml(p.role)}" placeholder="Accounts Payable"></div>
    </div>
    <div class="grid2" style="margin-top:10px;">
      ${checkboxRow("recognizedSenderName","Recognized sender name", a.recognizedSenderName)}
      ${checkboxRow("wasExpectingSuchEmail","Was expecting such an email", a.wasExpectingSuchEmail)}
      ${checkboxRow("feltTimePressure","Felt time pressure / urgency", a.feltTimePressure)}
      ${checkboxRow("checkedSenderAddress","Checked actual sender address", a.checkedSenderAddress)}
      ${checkboxRow("hoveredOverLink","Hovered over link before clicking", a.hoveredOverLink)}
      ${checkboxRow("enteredCredentials","Entered credentials on the page", a.enteredCredentials)}
      ${checkboxRow("openedAttachment","Opened the attachment", a.openedAttachment)}
      ${checkboxRow("reportedToSecurity","Reported to security team", a.reportedToSecurity)}
      ${checkboxRow("priorSecurityTrainingCompleted","Completed prior security training", a.priorSecurityTrainingCompleted)}
    </div>
    <label>Social-engineering trigger ratings (0-5)</label>
    <div class="grid2">
      ${triggerInput("authority", "Authority", a.triggers?.authority)}
      ${triggerInput("urgency", "Urgency", a.triggers?.urgency)}
      ${triggerInput("trust", "Trust / familiarity", a.triggers?.trust)}
      ${triggerInput("fear", "Fear", a.triggers?.fear)}
      ${triggerInput("curiosity", "Curiosity", a.triggers?.curiosity)}
      ${triggerInput("fatigue", "Fatigue / distraction", a.triggers?.fatigue)}
    </div>
    <label>Additional assessment ratings (0-5)</label>
    <div class="grid2">
      ${ratingInput("verifiedViaSecondChannel", "Verified through another channel", r.verifiedViaSecondChannel)}
      ${ratingInput("clickedLink", "Clicked a link", r.clickedLink)}
      ${ratingInput("downloadedFile", "Downloaded a file", r.downloadedFile)}
      ${ratingInput("sharedSensitiveInfo", "Shared sensitive information", r.sharedSensitiveInfo)}
      ${ratingInput("usedMfaAfterPrompt", "MFA prompt/code requested", r.usedMfaAfterPrompt)}
      ${ratingInput("reportedImmediately", "Reported quickly", r.reportedImmediately)}
    </div>
    <label>Reporting delay (minutes, if reported)</label>
    <input type="number" class="f-reportedDelayMinutes" value="${escapeHtml(a.reportedDelayMinutes ?? '')}">
    <label>Employee's own account of why they acted (free text)</label>
    <textarea class="f-selfReportedReason" style="min-height:60px;">${escapeHtml(a.selfReportedReason)}</textarea>
    <button class="btn secondary" style="margin-top:10px;" onclick="document.getElementById('${id}').remove()">Remove</button>
  `;
  document.getElementById("employeeList").appendChild(wrap);
}

function checkboxRow(field, label, checked) {
  return `<label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);margin:4px 0;">
    <input type="checkbox" class="f-${field}" ${checked ? "checked" : ""}> ${label}
  </label>`;
}

function triggerInput(field, label, value) {
  const safeValue = Math.max(0, Math.min(5, Number(value) || 0));
  return `<div>
    <label style="margin:4px 0;color:var(--muted);">${label}</label>
    <input type="number" class="f-trigger-${field}" min="0" max="5" value="${safeValue}">
  </div>`;
}

function ratingInput(field, label, value) {
  const safeValue = Math.max(0, Math.min(5, Number(value) || 0));
  return `<div>
    <label style="margin:4px 0;color:var(--muted);">${label}</label>
    <input type="number" class="f-rating-${field}" min="0" max="5" value="${safeValue}">
  </div>`;
}

function collectEmployeeResponses() {
  return Array.from(document.querySelectorAll(".employee-card")).map((card) => {
    const val = (sel) => card.querySelector(sel)?.value;
    const chk = (field) => card.querySelector(`.f-${field}`)?.checked || false;
    const delay = val(".f-reportedDelayMinutes");
    return {
      employeeId: val(".f-employeeId") || "unknown",
      department: val(".f-department") || null,
      role: val(".f-role") || null,
      answers: {
        recognizedSenderName: chk("recognizedSenderName"),
        wasExpectingSuchEmail: chk("wasExpectingSuchEmail"),
        feltTimePressure: chk("feltTimePressure"),
        checkedSenderAddress: chk("checkedSenderAddress"),
        hoveredOverLink: chk("hoveredOverLink"),
        enteredCredentials: chk("enteredCredentials"),
        openedAttachment: chk("openedAttachment"),
        reportedToSecurity: chk("reportedToSecurity"),
        reportedDelayMinutes: delay ? Number(delay) : null,
        priorSecurityTrainingCompleted: chk("priorSecurityTrainingCompleted"),
        triggers: {
          authority: Number(val(".f-trigger-authority") || 0),
          urgency: Number(val(".f-trigger-urgency") || 0),
          trust: Number(val(".f-trigger-trust") || 0),
          fear: Number(val(".f-trigger-fear") || 0),
          curiosity: Number(val(".f-trigger-curiosity") || 0),
          fatigue: Number(val(".f-trigger-fatigue") || 0),
        },
        questionnaireRatings: {
          verifiedViaSecondChannel: Number(val(".f-rating-verifiedViaSecondChannel") || 0),
          clickedLink: Number(val(".f-rating-clickedLink") || 0),
          downloadedFile: Number(val(".f-rating-downloadedFile") || 0),
          sharedSensitiveInfo: Number(val(".f-rating-sharedSensitiveInfo") || 0),
          usedMfaAfterPrompt: Number(val(".f-rating-usedMfaAfterPrompt") || 0),
          reportedImmediately: Number(val(".f-rating-reportedImmediately") || 0),
        },
        selfReportedReason: val(".f-selfReportedReason") || "",
      },
    };
  });
}

function loadEmployeeJson() {
  try {
    const jsonText = document.getElementById("employeeJsonPaste").value.trim();
    if (!jsonText) {
      alert("Paste completed questionnaire JSON first, or use the Questionnaire tab to upload a JSON file.");
      return;
    }
    const records = normalizeQuestionnaireRecords(JSON.parse(jsonText));
    loadQuestionnaireRecords(records);
  } catch (e) {
    alert("Invalid JSON: " + e.message);
  }
}

addEmployeeCard(); // start with one blank card

// --------------------- Full case analysis ---------------------
async function runFullAnalysis() {
  const errEl = document.getElementById("caseError");
  errEl.textContent = "";
  document.getElementById("caseSpinner").classList.remove("hidden");
  document.getElementById("resultsPanel").classList.add("hidden");

  try {
    const fd = new FormData();
    fd.append("rawEmailSource", document.getElementById("rawEmailSource").value);
    fd.append("plainTextBody", document.getElementById("plainTextBody").value);
    fd.append("htmlBody", document.getElementById("htmlBody").value);
    fd.append("employeeResponses", JSON.stringify(collectEmployeeResponses()));
    attachFiles.forEach((f) => fd.append("attachments", f));
    if (qrFile) fd.append("qrImage", qrFile);

    const resp = await fetch(`${apiBase()}/api/case/analyze`, { method: "POST", body: fd });
    if (!resp.ok) throw new Error((await resp.json()).error || "Analysis failed");
    const incident = await resp.json();
    lastIncident = incident;
    renderResults(incident);
  } catch (e) {
    errEl.textContent = "Error: " + e.message + " (is the backend running at " + apiBase() + " ?)";
  } finally {
    document.getElementById("caseSpinner").classList.add("hidden");
  }
}

function sevBadge(sev) {
  return `<span class="badge-sev sev-${sev||'info'}">${(sev||'info').toUpperCase()}</span>`;
}

function renderFindings(title, findings) {
  if (!findings || findings.length === 0) return `<h3>${title}</h3><p style="color:var(--muted);font-size:13px;">No findings.</p>`;
  return `<h3>${title}</h3>` + findings.map(f => `<div class="finding">${sevBadge(f.severity)} ${f.detail || f.type}</div>`).join("");
}

function renderSubScoreChart(incident) {
  const values = [
    incident.subScores.headerRiskScore,
    incident.subScores.urlRiskScore,
    incident.subScores.attachmentRiskScore,
    incident.subScores.contentRiskScore,
    incident.subScores.humanFactorScore,
  ];
  const canvas = document.getElementById("subScoreChart");
  const ctx = canvas.getContext("2d");
  if (window.Chart) {
    if (window._subChart) window._subChart.destroy();
    window._subChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Header/Auth", "URL/Link", "Attachment", "Content/NLP", "Human Factor"],
        datasets: [{ label: "Risk Score", data: values, backgroundColor: "#ef4444" }],
      },
      options: {
        scales: { y: { min: 0, max: 100, ticks: { color: "#8b93a7" } }, x: { ticks: { color: "#8b93a7" } } },
        plugins: { legend: { display: false } },
      },
    });
    return;
  }

  // Keep results usable when the optional Chart.js CDN is unavailable.
  const width = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
  const height = canvas.height = 180 * (window.devicePixelRatio || 1);
  ctx.clearRect(0, 0, width, height);
  const barWidth = width / values.length * 0.55;
  values.forEach((value, index) => {
    const score = Math.max(0, Math.min(100, Number(value) || 0));
    const x = (index + 0.225) * width / values.length;
    const barHeight = score / 100 * (height - 35);
    ctx.fillStyle = "#ef4444";
    ctx.fillRect(x, height - 25 - barHeight, barWidth, barHeight);
    ctx.fillStyle = "#8b93a7";
    ctx.font = `${12 * (window.devicePixelRatio || 1)}px Segoe UI`;
    ctx.textAlign = "center";
    ctx.fillText(String(score), x + barWidth / 2, height - 8);
  });
}

function renderResults(incident) {
  document.getElementById("resultsPanel").classList.remove("hidden");
  document.getElementById("caseIdLabel").textContent = incident.caseId;
  document.getElementById("overallSeverityNum").textContent = incident.overallSeverity;
  document.getElementById("cvssScoreNum").textContent = incident.cvss.baseScore;
  document.getElementById("execSummary").textContent = incident.executiveSummary;

  renderSubScoreChart(incident);

  let html = "";
  html += renderFindings("Header & Authentication Findings", incident.header.findings);
  html += `<h3>URL / Link Analysis</h3>` + (incident.urls.length ? incident.urls.map(u => `
    <div class="finding">${sevBadge(u.verdict === 'malicious' ? 'critical' : u.verdict === 'suspicious' ? 'medium' : 'low')}
    <b>${u.url}</b> — score ${u.finalScore}/100<br>${u.findings.map(f=>f.detail).join("<br>")}</div>
  `).join("") : `<p style="color:var(--muted);font-size:13px;">No URLs found.</p>`);

  if (incident.qrCode && incident.qrCode.found) {
    html += `<h3>QR Code</h3><div class="finding">${sevBadge('high')} Decoded payload: <code class="small">${incident.qrCode.payload}</code><br>${incident.qrCode.warning||''}</div>`;
  }

  html += `<h3>Attachment Analysis</h3>` + (incident.attachments.length ? incident.attachments.map(a => `
    <div class="finding">${sevBadge(a.attachmentRiskScore>60?'critical':a.attachmentRiskScore>30?'medium':'low')}
    <b>${a.metadata.originalName}</b> — score ${a.attachmentRiskScore}/100<br>SHA256: <code class="small">${a.sha256}</code><br>
    ${a.findings.map(f=>f.detail).join("<br>")}</div>
  `).join("") : `<p style="color:var(--muted);font-size:13px;">No attachments analyzed.</p>`);

  html += renderFindings("Content & NLP Persuasion-Tactic Findings", incident.content.findings);

  html += `<h3>Standards Mapping</h3><div class="finding">${incident.owaspMapping.map(o=>`<b>${o.id}</b> ${o.title}`).join("<br>")}</div>`;
  html += `<div class="finding">${incident.mitreMapping.map(m=>`<b>${m.id}</b> ${m.title} (${m.tactic})`).join("<br>")}</div>`;

  html += `<h3>Employee Psychological / Forensic Analysis</h3>`;
  html += `<div class="row" style="margin-bottom:12px;">
    <div class="stat-box"><div class="num">${incident.orgPsychology.avgHumanFactorScore}</div><div class="label">Avg Human Factor Score</div></div>
    <div class="stat-box"><div class="num">${incident.orgPsychology.clickThroughRate}%</div><div class="label">Compromise Rate</div></div>
    <div class="stat-box"><div class="num">${incident.orgPsychology.highRiskEmployeeCount}</div><div class="label">High-Risk Employees</div></div>
    <div class="stat-box"><div class="num">${incident.orgPsychology.averageQuestionnaireScore ?? "N/A"}</div><div class="label">Avg Questionnaire Score /5</div></div>
  </div>`;
  html += incident.employeeAnalyses.map(e => `
    <div class="finding">${sevBadge(e.humanFactorScore>=60?'critical':e.humanFactorScore>=30?'medium':'low')}
    <b>${e.employeeId}</b> (${e.department||'N/A'}) — ${e.riskTier}, score ${e.humanFactorScore}/100<br>
    Questionnaire average: ${e.questionnaireAverage ?? "N/A"}/5<br>
    ${e.factors.map(f=>f.detail).join("<br>")}<br>
    <i>Follow-up: ${e.recommendedFollowUp.join("; ")}</i></div>
  `).join("");

  html += `<h3>Mitigation Plan</h3>`;
  ["technical","policy","training"].forEach(cat => {
    html += `<h4 style="text-transform:capitalize;color:var(--accent2);">${cat} measures</h4>`;
    html += incident.mitigation[cat].map(m => `<div class="finding">${sevBadge(m.priority)} ${m.action} ${m.standard?`<i style="color:var(--muted);">(${m.standard})</i>`:''}</div>`).join("");
  });

  document.getElementById("findingsSections").innerHTML = html;
}

async function exportReport() {
  if (!lastIncident) return alert("Run the analysis first.");
  const btn = document.getElementById("reportSpinner");
  btn.classList.remove("hidden");
  const resultEl = document.getElementById("reportResult");
  resultEl.textContent = "";
  try {
    const password = document.getElementById("reportPassword").value;
    const resp = await fetch(`${apiBase()}/api/case/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident: lastIncident, password: password || undefined }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Report generation failed");
    const downloadUrl = `${apiBase()}${data.downloadUrl}`;
    const pdfResp = await fetch(downloadUrl);
    if (!pdfResp.ok) throw new Error(`PDF download failed (${pdfResp.status})`);
    const pdfBlob = await pdfResp.blob();
    const objectUrl = URL.createObjectURL(pdfBlob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `${lastIncident.caseId}-report.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
    resultEl.innerHTML = `Report generated and downloaded. <a href="${escapeHtml(downloadUrl)}" style="color:var(--accent2);" target="_blank" rel="noopener">Download again</a><br>
      Password protected: ${data.passwordProtected ? "Yes" : "No — " + escapeHtml(data.warning || "")}<br>
      Report SHA256: <code class="small">${escapeHtml(data.reportSha256)}</code>`;
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--red);">Error: ${e.message}</span>`;
  } finally {
    btn.classList.add("hidden");
  }
}

// --------------------- Quick triage tab ---------------------
async function triageUrlCheck() {
  const url = document.getElementById("triageUrl").value;
  const el = document.getElementById("triageUrlResult");
  el.innerHTML = "Checking...";
  try {
    const resp = await fetch(`${apiBase()}/api/triage/url`, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ url }) });
    const data = await resp.json();
    el.innerHTML = `${sevBadge(data.verdict==='malicious'?'critical':data.verdict==='suspicious'?'medium':'low')} Score: ${data.finalScore}/100 — ${data.verdict}<br>` +
      (data.findings||[]).map(f=>`<div class="finding">${f.detail}</div>`).join("");
  } catch (e) { el.innerHTML = `<span style="color:var(--red);">${e.message}</span>`; }
}

async function triageHeaderCheck() {
  const rawSource = document.getElementById("triageHeaders").value;
  const el = document.getElementById("triageHeaderResult");
  el.innerHTML = "Checking...";
  try {
    const resp = await fetch(`${apiBase()}/api/triage/headers`, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ rawSource }) });
    const data = await resp.json();
    el.innerHTML = `Header Risk Score: ${data.headerRiskScore}/100<br>SPF: ${data.authentication.spf} | DKIM: ${data.authentication.dkim} | DMARC: ${data.authentication.dmarc}<br>` +
      (data.findings||[]).map(f=>`<div class="finding">${sevBadge(f.severity)} ${f.detail}</div>`).join("");
  } catch (e) { el.innerHTML = `<span style="color:var(--red);">${e.message}</span>`; }
}

setupDrop("triageAttachDrop", "triageAttachInput", async (files) => {
  const file = files[0];
  const el = document.getElementById("triageAttachResult");
  el.innerHTML = "Analyzing...";
  const fd = new FormData();
  fd.append("file", file);
  try {
    const resp = await fetch(`${apiBase()}/api/triage/attachment`, { method: "POST", body: fd });
    const data = await resp.json();
    el.innerHTML = `Score: ${data.attachmentRiskScore}/100<br>SHA256: <code class="small">${data.sha256}</code><br>` +
      (data.findings||[]).map(f=>`<div class="finding">${sevBadge(f.severity)} ${f.detail}</div>`).join("");
  } catch (e) { el.innerHTML = `<span style="color:var(--red);">${e.message}</span>`; }
}, false);

async function triageFullEmailCheck() {
  const rawSource = document.getElementById("triageFullEmail").value;
  const el = document.getElementById("triageFullResult");
  el.innerHTML = "Scanning...";
  try {
    const [headerResp] = await Promise.all([
      fetch(`${apiBase()}/api/triage/headers`, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ rawSource }) }),
    ]);
    const header = await headerResp.json();
    el.innerHTML = `<b>Header Risk:</b> ${header.headerRiskScore}/100<br>` +
      (header.findings||[]).map(f=>`<div class="finding">${sevBadge(f.severity)} ${f.detail}</div>`).join("") +
      `<p style="color:var(--muted);font-size:12px;margin-top:8px;">For full URL/content/attachment analysis, use the Full Case Analysis tab.</p>`;
  } catch (e) { el.innerHTML = `<span style="color:var(--red);">${e.message}</span>`; }
}

// --------------------- Questionnaire tab ---------------------
function downloadVictimPdf() {
  const result = document.getElementById("questionnaireFormResult");
  result.textContent = "Preparing fillable PDF...";
  fetch(`${apiBase()}/api/questionnaire/pdf`)
    .then(async (response) => {
      if (!response.ok) {
        const body = await response.text();
        let detail = body;
        try { detail = JSON.parse(body).error || body; } catch {}
        throw new Error(`${response.status}: ${detail || "server error"}`);
      }
      const blob = await response.blob();
      if (blob.type && !blob.type.includes("pdf")) {
        throw new Error("The server returned a non-PDF response");
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "phishforensics_employee_questionnaire.pdf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      result.textContent = "Fillable PDF downloaded.";
    })
    .catch((error) => {
      result.textContent = `PDF download failed: ${error.message}. Confirm the backend is running at ${apiBase()} and try again.`;
    });
}

function readRadioBool(name) {
  return document.querySelector(`input[name="${name}"]:checked`)?.value === "true";
}

function collectQuestionnaireFormResponse() {
  const delay = document.getElementById("qReportedDelayMinutes").value;
  return {
    employeeId: document.getElementById("qEmployeeId").value.trim() || "unknown",
    department: document.getElementById("qDepartment").value.trim() || null,
    role: document.getElementById("qRole").value.trim() || null,
    answers: {
      recognizedSenderName: readRadioBool("qRecognizedSenderName"),
      wasExpectingSuchEmail: readRadioBool("qWasExpectingSuchEmail"),
      feltTimePressure: Number(document.getElementById("qTriggerUrgency").value) >= 3,
      checkedSenderAddress: readRadioBool("qCheckedSenderAddress"),
      hoveredOverLink: readRadioBool("qHoveredOverLink"),
      enteredCredentials: readRadioBool("qEnteredCredentials"),
      openedAttachment: readRadioBool("qOpenedAttachment"),
      reportedToSecurity: readRadioBool("qReportedToSecurity"),
      reportedDelayMinutes: delay ? Number(delay) : null,
      priorSecurityTrainingCompleted: readRadioBool("qPriorSecurityTrainingCompleted"),
      triggers: {
        authority: Number(document.getElementById("qTriggerAuthority").value),
        urgency: Number(document.getElementById("qTriggerUrgency").value),
        trust: Number(document.getElementById("qTriggerTrust").value),
        fear: Number(document.getElementById("qTriggerFear").value),
        curiosity: Number(document.getElementById("qTriggerCuriosity").value),
        fatigue: Number(document.getElementById("qTriggerFatigue").value),
      },
      questionnaireRatings: {
        verifiedViaSecondChannel: Number(document.getElementById("qRatingVerifiedViaSecondChannel").value),
        clickedLink: Number(document.getElementById("qRatingClickedLink").value),
        downloadedFile: Number(document.getElementById("qRatingDownloadedFile").value),
        sharedSensitiveInfo: Number(document.getElementById("qRatingSharedSensitiveInfo").value),
        usedMfaAfterPrompt: Number(document.getElementById("qRatingUsedMfaAfterPrompt").value),
        reportedImmediately: Number(document.getElementById("qRatingReportedImmediately").value),
      },
      selfReportedReason: document.getElementById("qSelfReportedReason").value.trim(),
    },
  };
}

function downloadFilledQuestionnaire() {
  const record = collectQuestionnaireFormResponse();
  const safeId = record.employeeId.replace(/[^a-z0-9_-]/gi, "_") || "employee";
  downloadTextFile(`phishforensics_questionnaire_${safeId}.json`, JSON.stringify([record], null, 2));
  document.getElementById("questionnaireFormResult").textContent = "Response JSON downloaded.";
}

function addFilledQuestionnaireToCase() {
  const record = collectQuestionnaireFormResponse();
  addEmployeeCard(record);
  questionnaireResponseCount += 1;
  document.getElementById("questionnaireFormResult").textContent = `Response ${questionnaireResponseCount} added. Fill the form again and select "+ Add Response to Case" for another employee.`;
  resetQuestionnaireForm();
  document.getElementById("questionnaireFormResult").textContent = `Response ${questionnaireResponseCount} added. Fill the form again and select "+ Add Response to Case" for another employee.`;
}

function resetQuestionnaireForm() {
  ["qEmployeeId", "qDepartment", "qRole", "qReportedDelayMinutes", "qSelfReportedReason"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  [
    "qRecognizedSenderName",
    "qWasExpectingSuchEmail",
    "qCheckedSenderAddress",
    "qHoveredOverLink",
    "qEnteredCredentials",
    "qOpenedAttachment",
    "qReportedToSecurity",
    "qPriorSecurityTrainingCompleted",
  ].forEach((name) => {
    document.querySelector(`input[name="${name}"][value="false"]`).checked = true;
  });
  ["VerifiedViaSecondChannel", "ClickedLink", "DownloadedFile", "SharedSensitiveInfo", "UsedMfaAfterPrompt", "ReportedImmediately"].forEach((name) => {
    const input = document.getElementById(`qRating${name}`);
    input.value = 0;
    document.getElementById(`qRating${name}Value`).textContent = "0";
  });
  ["Authority", "Urgency", "Trust", "Fear", "Curiosity", "Fatigue"].forEach((name) => {
    const input = document.getElementById(`qTrigger${name}`);
    input.value = 0;
    document.getElementById(`qTrigger${name}Value`).textContent = "0";
  });
  document.getElementById("questionnaireFormResult").textContent = "";
}

function buildVictimFormHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishForensics Employee Questionnaire</title>
<style>
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0b0f1a;color:#e6e9f2}
main{max-width:900px;margin:0 auto;padding:28px 18px 60px}
.panel{background:#131a2b;border:1px solid #263049;border-radius:12px;padding:22px;margin-bottom:18px}
h1{font-size:24px;margin:0 0 8px}h2{font-size:17px;margin:0 0 12px}
p,label{color:#9aa3b8}label{display:block;font-size:13px;margin:12px 0 6px}
input[type=text],input[type=number],textarea{width:100%;background:#1b2338;color:#e6e9f2;border:1px solid #263049;border-radius:8px;padding:10px;font:inherit}
textarea{min-height:90px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.box{background:#1b2338;border:1px solid #263049;border-radius:8px;padding:12px}
.opts{display:flex;gap:12px;flex-wrap:wrap}.opts label{display:flex;gap:6px;align-items:center;margin:4px 0;color:#e6e9f2}
input[type=range]{width:100%;accent-color:#7c3aed}.btn{background:linear-gradient(135deg,#ef4444,#7c3aed);color:white;border:0;border-radius:8px;padding:12px 18px;font-weight:700;cursor:pointer}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<div class="panel"><h1>Employee Social-Engineering Questionnaire</h1><p>Complete this after a phishing or social-engineering incident. The downloaded JSON can be returned to the security analyst for case analysis.</p></div>
<div class="panel">
<h2>Employee Details</h2>
<label>Employee ID</label><input id="employeeId" type="text" placeholder="emp001">
<label>Department</label><input id="department" type="text" placeholder="Finance">
<label>Role</label><input id="role" type="text" placeholder="Accounts Payable">
</div>
<div class="panel"><h2>Incident Actions</h2><div class="grid" id="questions"></div></div>
<div class="panel">
<h2>Trigger Ratings</h2><p>0 means not present, 5 means very strong.</p>
<div class="grid" id="triggers"></div>
<label>Reporting delay in minutes, if reported</label><input id="reportedDelayMinutes" type="number" min="0">
<label>In your own words, what influenced your action?</label><textarea id="selfReportedReason"></textarea>
<button class="btn" onclick="downloadResponse()">Download Completed JSON</button>
<p id="status"></p>
</div>
</main>
<script>
const questionDefs=[
["recognizedSenderName","Did the sender name look familiar or trusted?"],
["wasExpectingSuchEmail","Were you expecting this email or request?"],
["checkedSenderAddress","Did you verify the actual sender email address?"],
["hoveredOverLink","Did you hover/check the link destination before clicking?"],
["enteredCredentials","Did you enter your password, MFA code, or other credentials?"],
["openedAttachment","Did you open an attachment or downloaded file?"],
["reportedToSecurity","Did you report it to security or IT?"],
["priorSecurityTrainingCompleted","Have you completed security awareness training?"]
];
const behaviorDefs=[
["verifiedViaSecondChannel","Did you verify the request through another trusted channel?"],
["clickedLink","Did you click a link in the message?"],
["downloadedFile","Did you download a file from the message?"],
["sharedSensitiveInfo","Did you share sensitive or confidential information?"],
["usedMfaAfterPrompt","Did the message ask you to approve or enter an MFA code?"],
["reportedImmediately","Did you report the message quickly after noticing it?"]
];
const triggerDefs=[
["authority","Authority: boss, IT, HR, vendor, executive"],
["urgency","Urgency: deadline, warning, immediate action"],
["trust","Trust/Familiarity: familiar name, usual workflow"],
["fear","Fear: account lock, penalty, breach, loss"],
["curiosity","Curiosity: unexpected file, benefit, surprise"],
["fatigue","Fatigue/Distraction: busy, multitasking, tired"]
];
document.getElementById("questions").innerHTML=questionDefs.map(([id,label])=>'<div class="box"><label>'+label+'</label><div class="opts"><label><input type="radio" name="'+id+'" value="true"> Yes</label><label><input type="radio" name="'+id+'" value="false" checked> No</label></div></div>').join("");
document.getElementById("questions").innerHTML+=behaviorDefs.map(([id,label])=>'<div class="box"><label>'+label+'</label><div class="opts"><label><input type="radio" name="'+id+'" value="true"> Yes</label><label><input type="radio" name="'+id+'" value="false" checked> No</label></div></div>').join("");
document.getElementById("triggers").innerHTML=triggerDefs.map(([id,label])=>'<div class="box"><label>'+label+'</label><input type="range" id="'+id+'" min="0" max="5" value="0" oninput="document.getElementById(\\''+id+'Value\\').textContent=this.value"><span id="'+id+'Value">0</span>/5</div>').join("");
function bool(name){return document.querySelector('input[name="'+name+'"]:checked').value==="true"}
function downloadResponse(){
const delay=document.getElementById("reportedDelayMinutes").value;
const record={employeeId:document.getElementById("employeeId").value.trim()||"unknown",department:document.getElementById("department").value.trim()||null,role:document.getElementById("role").value.trim()||null,answers:{recognizedSenderName:bool("recognizedSenderName"),wasExpectingSuchEmail:bool("wasExpectingSuchEmail"),feltTimePressure:Number(document.getElementById("urgency").value)>=3,checkedSenderAddress:bool("checkedSenderAddress"),hoveredOverLink:bool("hoveredOverLink"),enteredCredentials:bool("enteredCredentials"),openedAttachment:bool("openedAttachment"),reportedToSecurity:bool("reportedToSecurity"),reportedDelayMinutes:delay?Number(delay):null,priorSecurityTrainingCompleted:bool("priorSecurityTrainingCompleted"),...Object.fromEntries(behaviorDefs.map(([id])=>[id,bool(id)])),triggers:{authority:Number(document.getElementById("authority").value),urgency:Number(document.getElementById("urgency").value),trust:Number(document.getElementById("trust").value),fear:Number(document.getElementById("fear").value),curiosity:Number(document.getElementById("curiosity").value),fatigue:Number(document.getElementById("fatigue").value)},selfReportedReason:document.getElementById("selfReportedReason").value.trim()}};
const blob=new Blob([JSON.stringify([record],null,2)],{type:"application/json"});
const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="phishforensics_questionnaire_"+record.employeeId.replace(/[^a-z0-9_-]/gi,"_")+".json";a.click();URL.revokeObjectURL(url);document.getElementById("status").textContent="Completed JSON downloaded.";
}
</script>
</body>
</html>`;
}

function downloadVictimForm() {
  downloadTextFile("phishforensics_employee_questionnaire.html", buildVictimFormHtml(), "text/html");
}

function uploadQuestionnaire() {
  const fileInput = document.getElementById("questionnaireUpload");
  const el = document.getElementById("questionnaireUploadResult");
  const files = Array.from(fileInput.files || []);
  if (!files.length) return;
  el.textContent = `Loading ${files.length} response sheet${files.length === 1 ? "" : "s"}...`;
  Promise.all(files.map(async (file) => {
    if (!(file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf"))) {
      throw new Error(`${file.name}: only completed PDF response sheets are supported`);
    }
    const fd = new FormData();
    fd.append("questionnaire", file);
    const resp = await fetch(`${apiBase()}/api/questionnaire/upload`, { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(`${file.name}: ${data.error || "upload failed"}`);
    return normalizeQuestionnaireRecords(data);
  }))
    .then((recordGroups) => {
      const records = recordGroups.flat();
      loadQuestionnaireRecords(records);
      el.textContent = `Loaded ${records.length} employee response(s) from ${files.length} PDF response sheet${files.length === 1 ? "" : "s"}.`;
      fileInput.value = "";
      document.querySelector('nav button[data-tab="case"]').click();
    })
    .catch((err) => {
      el.textContent = "Could not load response sheet: " + err.message;
      fileInput.value = "";
    });
}

document.querySelectorAll('input[type="range"][id^="qTrigger"]').forEach((input) => {
  const valueEl = document.getElementById(`${input.id}Value`);
  if (valueEl) input.addEventListener("input", () => { valueEl.textContent = input.value; });
});
