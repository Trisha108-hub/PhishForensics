/**
 * reportGenerator.js
 * Renders the full incident report to PDF using PDFKit, then password-protects
 * the final PDF using qpdf (system binary) as a post-processing step.
 */

const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
const { execFile } = require("child_process");
const { severityLabelFromCvss } = require("./riskScoring");

function severityColor(score) {
  if (score >= 75) return "#b91c1c";
  if (score >= 50) return "#f97316";
  if (score >= 25) return "#eab308";
  return "#22c55e";
}

function drawProgressBar(doc, x, y, width, height, score, label, color = severityColor(score)) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const originalX = doc.x;
  const originalY = doc.y;
  doc.font("Helvetica").fontSize(9).fillColor("#111827").text(label, x, y, { width: 140 });
  doc.roundedRect(x + 150, y, width, height, 3).fill("#e5e7eb");
  doc.roundedRect(x + 150, y, width * (safeScore / 100), height, 3).fill(color);
  doc.fillColor("#111827").font("Helvetica-Bold").fontSize(9).text(`${safeScore}/100`, x + 158 + width, y, { width: 60 });
  doc.x = originalX;
  doc.y = originalY;
}

function drawSeverityGauge(doc, score) {
  const x = 50;
  const y = doc.y + 24;
  const width = doc.page.width - 100;
  doc.roundedRect(x, y, width, 76, 8).fillAndStroke("#f8fafc", "#dbe3ea");
  doc.font("Helvetica-Bold").fontSize(10).fillColor("#334155").text("COMPOSITE SEVERITY", x + 18, y + 16);
  drawProgressBar(doc, x + 18, y + 38, width - 230, 14, score, "", severityColor(score));
  doc.y = y + 100;
}

function drawSubScoreBarChart(doc, scores) {
  const rows = [
    ["Header/Auth", scores.headerRiskScore],
    ["URL/Link", scores.urlRiskScore],
    ["Attachment", scores.attachmentRiskScore],
    ["Content/NLP", scores.contentRiskScore],
    ["Human Factor", scores.humanFactorScore],
  ];
  const startX = doc.x;
  let y = doc.y + 8;
  rows.forEach(([label, value]) => {
    drawProgressBar(doc, startX, y, 280, 12, value, label, "#dc2626");
    y += 24;
  });
  doc.x = doc.page.margins.left;
  doc.y = y + 10;
}

function drawEmployeeSusceptibilityChart(doc, employeeAnalyses) {
  const startX = doc.x;
  let y = doc.y + 8;
  employeeAnalyses.slice(0, 12).forEach((employee) => {
    drawProgressBar(doc, startX, y, 260, 12, employee.humanFactorScore, employee.employeeId, severityColor(employee.humanFactorScore));
    y += 24;
  });
  if (employeeAnalyses.length > 12) {
    doc.font("Helvetica").fontSize(8).fillColor("#6b7280").text(`Chart shows first 12 of ${employeeAnalyses.length} employees.`, startX, y);
    y += 16;
  }
  doc.x = doc.page.margins.left;
  doc.y = y + 8;
}

function addSectionHeader(doc, title) {
  doc.moveDown(1);
  doc.fontSize(16).fillColor("#0f172a").font("Helvetica-Bold").text(title);
  doc.moveDown(0.3);
  doc.strokeColor("#0ea5a8").lineWidth(2).moveTo(doc.x, doc.y).lineTo(doc.page.width - doc.page.margins.right, doc.y).stroke();
  doc.moveDown(0.5);
  doc.font("Helvetica").fillColor("#1f2937").fontSize(10);
}

function startSectionPage(doc, force = false) {
  const bottom = doc.page.height - doc.page.margins.bottom;
  const minimumSectionSpace = 120;
  if (force || doc.y > bottom - minimumSectionSpace) doc.addPage();
  doc.x = doc.page.margins.left;
}

function drawMetricCard(doc, x, y, width, label, value, accent = "#0ea5a8") {
  doc.roundedRect(x, y, width, 58, 6).fillAndStroke("#f8fafc", "#dbe3ea");
  doc.rect(x, y, 4, 58).fill(accent);
  doc.font("Helvetica").fontSize(8).fillColor("#64748b").text(label.toUpperCase(), x + 14, y + 12, { width: width - 22 });
  doc.font("Helvetica-Bold").fontSize(16).fillColor("#0f172a").text(String(value), x + 14, y + 28, { width: width - 22 });
}

function drawFooter(doc, pageNumber) {
  const y = doc.page.height - 30;
  const currentY = doc.y;
  doc.save();
  doc.strokeColor("#dbe3ea").lineWidth(0.6).moveTo(doc.page.margins.left, y - 8)
    .lineTo(doc.page.width - doc.page.margins.right, y - 8).stroke();
  doc.font("Helvetica").fontSize(7).fillColor("#64748b")
    .text("PHISHFORENSICS  |  CONFIDENTIAL SECURITY ANALYSIS", doc.page.margins.left, y, { width: 300, lineBreak: false });
  doc.text(`Page ${pageNumber}`, doc.page.width - doc.page.margins.right - 60, y, { width: 60, align: "right", lineBreak: false });
  doc.restore();
  doc.y = currentY;
}

function findingsTable(doc, findings = []) {
  if (findings.length === 0) {
    doc.fontSize(10).fillColor("#6b7280").text("No findings in this category.");
    return;
  }
  findings.forEach((f) => {
    doc.fontSize(9).fillColor(severityTextColor(f.severity)).font("Helvetica-Bold").text(`[${(f.severity || "info").toUpperCase()}] `, { continued: true });
    doc.fillColor("#1f2937").font("Helvetica").text(f.detail || f.type);
    doc.moveDown(0.2);
  });
}

function severityTextColor(sev) {
  return { critical: "#b91c1c", high: "#c2410c", medium: "#a16207", low: "#15803d", info: "#374151" }[sev] || "#374151";
}

/**
 * Main report build. `incident` is the fully assembled analysis object from server.js.
 */
async function generateReportPdf(incident, outputPath) {
  const doc = new PDFDocument({
    margin: 50,
    info: { Title: `Phishing Incident Report - ${incident.caseId}`, Author: "PhishForensics" },
  });
  const stream = fs.createWriteStream(outputPath);
  doc.pipe(stream);

  // --- Cover page ---
  doc.rect(0, 0, doc.page.width, 116).fill("#0f2f3a");
  doc.fontSize(10).fillColor("#8ee6dc").font("Helvetica-Bold").text("PHISHFORENSICS", 50, 38, { characterSpacing: 1.5 });
  doc.fontSize(8).fillColor("#c7e8e4").font("Helvetica").text("INCIDENT RESPONSE AND FORENSIC ANALYSIS", 50, 57);
  doc.fontSize(26).fillColor("#0f172a").font("Helvetica-Bold").text("Phishing Incident Analysis Report", 50, 164);
  doc.fontSize(11).fillColor("#64748b").font("Helvetica").text("Evidence-led assessment of message authenticity, attack surface, and human factors", 50, 202);
  doc.moveDown(2.2);
  drawMetricCard(doc, 50, 252, 160, "Case ID", incident.caseId, "#0ea5a8");
  drawMetricCard(doc, 226, 252, 160, "Overall severity", `${incident.overallSeverity}/100`, severityColor(incident.overallSeverity));
  drawMetricCard(doc, 402, 252, 160, "CVSS base score", incident.cvss.baseScore, "#64748b");
  doc.font("Helvetica").fontSize(9).fillColor("#64748b").text(`Generated ${new Date(incident.generatedAt || Date.now()).toLocaleString()}`, 50, 334);
  doc.font("Helvetica-Bold").fontSize(11).fillColor("#334155").text(`Classification: ${severityLabelFromCvss(incident.cvss.baseScore)}`, 50, 370);
  doc.font("Helvetica").fontSize(8).fillColor("#64748b").text(`CVSS 3.1 vector: ${incident.cvss.vectorString}`, 50, 390, { width: 512 });

  doc.y = 430;
  drawSeverityGauge(doc, incident.overallSeverity);

  // --- Executive summary ---
  startSectionPage(doc, true);
  addSectionHeader(doc, "1. Executive Summary");
  doc.text(incident.executiveSummary || "N/A");

  // --- Header analysis ---
  startSectionPage(doc);
  addSectionHeader(doc, "2. Email Header & Authentication Analysis");
  doc.font("Helvetica-Bold").text("Identity:");
  doc.font("Helvetica").text(`From: ${incident.header.identity.from}`);
  doc.text(`Reply-To: ${incident.header.identity.replyTo || "N/A"}`);
  doc.text(`Return-Path: ${incident.header.identity.returnPath || "N/A"}`);
  doc.text(`Subject: ${incident.header.identity.subject || "N/A"}`);
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").text("Authentication Results:");
  doc.font("Helvetica").text(`SPF: ${incident.header.authentication.spf} | DKIM: ${incident.header.authentication.dkim} | DMARC: ${incident.header.authentication.dmarc}`);
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").text("Findings:");
  findingsTable(doc, incident.header.findings);
  doc.moveDown(0.3);
  doc.font("Helvetica-Bold").text(`Header Risk Score: ${incident.header.headerRiskScore}/100`);

  // --- URL / QR analysis ---
  const hasQrAnalysis = incident.qrCode && incident.qrCode.found;
  if (incident.urls.length || hasQrAnalysis) {
    startSectionPage(doc);
    addSectionHeader(doc, "3. Malicious Link & QR Code Analysis");
    incident.urls.forEach((u, i) => {
      doc.font("Helvetica-Bold").fontSize(10).text(`${i + 1}. ${u.url}`);
      doc.font("Helvetica").fontSize(9).fillColor("#4b5563").text(`Verdict: ${u.verdict.toUpperCase()}  |  Score: ${u.finalScore}/100`);
      findingsTable(doc, u.findings);
      doc.moveDown(0.4);
    });
    if (hasQrAnalysis) {
      doc.moveDown(0.3);
      doc.font("Helvetica-Bold").text("QR Code Payload Detected:");
      doc.font("Helvetica").text(`Decoded content: ${incident.qrCode.payload}`);
      if (incident.qrCode.warning) doc.fillColor("#b91c1c").text(incident.qrCode.warning);
    }
  }

  // --- Attachment analysis ---
  if (incident.attachments.length) {
    startSectionPage(doc);
    addSectionHeader(doc, "4. Attachment Analysis (Metadata, Stego Screen, Hash Reputation)");
    incident.attachments.forEach((a, i) => {
      doc.font("Helvetica-Bold").fontSize(10).text(`${i + 1}. ${a.metadata.originalName}`);
      doc.font("Helvetica").fontSize(9).fillColor("#4b5563").text(`SHA256: ${a.sha256}`);
      doc.text(`Size: ${a.metadata.sizeBytes} bytes | Type: ${a.metadata.type}`);
      if (a.stegoScreen.performed) {
        doc.text(`Steganography screen: LSB ratio ${a.stegoScreen.lsbOneRatio}, flagged=${a.stegoScreen.flaggedAsCandidate}`);
      }
      if (a.virusTotal.available) {
        doc.text(`VirusTotal: ${a.virusTotal.malicious}/${a.virusTotal.totalEngines} engines flagged malicious`);
      }
      findingsTable(doc, a.findings);
      doc.moveDown(0.4);
    });
  }

  // --- Content / NLP analysis ---
  startSectionPage(doc);
  addSectionHeader(doc, "5. Content & NLP / Persuasion-Tactic Analysis");
  doc.text(`Detected tactics (mapped to Cialdini's principles of influence):`);
  incident.content.matchedTactics.forEach((t) => {
    doc.font("Helvetica-Bold").fontSize(9).text(`• ${t.label}`, { continued: true });
    doc.font("Helvetica").text(`  — Principle: ${t.cialdiniPrinciple}, matches: ${t.matchCount}`);
  });
  doc.moveDown(0.3);
  doc.font("Helvetica-Bold").text(`Content Risk Score: ${incident.content.contentRiskScore}/100`);

  // --- Sub-score chart ---
  startSectionPage(doc);
  addSectionHeader(doc, "6. Composite Severity Breakdown");
  drawSubScoreBarChart(doc, incident.subScores);
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").text(`CVSS 3.1 Vector: ${incident.cvss.vectorString}`);
  doc.text(`CVSS Base Score: ${incident.cvss.baseScore} (${severityLabelFromCvss(incident.cvss.baseScore)})`);

  // --- OWASP / MITRE mapping ---
  startSectionPage(doc);
  addSectionHeader(doc, "7. Standards Mapping — OWASP Top 10 & MITRE ATT&CK");
  doc.font("Helvetica-Bold").text("OWASP Top 10 (2021) Relevance:");
  incident.owaspMapping.forEach((o) => {
    doc.font("Helvetica-Bold").fontSize(9).text(`${o.id} — ${o.title}`);
    doc.font("Helvetica").fontSize(9).fillColor("#4b5563").text(o.relevance);
    doc.moveDown(0.2);
  });
  doc.moveDown(0.4);
  doc.font("Helvetica-Bold").fillColor("#1f2937").text("MITRE ATT&CK Techniques Observed:");
  incident.mitreMapping.forEach((m) => {
    doc.font("Helvetica").fontSize(9).text(`${m.id} — ${m.title} (Tactic: ${m.tactic})`);
  });

  // --- Forensic / psychological analysis ---
  if (incident.employeeAnalyses.length) {
    startSectionPage(doc);
    addSectionHeader(doc, "8. Forensic & Psychological Analysis (Per-Employee)");
  doc.font("Helvetica").fontSize(9).fillColor("#6b7280").text(
    "Note: This section identifies which social-engineering mechanisms the questionnaire responses indicate were effective. It is a behavioral/pattern analysis for security-training purposes, not a clinical or diagnostic assessment of any individual."
  );
  doc.moveDown(0.5);
  if (incident.employeeAnalyses.length > 0) {
    drawEmployeeSusceptibilityChart(doc, incident.employeeAnalyses);
    doc.moveDown(0.5);
  }
  incident.employeeAnalyses.forEach((e) => {
    doc.x = doc.page.margins.left;
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#111827").text(`Employee: ${e.employeeId}  |  Dept: ${e.department || "N/A"}  |  Tier: ${e.riskTier}`);
    doc.font("Helvetica").fontSize(9).text(`20-question average: ${e.questionnaireAverage ?? "N/A"}/5`);
    findingsTable(doc, e.factors);
    doc.font("Helvetica-Bold").fontSize(9).text("Recommended follow-up:");
    e.recommendedFollowUp.forEach((r) => doc.font("Helvetica").fontSize(9).text(`- ${r}`));
    doc.moveDown(0.5);
    doc.x = doc.page.margins.left;
  });
  doc.moveDown(0.3);
  doc.font("Helvetica-Bold").text("Organization-Level Psychological Summary:");
  doc.font("Helvetica").fontSize(9).text(`Average human-factor score: ${incident.orgPsychology.avgHumanFactorScore}/100`);
  doc.text(`Average questionnaire score: ${incident.orgPsychology.averageQuestionnaireScore ?? "N/A"}/5 (${incident.orgPsychology.questionnaireResponsesIncluded || 0} response(s) with ratings)`);
  doc.text(`Click-through / compromise rate: ${incident.orgPsychology.clickThroughRate}%`);
    doc.text(`High-susceptibility employees: ${incident.orgPsychology.highRiskEmployeeCount}`);
  }

  // --- Mitigation ---
  startSectionPage(doc);
  addSectionHeader(doc, "9. Mitigation & Security Recommendations");
  ["technical", "policy", "training"].forEach((cat) => {
    doc.font("Helvetica-Bold").fontSize(12).fillColor("#111827").text(cat.charAt(0).toUpperCase() + cat.slice(1) + " Measures:");
    incident.mitigation[cat].forEach((m) => {
      doc.font("Helvetica-Bold").fontSize(9).fillColor(severityTextColor(m.priority)).text(`[${m.priority.toUpperCase()}] `, { continued: true });
      doc.font("Helvetica").fillColor("#1f2937").text(m.action + (m.standard ? `  (Ref: ${m.standard})` : ""));
    });
    doc.moveDown(0.5);
  });

  // --- Chain of custody ---
  if (incident.custody.length) {
    startSectionPage(doc);
    addSectionHeader(doc, "10. Chain of Custody — Artifact Hashes (SHA256)");
    incident.custody.forEach((c) => {
      doc.font("Helvetica-Bold").fontSize(9).text(c.label);
      doc.font("Helvetica").fontSize(8).fillColor("#4b5563").text(`SHA256: ${c.sha256}`);
      doc.text(`Hashed at: ${c.hashedAt}`);
      doc.moveDown(0.3);
    });
  }

  doc.end();

  await new Promise((resolve, reject) => {
    stream.on("finish", resolve);
    stream.on("error", reject);
  });

  return outputPath;
}

/**
 * Password-protects an existing PDF in place using qpdf (must be installed on the host system:
 * `apt-get install qpdf` / `brew install qpdf`). Falls back to leaving the file
 * unprotected (with a warning) if qpdf isn't available, so report generation never
 * silently fails.
 */
function passwordProtectPdf(inputPath, outputPath, password) {
  return new Promise((resolve) => {
    execFile("qpdf", ["--encrypt", password, password, "256", "--", inputPath, outputPath], { timeout: 20000 }, (err) => {
      if (err) {
        resolve({ protected: false, warning: "qpdf not found on host system — report was generated WITHOUT password protection. Install qpdf to enable this feature.", path: inputPath });
      } else {
        resolve({ protected: true, path: outputPath });
      }
    });
  });
}

module.exports = { generateReportPdf, passwordProtectPdf };
