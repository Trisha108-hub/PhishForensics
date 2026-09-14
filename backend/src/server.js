require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

const { analyzeHeaders } = require("./engines/headerAnalysis");
const { analyzeContentUrls, analyzeQrCodeImage } = require("./engines/urlAnalysis");
const { analyzeContent } = require("./engines/contentAnalysis");
const { analyzeAttachment } = require("./engines/attachmentAnalysis");
const { deriveCvssVector, computeOverallSeverity, OWASP_MAPPING, MITRE_ATTACK_MAPPING } = require("./engines/riskScoring");
const { analyzeEmployeeResponse, aggregateOrgPsychology } = require("./engines/psychAnalysis");
const { buildMitigationPlan } = require("./engines/mitigationEngine");
const { generateReportPdf, passwordProtectPdf } = require("./engines/reportGenerator");
const { generateQuestionnairePdfBuffer, parseQuestionnairePdf } = require("./engines/questionnairePdf");
const { sha256OfString, sha256OfFile, buildCustodyRecord } = require("./utils/hashUtils");

const app = express();
app.use(cors());
app.use(express.json({ limit: "25mb" }));

const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
const REPORT_DIR = path.join(__dirname, "..", "reports");
const FRONTEND_DIR = path.join(__dirname, "..", "..", "frontend");
[UPLOAD_DIR, REPORT_DIR].forEach((d) => fs.existsSync(d) || fs.mkdirSync(d, { recursive: true }));

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 50 * 1024 * 1024 } });

// Serve the browser client from the same origin so the complete app can be
// started with only `npm start` and opened at http://localhost:4000.
if (fs.existsSync(FRONTEND_DIR)) {
  app.use(express.static(FRONTEND_DIR));
}

// ---------------------------------------------------------------------------
// QUICK TRIAGE TOOL (standalone) - single URL / single attachment / raw header check
// ---------------------------------------------------------------------------
app.post("/api/triage/url", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "url is required" });
    const results = await analyzeContentUrls(url, "");
    res.json(results[0] || { url, finalScore: 0, verdict: "unknown" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/triage/headers", async (req, res) => {
  try {
    const { rawSource } = req.body;
    if (!rawSource) return res.status(400).json({ error: "rawSource is required" });
    const result = await analyzeHeaders(rawSource);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/triage/attachment", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "file is required" });
    const result = await analyzeAttachment(req.file.path, req.file.originalname);
    fs.unlink(req.file.path, () => {});
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/triage/qr", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "image is required" });
    const buffer = fs.readFileSync(req.file.path);
    const result = await analyzeQrCodeImage(buffer);
    fs.unlink(req.file.path, () => {});
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// FULL CASE PIPELINE
// Accepts: rawEmailSource (text), htmlBody (text, optional), attachments (files),
// employeeResponses (JSON array, per the questionnaire schema)
// ---------------------------------------------------------------------------
const caseUpload = upload.fields([
  { name: "attachments", maxCount: 20 },
  { name: "qrImage", maxCount: 1 },
]);

app.post("/api/case/analyze", caseUpload, async (req, res) => {
  try {
    const caseId = "PF-" + uuidv4().split("-")[0].toUpperCase();
    const rawEmailSource = req.body.rawEmailSource || "";
    const htmlBody = req.body.htmlBody || "";
    const plainTextBody = req.body.plainTextBody || rawEmailSource;
    let employeeResponses = [];
    try {
      employeeResponses = JSON.parse(req.body.employeeResponses || "[]");
    } catch {
      return res.status(400).json({ error: "employeeResponses must be valid JSON" });
    }
    if (!Array.isArray(employeeResponses)) {
      return res.status(400).json({ error: "employeeResponses must be a JSON array" });
    }

    const custody = [];

    // 1. Header analysis
    const header = await analyzeHeaders(rawEmailSource);
    custody.push(buildCustodyRecord("Raw email source", sha256OfString(rawEmailSource)));

    // 2. URL / QR analysis
    const urls = await analyzeContentUrls(plainTextBody, htmlBody);
    let qrCode = { found: false };
    const uploadedFiles = Object.values(req.files || {}).flat();
    const qrFile = (req.files?.qrImage || [])[0];
    if (qrFile) {
      qrCode = await analyzeQrCodeImage(fs.readFileSync(qrFile.path));
    }

    // 3. Content / NLP analysis
    const content = analyzeContent(plainTextBody);

    // 4. Attachment analysis
    const attachmentFiles = req.files?.attachments || [];
    const attachments = [];
    for (const file of attachmentFiles) {
      const result = await analyzeAttachment(file.path, file.originalname);
      attachments.push(result);
      custody.push(buildCustodyRecord(`Attachment: ${file.originalname}`, result.sha256));
    }

    // 5. Psychological / forensic analysis per employee
    const employeeAnalyses = employeeResponses.map(analyzeEmployeeResponse);
    const orgPsychology = aggregateOrgPsychology(employeeAnalyses);

    // 6. Composite scoring
    const urlRiskScore = urls.length ? Math.max(...urls.map((u) => u.finalScore)) : 0;
    const attachmentRiskScore = attachments.length ? Math.max(...attachments.map((a) => a.attachmentRiskScore)) : 0;
    const subScores = {
      headerRiskScore: header.headerRiskScore,
      urlRiskScore,
      attachmentRiskScore,
      contentRiskScore: content.contentRiskScore,
      humanFactorScore: orgPsychology.avgHumanFactorScore,
    };
    const overallSeverity = computeOverallSeverity(subScores);

    const credentialsWereEntered = employeeResponses.some((e) => e.answers?.enteredCredentials);
    const malwareExecuted = employeeResponses.some((e) => e.answers?.openedAttachment) && attachmentRiskScore > 50;
    const cvss = deriveCvssVector({ ...subScores, credentialsWereEntered, malwareExecuted });

    // 7. Mitigation plan
    const mitigation = buildMitigationPlan({ headerResult: header, urlResults: urls, attachmentResults: attachments, contentResult: content, orgPsychology });

    const executiveSummary = buildExecutiveSummary({ header, urls, attachments, content, orgPsychology, overallSeverity, cvss });

    const incident = {
      caseId,
      generatedAt: new Date().toISOString(),
      executiveSummary,
      header,
      urls,
      qrCode,
      content,
      attachments,
      employeeAnalyses,
      orgPsychology,
      subScores,
      overallSeverity,
      cvss,
      owaspMapping: OWASP_MAPPING,
      mitreMapping: MITRE_ATTACK_MAPPING,
      mitigation,
      custody,
    };

    // cleanup uploaded temp files (they're hashed/analyzed already)
    uploadedFiles.forEach((f) => fs.unlink(f.path, () => {}));

    res.json(incident);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

function buildExecutiveSummary({ header, urls, attachments, content, orgPsychology, overallSeverity, cvss }) {
  const parts = [];
  parts.push(`This report documents the analysis of a phishing email purportedly from "${header.identity.from}".`);
  if (header.authentication.dmarc === "fail" || header.authentication.spf === "fail") {
    parts.push("Email authentication checks (SPF/DKIM/DMARC) indicate the message likely originated from an unauthorized/spoofed source.");
  }
  const maliciousUrls = urls.filter((u) => u.verdict === "malicious").length;
  if (maliciousUrls > 0) parts.push(`${maliciousUrls} malicious URL(s) were identified in the message body.`);
  if (attachments.some((a) => a.attachmentRiskScore > 50)) parts.push("At least one attachment exhibited high-risk characteristics requiring further forensic handling.");
  if (content.matchedTactics.length > 0) parts.push(`The message content employed ${content.matchedTactics.length} distinct social-engineering tactic(s), including ${content.matchedTactics.map((t) => t.label).join(", ")}.`);
  if (orgPsychology.totalEmployeesAssessed > 0) parts.push(`Of ${orgPsychology.totalEmployeesAssessed} employee(s) assessed, ${orgPsychology.clickThroughRate}% took a compromising action (credential entry and/or attachment execution).`);
  parts.push(`Overall composite severity is scored ${overallSeverity}/100, corresponding to a CVSS 3.1 base score of ${cvss.baseScore}.`);
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// REPORT EXPORT (password-protected PDF)
// ---------------------------------------------------------------------------
app.post("/api/case/report", async (req, res) => {
  try {
    const { incident, password } = req.body;
    if (!incident) return res.status(400).json({ error: "incident object is required (from /api/case/analyze response)" });
    if (!/^[A-Za-z0-9_-]+$/.test(String(incident.caseId || ""))) {
      return res.status(400).json({ error: "incident.caseId is invalid" });
    }

    const caseId = String(incident.caseId);
    const rawPath = path.join(REPORT_DIR, `${caseId}-raw.pdf`);
    const finalPath = path.join(REPORT_DIR, `${caseId}-protected.pdf`);

    await generateReportPdf(incident, rawPath);
    const pw = password || process.env.DEFAULT_REPORT_PASSWORD || "ChangeMe123!";
    const protection = await passwordProtectPdf(rawPath, finalPath, pw);

    const servedPath = protection.protected ? finalPath : rawPath;
    const reportHash = await sha256OfFile(servedPath);

    res.json({
      downloadUrl: `/api/case/report/download?file=${encodeURIComponent(path.basename(servedPath))}`,
      passwordProtected: protection.protected,
      warning: protection.warning || null,
      reportSha256: reportHash,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/case/report/download", (req, res) => {
  const file = req.query.file;
  if (!file || path.basename(file) !== file || !/^[A-Za-z0-9_-]+\.pdf$/.test(file)) {
    return res.status(400).send("Invalid file");
  }
  const filePath = path.join(REPORT_DIR, path.basename(file));
  if (!fs.existsSync(filePath)) return res.status(404).send("Not found");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.download(filePath);
});

// ---------------------------------------------------------------------------
// QUESTIONNAIRE TEMPLATE DOWNLOAD/UPLOAD
// ---------------------------------------------------------------------------
app.get("/api/questionnaire/template", (req, res) => {
  const template = [
    {
      employeeId: "emp001",
      department: "Finance",
      role: "Accounts Payable",
      answers: {
        recognizedSenderName: true,
        wasExpectingSuchEmail: false,
        feltTimePressure: true,
        checkedSenderAddress: false,
        hoveredOverLink: false,
        enteredCredentials: true,
        openedAttachment: false,
        reportedToSecurity: false,
        reportedDelayMinutes: null,
        priorSecurityTrainingCompleted: true,
        triggers: {
          authority: 4,
          urgency: 5,
          trust: 3,
          fear: 2,
          curiosity: 0,
          fatigue: 3,
        },
        questionnaireRatings: {
          verifiedViaSecondChannel: 0,
          clickedLink: 1,
          downloadedFile: 0,
          sharedSensitiveInfo: 0,
          usedMfaAfterPrompt: 0,
          reportedImmediately: 1,
        },
        selfReportedReason: "It looked like it was from my manager and said it was urgent, so I didn't check carefully.",
      },
    },
  ];
  res.setHeader("Content-Disposition", "attachment; filename=phishguard_questionnaire_template.json");
  res.json(template);
});

app.get("/api/questionnaire/pdf", async (req, res) => {
  try {
    const pdf = await generateQuestionnairePdfBuffer();
    res.set({
      "Content-Disposition": 'attachment; filename="phishforensics_employee_questionnaire.pdf"',
      "Content-Type": "application/pdf",
      "Content-Length": pdf.length,
      "Cache-Control": "no-store",
    });
    res.end(pdf);
  } catch (e) {
    console.error("Questionnaire PDF generation failed:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/questionnaire/upload", upload.single("questionnaire"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "questionnaire file is required" });
    const ext = path.extname(req.file.originalname).toLowerCase();
    let responses;
    if (ext === ".pdf" || req.file.mimetype === "application/pdf") {
      responses = await parseQuestionnairePdf(req.file.path);
    } else {
      responses = JSON.parse(fs.readFileSync(req.file.path, "utf8"));
    }
    fs.unlink(req.file.path, () => {});
    res.json({ responses });
  } catch (e) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(400).json({ error: e.message });
  }
});

app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

const PORT = process.env.PORT || 4000;
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/") || !fs.existsSync(path.join(FRONTEND_DIR, "index.html"))) {
    return next();
  }
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`PhishForensics backend running on port ${PORT}`);
});
