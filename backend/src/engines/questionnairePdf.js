const fs = require("fs");
const { PDFDocument, StandardFonts, rgb } = require("pdf-lib");

const YES_NO_FIELDS = [
  ["recognizedSenderName", "Did the sender name look familiar or trusted?"],
  ["wasExpectingSuchEmail", "Were you expecting this email or request?"],
  ["checkedSenderAddress", "Did you verify the actual sender email address?"],
  ["hoveredOverLink", "Did you hover/check the link destination before clicking?"],
  ["enteredCredentials", "Did you enter your password, MFA code, or other credentials?"],
  ["openedAttachment", "Did you open an attachment or downloaded file?"],
  ["reportedToSecurity", "Did you report it to security or IT?"],
  ["priorSecurityTrainingCompleted", "Have you completed security awareness training?"],
];

const TRIGGER_FIELDS = [
  ["authority", "Authority: boss, IT, HR, vendor, executive"],
  ["urgency", "Urgency: deadline, warning, immediate action"],
  ["trust", "Trust/familiarity: known name, usual workflow"],
  ["fear", "Fear: account lock, penalty, breach, loss"],
  ["curiosity", "Curiosity: unexpected file, offer, surprise"],
  ["fatigue", "Fatigue/distraction: busy, multitasking, tired"],
];

const BEHAVIOR_FIELDS = [
  ["verifiedViaSecondChannel", "Did you verify the request through another trusted channel?"],
  ["clickedLink", "Did you click a link in the message?"],
  ["downloadedFile", "Did you download a file from the message?"],
  ["sharedSensitiveInfo", "Did you share sensitive or confidential information?"],
  ["usedMfaAfterPrompt", "Did the message ask you to approve or enter an MFA code?"],
  ["reportedImmediately", "Did you report the message quickly after noticing it?"],
];

const ADDITIONAL_RATING_FIELDS = [
  ["verifiedViaSecondChannel", "Verified the request through another trusted channel"],
  ["clickedLink", "Clicked a link in the message"],
  ["downloadedFile", "Downloaded a file from the message"],
  ["sharedSensitiveInfo", "Shared sensitive or confidential information"],
  ["usedMfaAfterPrompt", "Message asked for an MFA approval or code"],
  ["reportedImmediately", "Reported the message quickly after noticing it"],
];

function drawText(page, text, x, y, size = 10, font, color = rgb(0.12, 0.16, 0.24)) {
  page.drawText(text, { x, y, size, font, color });
}

function addTextField(form, page, name, x, y, width, height, fontSize = 10) {
  const field = form.createTextField(name);
  field.acroField.setDefaultAppearance(`/Helv ${fontSize} Tf 0 g`);
  field.addToPage(page, { x, y, width, height, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
  return field;
}

async function generateQuestionnairePdfBuffer() {
  const pdfDoc = await PDFDocument.create();
  const form = pdfDoc.getForm();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.addPage([612, 792]);
  const { height } = page.getSize();
  let y = height - 52;

  drawText(page, "PhishForensics Employee Social-Engineering Questionnaire", 48, y, 17, bold, rgb(0.08, 0.1, 0.18));
  y -= 24;
  drawText(page, "Fill this PDF after a phishing/social-engineering incident, save it, and return the completed PDF to security.", 48, y, 9, font, rgb(0.35, 0.4, 0.5));
  y -= 34;

  drawText(page, "Employee Details", 48, y, 12, bold);
  y -= 38;
  [
    ["employeeId", "Employee ID", 48, 180],
    ["department", "Department", 232, 150],
    ["role", "Role", 390, 172],
  ].forEach(([name, label, x, width]) => {
    drawText(page, label, x, y + 16, 8, font, rgb(0.35, 0.4, 0.5));
    const field = form.createTextField(name);
    field.acroField.setDefaultAppearance("/Helv 10 Tf 0 g");
    field.addToPage(page, { x, y: y - 8, width, height: 18, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
    field.enableReadOnly();
    field.disableReadOnly();
  });
  y -= 32;

  drawText(page, "Incident Actions", 48, y, 12, bold);
  y -= 20;
  drawText(page, "For each answer, type Yes or No.", 48, y, 9, font, rgb(0.35, 0.4, 0.5));
  y -= 20;
  YES_NO_FIELDS.forEach(([name, label]) => {
    drawText(page, label, 48, y, 9, font);
    const field = form.createTextField(name);
    field.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
    field.addToPage(page, { x: 470, y: y - 4, width: 54, height: 16, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
    field.enableReadOnly();
    field.disableReadOnly();
    y -= 24;
  });

  y -= 8;
  drawText(page, "Additional Incident Behaviors", 48, y, 12, bold);
  y -= 20;
  drawText(page, "Answer Yes or No for these incident behavior questions.", 48, y, 9, font, rgb(0.35, 0.4, 0.5));
  y -= 20;
  BEHAVIOR_FIELDS.forEach(([name, label]) => {
    drawText(page, label, 48, y, 9, font);
    const field = form.createTextField(name);
    field.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
    field.addToPage(page, { x: 470, y: y - 4, width: 54, height: 16, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
    field.enableReadOnly();
    field.disableReadOnly();
    y -= 24;
  });

  const page2 = pdfDoc.addPage([612, 792]);
  y = page2.getSize().height - 52;
  drawText(page2, "PhishForensics Questionnaire — Trigger Ratings & Notes", 48, y, 17, bold, rgb(0.08, 0.1, 0.18));
  y -= 32;
  drawText(page2, "Social-Engineering Trigger Ratings", 48, y, 12, bold);
  y -= 20;
  drawText(page2, "Rate each trigger from 0 to 5. 0 = not present, 5 = very strong.", 48, y, 9, font, rgb(0.35, 0.4, 0.5));
  y -= 20;
  TRIGGER_FIELDS.forEach(([name, label]) => {
    drawText(page2, label, 48, y, 9, font);
    const field = form.createTextField(`trigger_${name}`);
    field.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
    field.addToPage(page2, { x: 470, y: y - 4, width: 54, height: 16, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
    field.enableReadOnly();
    field.disableReadOnly();
    y -= 24;
  });

  y -= 8;
  drawText(page2, "Additional Assessment Questions", 48, y, 12, bold);
  y -= 20;
  drawText(page2, "Rate each item from 0 (never/not applicable) to 5 (always/strongly applicable).", 48, y, 9, font, rgb(0.35, 0.4, 0.5));
  y -= 20;
  ADDITIONAL_RATING_FIELDS.forEach(([name, label]) => {
    drawText(page2, label, 48, y, 9, font);
    const field = form.createTextField(`rating_${name}`);
    field.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
    field.addToPage(page2, { x: 470, y: y - 4, width: 54, height: 16, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
    field.enableReadOnly();
    field.disableReadOnly();
    y -= 24;
  });

  y -= 8;
  drawText(page2, "Reporting delay in minutes, if reported", 48, y, 9, font);
  const delayField = form.createTextField("reportedDelayMinutes");
  delayField.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
  delayField.addToPage(page2, { x: 260, y: y - 4, width: 70, height: 16, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
  delayField.enableReadOnly();
  delayField.disableReadOnly();
  y -= 34;

  drawText(page2, "Employee's own account of what influenced their action", 48, y, 9, font);
  y -= 80;
  const reasonField = form.createTextField("selfReportedReason");
  reasonField.acroField.setDefaultAppearance("/Helv 9 Tf 0 g");
  reasonField.addToPage(page2, { x: 48, y, width: 476, height: 70, borderColor: rgb(0.55, 0.6, 0.7), borderWidth: 1 });
  reasonField.enableReadOnly();
  reasonField.disableReadOnly();

  // Keep the AcroForm fields editable. Some pdf-lib versions throw while
  // regenerating appearances for empty fields, so leave viewer-side rendering
  // enabled instead of failing the entire download.
  return Buffer.from(await pdfDoc.save({ updateFieldAppearances: false }));
}

function boolFromText(value) {
  return /^(yes|y|true|1)$/i.test(String(value || "").trim());
}

function ratingFromText(value) {
  const num = Number(String(value || "").trim());
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(5, Math.round(num)));
}

async function parseQuestionnairePdf(filePath) {
  const pdfDoc = await PDFDocument.load(fs.readFileSync(filePath));
  const form = pdfDoc.getForm();
  const text = (name) => {
    try {
      return form.getTextField(name).getText();
    } catch {
      return "";
    }
  };

  const triggers = Object.fromEntries(
    TRIGGER_FIELDS.map(([name]) => [name, ratingFromText(text(`trigger_${name}`))])
  );
  const questionnaireRatings = Object.fromEntries(
    ADDITIONAL_RATING_FIELDS.map(([name]) => [name, ratingFromText(text(`rating_${name}`))])
  );

  return [
    {
      employeeId: text("employeeId").trim() || "unknown",
      department: text("department").trim() || null,
      role: text("role").trim() || null,
      answers: {
        ...Object.fromEntries(YES_NO_FIELDS.map(([name]) => [name, boolFromText(text(name))])),
        ...Object.fromEntries(BEHAVIOR_FIELDS.map(([name]) => [name, boolFromText(text(name))])),
        feltTimePressure: triggers.urgency >= 3,
        reportedDelayMinutes: text("reportedDelayMinutes").trim() ? Number(text("reportedDelayMinutes")) : null,
        triggers,
        questionnaireRatings,
        selfReportedReason: text("selfReportedReason").trim(),
      },
    },
  ];
}

module.exports = { generateQuestionnairePdfBuffer, parseQuestionnairePdf };
