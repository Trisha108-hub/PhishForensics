/**
 * psychAnalysis.js
 * Takes structured questionnaire responses for one employee/victim and produces
 * a pattern-based (not clinical) analysis of which social-engineering / persuasion
 * mechanisms most likely drove the click-through, referencing established
 * frameworks (Cialdini's Influence principles, SANS "Human Risk" categories).
 *
 * Expected input shape (also matches the downloadable questionnaire template):
 * {
 *   employeeId, department, role,
 *   answers: {
 *     recognizedSenderName: bool,
 *     wasExpectingSuchEmail: bool,
 *     feltTimePressure: bool,
 *     checkedSenderAddress: bool,
 *     hoveredOverLink: bool,
 *     enteredCredentials: bool,
 *     openedAttachment: bool,
 *     reportedToSecurity: bool,
 *     reportedDelayMinutes: number|null,
 *     priorSecurityTrainingCompleted: bool,
 *     triggers: {
 *       authority: number, urgency: number, trust: number,
 *       fear: number, curiosity: number, fatigue: number
 *     },
 *     selfReportedReason: string   // free text
 *     questionnaireRatings: object // optional 0-5 ratings for the six additional questions
 *   }
 * }
 */

const REASON_KEYWORDS = {
  authority: [/boss/i, /manager/i, /ceo/i, /it (support|department)/i, /hr/i, /looked official/i],
  urgency: [/urgent/i, /rush/i, /deadline/i, /in a hurry/i, /busy/i, /didn'?t have time/i, /quick/i],
  trust: [/knew (the|this) (sender|person)/i, /trusted/i, /looked (familiar|legit)/i, /normal/i, /usual/i],
  fear: [/scared/i, /worried/i, /account.*(lock|suspend)/i, /panic/i, /afraid/i],
  curiosity: [/curious/i, /interesting/i, /wanted to see/i, /clicked without thinking/i],
  fatigue: [/tired/i, /distracted/i, /multitasking/i, /end of (day|shift)/i, /overwhelmed/i, /too many emails/i],
};

function classifySelfReportedReason(text = "") {
  const hits = [];
  for (const [category, patterns] of Object.entries(REASON_KEYWORDS)) {
    if (patterns.some((p) => p.test(text))) hits.push(category);
  }
  return hits;
}

function classifyTriggerRatings(triggers = {}) {
  return Object.entries(triggers)
    .filter(([, value]) => Number(value) >= 3)
    .map(([category]) => category);
}

/**
 * Produces the per-employee forensic/psychological breakdown.
 */
function analyzeEmployeeResponse(record) {
  const a = record.answers || {};
  const factors = [];
  let humanFactorScore = 0; // 0-100, higher = more severe compromise / more susceptibility signal

  if (a.enteredCredentials) {
    factors.push({ factor: "credential_disclosure", severity: "critical", detail: "Employee entered credentials on the phishing page — direct account compromise risk." });
    humanFactorScore += 40;
  }
  if (a.openedAttachment) {
    factors.push({ factor: "attachment_execution", severity: "critical", detail: "Employee opened the malicious attachment, potentially triggering payload execution." });
    humanFactorScore += 35;
  }
  if (a.feltTimePressure) {
    factors.push({ factor: "urgency_susceptibility", severity: "high", detail: "Employee reported feeling time pressure, indicating the urgency/scarcity tactic in the email was effective (Cialdini: Scarcity)." });
    humanFactorScore += 12;
  }
  if (a.recognizedSenderName && !a.checkedSenderAddress) {
    factors.push({ factor: "false_familiarity", severity: "high", detail: "Employee recognized a familiar-looking sender name but did not verify the actual email address — spoofed display-name attacks exploit this exact gap." });
    humanFactorScore += 15;
  }
  if (!a.wasExpectingSuchEmail) {
    factors.push({ factor: "unsolicited_action", severity: "medium", detail: "Employee acted on an email they were not expecting, without independent verification through a second channel." });
    humanFactorScore += 8;
  }
  if (!a.priorSecurityTrainingCompleted) {
    factors.push({ factor: "training_gap", severity: "medium", detail: "No prior completed security awareness training on record for this employee — a contributing organizational (not individual) factor." });
    humanFactorScore += 10;
  }
  if (a.reportedToSecurity === false) {
    factors.push({ factor: "no_incident_reporting", severity: "high", detail: "Employee did not report the incident to security, delaying containment and increasing organizational dwell-time risk." });
    humanFactorScore += 10;
  } else if (typeof a.reportedDelayMinutes === "number" && a.reportedDelayMinutes > 60) {
    factors.push({ factor: "delayed_reporting", severity: "medium", detail: `Incident was reported ${a.reportedDelayMinutes} minutes after the interaction, extending the window for attacker follow-through.` });
    humanFactorScore += 6;
  }

  const reasonCategories = Array.from(new Set([
    ...classifySelfReportedReason(a.selfReportedReason || ""),
    ...classifyTriggerRatings(a.triggers || {}),
  ]));
  const yesNoFields = [
    "recognizedSenderName", "wasExpectingSuchEmail", "checkedSenderAddress",
    "hoveredOverLink", "enteredCredentials", "openedAttachment",
    "reportedToSecurity", "priorSecurityTrainingCompleted",
  ];
  const behaviorFields = [
    "verifiedViaSecondChannel", "clickedLink", "downloadedFile",
    "sharedSensitiveInfo", "usedMfaAfterPrompt", "reportedImmediately",
  ];
  const binaryValues = yesNoFields.map((field) => a[field] ? 5 : 0);
  const additionalValues = a.questionnaireRatings
    ? Object.values(a.questionnaireRatings)
    : behaviorFields.map((field) => a[field] ? 5 : 0);
  const ratingValues = [
    ...binaryValues,
    ...Object.values(a.triggers || {}),
    ...additionalValues,
  ].map(Number).filter((value) => Number.isFinite(value));
  const questionnaireAverage = ratingValues.length === 20
    ? Number((ratingValues.reduce((sum, value) => sum + Math.max(0, Math.min(5, value)), 0) / 20).toFixed(2))
    : null;
  reasonCategories.forEach((cat) => {
    const rating = a.triggers?.[cat];
    factors.push({
      factor: `self_reported_${cat}`,
      severity: "info",
      detail: `Employee's response aligns with the "${cat}" social-engineering trigger${typeof rating === "number" ? ` (rated ${rating}/5)` : ""}, consistent with the manipulation tactics identified in the content analysis.`,
    });
  });

  humanFactorScore = Math.min(humanFactorScore, 100);

  return {
    employeeId: record.employeeId,
    department: record.department || null,
    role: record.role || null,
    humanFactorScore,
    questionnaireAverage,
    riskTier: humanFactorScore >= 60 ? "High Susceptibility" : humanFactorScore >= 30 ? "Moderate Susceptibility" : "Low Susceptibility",
    factors,
    selfReportedCategories: reasonCategories,
    recommendedFollowUp: buildFollowUpRecommendations(a, humanFactorScore),
  };
}

function buildFollowUpRecommendations(a, score) {
  const recs = [];
  if (a.enteredCredentials) recs.push("Immediate password reset + force re-authentication with MFA enrollment check.");
  if (a.openedAttachment) recs.push("Endpoint forensic triage (EDR scan, isolate host pending scan results).");
  if (score >= 30) recs.push("Enroll in targeted phishing-simulation micro-training within 2 weeks.");
  if (!a.priorSecurityTrainingCompleted) recs.push("Complete baseline security awareness training module.");
  if (a.reportedToSecurity === false) recs.push("Coach on the 'report first, don't investigate yourself' reporting policy.");
  if (recs.length === 0) recs.push("No corrective action required — reinforce positive reporting behavior with recognition.");
  return recs;
}

/**
 * Aggregate multiple employee responses into org-level psychological findings.
 */
function aggregateOrgPsychology(employeeAnalyses) {
  const tacticFrequency = {};
  employeeAnalyses.forEach((e) =>
    e.selfReportedCategories.forEach((cat) => {
      tacticFrequency[cat] = (tacticFrequency[cat] || 0) + 1;
    })
  );

  const avgHumanFactorScore =
    employeeAnalyses.reduce((acc, e) => acc + e.humanFactorScore, 0) / (employeeAnalyses.length || 1);
  const questionnaireAverages = employeeAnalyses
    .map((employee) => employee.questionnaireAverage)
    .filter((value) => typeof value === "number");

  const clickThroughRate =
    employeeAnalyses.filter((e) => e.factors.some((f) => f.factor === "credential_disclosure" || f.factor === "attachment_execution")).length /
    (employeeAnalyses.length || 1);

  return {
    totalEmployeesAssessed: employeeAnalyses.length,
    avgHumanFactorScore: Math.round(avgHumanFactorScore),
    averageQuestionnaireScore: questionnaireAverages.length
      ? Number((questionnaireAverages.reduce((sum, value) => sum + value, 0) / questionnaireAverages.length).toFixed(2))
      : null,
    questionnaireResponsesIncluded: questionnaireAverages.length,
    clickThroughRate: Number((clickThroughRate * 100).toFixed(1)),
    dominantTactics: Object.entries(tacticFrequency).sort((a, b) => b[1] - a[1]),
    highRiskEmployeeCount: employeeAnalyses.filter((e) => e.riskTier === "High Susceptibility").length,
  };
}

module.exports = { analyzeEmployeeResponse, aggregateOrgPsychology, classifySelfReportedReason };
