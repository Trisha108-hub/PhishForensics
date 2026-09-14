/**
 * mitigationEngine.js
 * Generates a prioritized, technical + policy mitigation plan from the
 * combined findings of every analysis engine.
 */

function buildMitigationPlan({ headerResult, urlResults = [], attachmentResults = [], contentResult, orgPsychology }) {
  const technical = [];
  const policy = [];
  const training = [];

  // --- Email authentication / infra ---
  if (headerResult.authentication.spf !== "pass") {
    technical.push({ priority: "high", action: "Enforce SPF with a hard-fail policy (-all) on all sending domains.", standard: "RFC 7208 / NIST SP 800-177" });
  }
  if (headerResult.authentication.dkim !== "pass") {
    technical.push({ priority: "high", action: "Deploy/repair DKIM signing on outbound mail infrastructure and rotate keys periodically.", standard: "RFC 6376" });
  }
  if (headerResult.authentication.dmarc !== "pass") {
    technical.push({ priority: "critical", action: "Publish/enforce a DMARC policy at p=reject (after a monitoring period at p=quarantine) to stop spoofed mail using your domain.", standard: "RFC 7489" });
  }

  // --- URL / link findings ---
  if (urlResults.some((u) => u.verdict !== "likely_benign")) {
    technical.push({ priority: "high", action: "Deploy/verify a secure email gateway with time-of-click URL rewriting and sandboxed detonation for all inbound links.", standard: "NIST SP 800-177 Rev.1" });
    technical.push({ priority: "medium", action: "Block identified malicious domains/IPs at the DNS resolver and perimeter firewall.", standard: "CIS Control 9" });
  }
  if (urlResults.some((u) => u.findings.some((f) => f.type === "brand_lookalike"))) {
    technical.push({ priority: "medium", action: "Register/monitor common typosquat variants of company and partner brand domains (defensive domain registration + brand-monitoring service).", standard: "CIS Control 9" });
  }

  // --- Attachments ---
  if (attachmentResults.some((a) => a.findings.some((f) => f.type === "macro_enabled_office_doc"))) {
    technical.push({ priority: "critical", action: "Disable Office macros from the internet by default via Group Policy / Intune configuration (block VBA execution for files originating externally).", standard: "CIS Control 9 / Microsoft ASR rules" });
  }
  if (attachmentResults.some((a) => a.findings.some((f) => f.type === "high_risk_extension" || f.type === "double_extension"))) {
    technical.push({ priority: "high", action: "Enforce attachment-type filtering at the mail gateway to block or sandbox high-risk executable/script extensions.", standard: "CIS Control 9" });
  }
  if (attachmentResults.some((a) => a.stegoScreen?.flaggedAsCandidate)) {
    technical.push({ priority: "medium", action: "Route flagged image attachments to dedicated steganalysis tooling (e.g. StegExpose, zsteg) for confirmatory forensic review.", standard: "NIST SP 800-86 (forensic process)" });
  }

  // --- Endpoint / identity ---
  if ((orgPsychology?.clickThroughRate || 0) > 0) {
    technical.push({ priority: "critical", action: "Mandate phishing-resistant MFA (FIDO2/WebAuthn) for all accounts, especially those confirmed to have entered credentials.", standard: "NIST SP 800-63B / OWASP A07:2021" });
    policy.push({ priority: "high", action: "Enforce immediate password rotation + session revocation for any account confirmed to have disclosed credentials." });
  }
  technical.push({ priority: "medium", action: "Ensure EDR/antivirus coverage on all endpoints with real-time behavioral detection, not signature-only.", standard: "CIS Control 10" });

  // --- Policy / process ---
  policy.push({ priority: "high", action: "Establish/reinforce a one-click 'Report Phishing' button in the mail client tied to the SOC triage queue." });
  policy.push({ priority: "medium", action: "Implement out-of-band verification requirement for any request involving credentials, payments, or urgent account actions." });
  if ((orgPsychology?.avgHumanFactorScore || 0) > 30) {
    policy.push({ priority: "high", action: "Introduce a no-blame reporting culture policy to reduce delayed/non-reporting behavior observed in this incident." });
  }

  // --- Training, tied to detected persuasion tactics ---
  (contentResult?.matchedTactics || []).forEach((t) => {
    training.push({
      priority: "medium",
      action: `Targeted micro-training module on recognizing "${t.label}" tactics (principle: ${t.cialdiniPrinciple}).`,
    });
  });
  if ((orgPsychology?.highRiskEmployeeCount || 0) > 0) {
    training.push({ priority: "high", action: `Enroll the ${orgPsychology.highRiskEmployeeCount} identified high-susceptibility employee(s) in focused 1:1 coaching + follow-up simulated phishing test within 30 days.` });
  }
  training.push({ priority: "low", action: "Run quarterly organization-wide phishing simulations with escalating sophistication, tracked against this incident's baseline click-through rate." });

  const sortByPriority = (arr) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return arr.sort((a, b) => order[a.priority] - order[b.priority]);
  };

  return {
    technical: sortByPriority(technical),
    policy: sortByPriority(policy),
    training: sortByPriority(training),
  };
}

module.exports = { buildMitigationPlan };
