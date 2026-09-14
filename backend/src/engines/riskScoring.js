/**
 * riskScoring.js
 * Combines header, URL, attachment and content sub-scores into an overall
 * incident severity, derives a representative CVSS 3.1 vector, and maps
 * the incident to OWASP Top 10 / MITRE ATT&CK references for the report.
 */

/**
 * We express phishing-incident severity as a CVSS 3.1 *contextual* vector.
 * This is a standard, defensible way consultants translate a social-engineering
 * incident into a CVSS score for executive reporting, even though CVSS was
 * designed for software vulnerabilities — we're scoring the *exploitability
 * and impact of this specific delivered attack*, not a CVE.
 */
function deriveCvssVector({ headerRiskScore, urlRiskScore, attachmentRiskScore, contentRiskScore, credentialsWereEntered, malwareExecuted }) {
  // Attack Vector: Network (phishing is always delivered over network)
  const AV = "N";
  // Attack Complexity: Low if generic mass-phish patterns, High if it's a highly tailored spear-phish
  const AC = contentRiskScore > 60 ? "L" : "H";
  // Privileges Required: None (attacker needs no prior access to send the email)
  const PR = "N";
  // User Interaction: Required (victim must click/open/enter data)
  const UI = "R";
  // Scope: Changed if malware executed or credentials harvested cross system boundary, else Unchanged
  const S = malwareExecuted || credentialsWereEntered ? "C" : "U";
  // Confidentiality Impact
  const C = credentialsWereEntered ? "H" : urlRiskScore > 60 ? "M" : "L";
  // Integrity Impact
  const I = malwareExecuted ? "H" : attachmentRiskScore > 60 ? "M" : "L";
  // Availability Impact
  const A = malwareExecuted ? "H" : "N";

  const vectorString = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;

  // Simplified base score approximation (not the full official formula, but
  // proportionally consistent with FIRST.org's CVSS 3.1 calculator for reporting purposes)
  const weights = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: { N: 0.85, L: 0.62, H: 0.27 },
    UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 },
    I: { H: 0.56, M: 0.22, L: 0.22, N: 0 },
    A: { H: 0.56, M: 0.22, N: 0 },
  };

  const iscBase = 1 - (1 - weights.C[C]) * (1 - weights.I[I]) * (1 - weights.A[A]);
  const impact = S === "C" ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15) : 6.42 * iscBase;
  const exploitability = 8.22 * weights.AV[AV] * weights.AC[AC] * weights.PR[PR] * weights.UI[UI];

  let base;
  if (impact <= 0) base = 0;
  else if (S === "C") base = Math.min(1.08 * (impact + exploitability), 10);
  else base = Math.min(impact + exploitability, 10);

  const roundUp1Decimal = (n) => Math.ceil(n * 10) / 10;

  return { vectorString, baseScore: roundUp1Decimal(Math.max(base, 0)) };
}

function severityLabelFromCvss(score) {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

/** Static mapping references included in every report for standards alignment */
const OWASP_MAPPING = [
  { id: "A01:2021", title: "Broken Access Control", relevance: "If harvested credentials grant the attacker unauthorized access to systems the victim was authorized to use." },
  { id: "A03:2021", title: "Injection", relevance: "Relevant if the phishing payload leads to script/macro injection via the attachment." },
  { id: "A05:2021", title: "Security Misconfiguration", relevance: "Relevant where SPF/DKIM/DMARC were absent or misconfigured, enabling spoofing." },
  { id: "A07:2021", title: "Identification and Authentication Failures", relevance: "Directly relevant when credentials were harvested and MFA was absent or bypassed." },
  { id: "A09:2021", title: "Security Logging and Monitoring Failures", relevance: "Relevant if the phishing email or resulting compromise was not detected by existing monitoring." },
];

const MITRE_ATTACK_MAPPING = [
  { id: "T1566", title: "Phishing", tactic: "Initial Access" },
  { id: "T1566.001", title: "Spearphishing Attachment", tactic: "Initial Access" },
  { id: "T1566.002", title: "Spearphishing Link", tactic: "Initial Access" },
  { id: "T1598", title: "Phishing for Information", tactic: "Reconnaissance" },
  { id: "T1204", title: "User Execution", tactic: "Execution" },
  { id: "T1656", title: "Impersonation", tactic: "Resource Development / Defense Evasion" },
];

function computeOverallSeverity({ headerRiskScore = 0, urlRiskScore = 0, attachmentRiskScore = 0, contentRiskScore = 0, humanFactorScore = 0 }) {
  // Weighted composite - human factor (did anyone actually fall for it) weighted highest
  const overall = Math.round(
    headerRiskScore * 0.2 +
      urlRiskScore * 0.25 +
      attachmentRiskScore * 0.2 +
      contentRiskScore * 0.15 +
      humanFactorScore * 0.2
  );
  return Math.min(overall, 100);
}

module.exports = {
  deriveCvssVector,
  severityLabelFromCvss,
  OWASP_MAPPING,
  MITRE_ATTACK_MAPPING,
  computeOverallSeverity,
};
