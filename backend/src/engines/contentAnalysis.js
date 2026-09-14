/**
 * contentAnalysis.js
 * Heuristic NLP scan of email body text for social-engineering / persuasion
 * tactics (mapped to Cialdini's principles) and generic phishing language patterns.
 */

const TACTIC_PATTERNS = {
  urgency: {
    label: "Urgency / Time Pressure",
    cialdini: "Scarcity",
    patterns: [/\burgent\b/i, /\bimmediately\b/i, /act now/i, /expires? (today|soon|in \d+)/i, /within \d+ (hours|minutes|days)/i, /final notice/i, /last chance/i],
  },
  authority: {
    label: "Authority Impersonation",
    cialdini: "Authority",
    patterns: [/\bceo\b/i, /\bhr department\b/i, /it support/i, /help ?desk/i, /management team/i, /legal (department|action)/i, /security team/i],
  },
  fear: {
    label: "Fear / Threat of Loss",
    cialdini: "Loss Aversion / Fear",
    patterns: [/account (will be|has been) (suspended|locked|closed)/i, /unauthorized (access|login|activity)/i, /suspicious activity/i, /your (account|password) (has been|will be) compromised/i, /failure to (comply|respond|act)/i, /legal action/i],
  },
  reward: {
    label: "Reward / Incentive Bait",
    cialdini: "Reciprocity",
    patterns: [/you('| ha)ve won/i, /claim your (prize|reward|refund)/i, /free (gift|money|bonus)/i, /gift card/i, /cash prize/i],
  },
  socialProof: {
    label: "Social Proof",
    cialdini: "Social Proof",
    patterns: [/everyone (else )?has (already )?(done|completed|signed)/i, /other employees (have|already)/i, /join (thousands|millions) of/i],
  },
  credentialHarvest: {
    label: "Credential Harvesting Request",
    cialdini: "N/A (technical intent)",
    patterns: [/verify your (account|password|identity|details)/i, /confirm your (login|credentials|password)/i, /update your (payment|billing) (info|information|details)/i, /click here to (login|sign in|verify)/i, /re-?enter your password/i],
  },
  genericGreeting: {
    label: "Generic / Non-Personalized Greeting",
    cialdini: "N/A (quality signal)",
    patterns: [/^dear (customer|user|valued (customer|member)|sir\/madam)/im, /^dear employee/im],
  },
  grammarSpelling: {
    label: "Unusual Phrasing / Grammar Irregularity",
    cialdini: "N/A (quality signal)",
    patterns: [/kindly (revert|do the needful)/i, /please to inform/i, /do the needful/i],
  },
};

function analyzeContent(bodyText = "") {
  const findings = [];
  let tacticScore = 0;
  const matchedTactics = [];

  for (const [key, config] of Object.entries(TACTIC_PATTERNS)) {
    const matches = config.patterns.filter((p) => p.test(bodyText));
    if (matches.length > 0) {
      matchedTactics.push({
        tactic: key,
        label: config.label,
        cialdiniPrinciple: config.cialdini,
        matchCount: matches.length,
      });
      tacticScore += Math.min(matches.length * 8, 20);
      findings.push({
        type: `tactic_${key}`,
        severity: key === "credentialHarvest" || key === "fear" ? "high" : "medium",
        detail: `Detected "${config.label}" language pattern (${matches.length} match(es)) — leverages the psychological principle of ${config.cialdini}.`,
      });
    }
  }

  // Basic readability / anomaly signals
  const sentenceCount = (bodyText.match(/[.!?]+/g) || []).length || 1;
  const wordCount = (bodyText.match(/\S+/g) || []).length;
  const avgWordsPerSentence = Math.round(wordCount / sentenceCount);
  const exclamationDensity = (bodyText.match(/!/g) || []).length / Math.max(sentenceCount, 1);

  if (exclamationDensity > 0.3) {
    findings.push({
      type: "excessive_exclamation",
      severity: "low",
      detail: "Unusually high density of exclamation marks — associated with manufactured urgency in phishing copy.",
    });
    tacticScore += 5;
  }

  const contentRiskScore = Math.min(100, tacticScore);

  return {
    matchedTactics,
    findings,
    metrics: { wordCount, sentenceCount, avgWordsPerSentence, exclamationDensity: Number(exclamationDensity.toFixed(2)) },
    contentRiskScore,
  };
}

module.exports = { analyzeContent, TACTIC_PATTERNS };
