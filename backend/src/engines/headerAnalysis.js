/**
 * headerAnalysis.js
 * Parses raw email headers and produces a structured, scored analysis.
 * All findings are heuristic unless clearly derived from a passed/failed
 * auth mechanism (SPF/DKIM/DMARC), which is deterministic from the header text.
 */

const { simpleParser } = require("mailparser");

function extractAuthResults(rawHeaders) {
  const authHeader =
    rawHeaders.match(/Authentication-Results:.*(?:\n[ \t].*)*/gi) || [];
  const joined = authHeader.join(" ");

  const spf = /spf=(\w+)/i.exec(joined)?.[1]?.toLowerCase() || "none";
  const dkim = /dkim=(\w+)/i.exec(joined)?.[1]?.toLowerCase() || "none";
  const dmarc = /dmarc=(\w+)/i.exec(joined)?.[1]?.toLowerCase() || "none";

  return { spf, dkim, dmarc, raw: joined || null };
}

function domainOf(addr = "") {
  const match = /@([^\s>]+)/.exec(addr);
  return match ? match[1].toLowerCase() : null;
}

function levenshtein(a, b) {
  const m = a.length,
    n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Detects homoglyph / lookalike domain spoofing by comparing From/Reply-To/Return-Path
 * domains against each other and flags small edit-distance tricks (e.g. paypa1.com, micros0ft.com)
 */
function detectDomainSpoofing(fromAddr, replyToAddr, returnPathAddr) {
  const findings = [];
  const fromDomain = domainOf(fromAddr);
  const replyDomain = domainOf(replyToAddr);
  const returnDomain = domainOf(returnPathAddr);

  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    findings.push({
      type: "reply_to_mismatch",
      severity: "high",
      detail: `From domain (${fromDomain}) differs from Reply-To domain (${replyDomain}). Classic BEC/phishing technique to redirect victim replies to an attacker-controlled mailbox.`,
    });
  }

  if (fromDomain && returnDomain && fromDomain !== returnDomain) {
    const dist = levenshtein(fromDomain, returnDomain);
    findings.push({
      type: "return_path_mismatch",
      severity: dist <= 3 ? "critical" : "medium",
      detail: `From domain (${fromDomain}) differs from envelope Return-Path domain (${returnDomain})${
        dist <= 3
          ? " — domains are visually/structurally similar, suggesting a lookalike/typosquat domain."
          : "."
      }`,
    });
  }

  return findings;
}

function analyzeReceivedChain(rawHeaders) {
  const received = rawHeaders.match(/Received:.*(?:\n[ \t].*)*/gi) || [];
  const hopCount = received.length;
  const ips = [];
  received.forEach((line) => {
    const ipMatches = line.match(
      /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{6,}\b/g
    );
    if (ipMatches) ips.push(...ipMatches);
  });

  const findings = [];
  if (hopCount === 0) {
    findings.push({
      type: "missing_received_chain",
      severity: "high",
      detail:
        "No Received: headers found. This is unusual for legitimate mail and may indicate a forged or manually crafted header block.",
    });
  } else if (hopCount === 1) {
    findings.push({
      type: "minimal_hop_count",
      severity: "medium",
      detail:
        "Only a single mail hop detected. Legitimate corporate mail typically transits multiple relays; a single hop can indicate direct injection from a script or open relay.",
    });
  }

  return { hopCount, ips: [...new Set(ips)], findings };
}

function scoreAuthResults({ spf, dkim, dmarc }) {
  let score = 0;
  const findings = [];

  if (spf === "fail" || spf === "softfail") {
    score += spf === "fail" ? 25 : 12;
    findings.push({
      type: "spf_" + spf,
      severity: spf === "fail" ? "critical" : "medium",
      detail: `SPF check result: ${spf.toUpperCase()}. The sending server is not authorized to send mail for this domain.`,
    });
  } else if (spf === "none") {
    score += 8;
    findings.push({
      type: "spf_none",
      severity: "low",
      detail: "No SPF record evaluation found in headers — could not verify sender authorization.",
    });
  }

  if (dkim === "fail" || dkim === "none") {
    score += dkim === "fail" ? 25 : 10;
    findings.push({
      type: "dkim_" + dkim,
      severity: dkim === "fail" ? "critical" : "low",
      detail:
        dkim === "fail"
          ? "DKIM signature verification FAILED — message content or headers may have been tampered with in transit, or signature was forged."
          : "No DKIM signature present — message authenticity cannot be cryptographically verified.",
    });
  }

  if (dmarc === "fail") {
    score += 25;
    findings.push({
      type: "dmarc_fail",
      severity: "critical",
      detail:
        "DMARC alignment FAILED. The domain's own policy indicates this message should be treated as spoofed unless explicitly overridden by mail flow rules.",
    });
  }

  return { score: Math.min(score, 100), findings };
}

/**
 * Main entry point.
 * @param {string} rawEmailSource - full raw email including headers (.eml content or pasted headers)
 */
async function analyzeHeaders(rawEmailSource) {
  const parsed = await simpleParser(rawEmailSource).catch(() => null);

  const fromAddr = parsed?.from?.value?.[0]?.address || "";
  const replyToAddr = parsed?.replyTo?.value?.[0]?.address || "";
  // mailparser doesn't expose Return-Path directly in all versions; fall back to regex
  const returnPathMatch = /Return-Path:\s*<?([^>\s]+)>?/i.exec(rawEmailSource);
  const returnPathAddr = returnPathMatch ? returnPathMatch[1] : "";

  const auth = extractAuthResults(rawEmailSource);
  const authScoring = scoreAuthResults(auth);
  const spoofFindings = detectDomainSpoofing(fromAddr, replyToAddr, returnPathAddr);
  const receivedChain = analyzeReceivedChain(rawEmailSource);

  const allFindings = [
    ...authScoring.findings,
    ...spoofFindings,
    ...receivedChain.findings,
  ];

  // Weighted composite header-risk score (0-100)
  const spoofPenalty = spoofFindings.reduce(
    (acc, f) => acc + (f.severity === "critical" ? 25 : f.severity === "high" ? 15 : 8),
    0
  );
  const chainPenalty = receivedChain.findings.reduce(
    (acc, f) => acc + (f.severity === "high" ? 10 : 5),
    0
  );
  const headerRiskScore = Math.min(
    100,
    Math.round(authScoring.score * 0.6 + spoofPenalty * 0.3 + chainPenalty * 0.1)
  );

  return {
    identity: {
      from: fromAddr,
      replyTo: replyToAddr || null,
      returnPath: returnPathAddr || null,
      subject: parsed?.subject || null,
      date: parsed?.date || null,
    },
    authentication: auth,
    receivedChain: {
      hopCount: receivedChain.hopCount,
      relayIps: receivedChain.ips,
    },
    findings: allFindings,
    headerRiskScore,
  };
}

module.exports = { analyzeHeaders, levenshtein, domainOf };
