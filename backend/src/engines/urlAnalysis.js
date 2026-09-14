/**
 * urlAnalysis.js
 * Extracts URLs (and decoded QR-code payload URLs) from content, runs heuristic
 * red-flag scoring, and — if API keys are configured — enriches with real
 * reputation data from VirusTotal / Google Safe Browsing / URLScan.io.
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { levenshtein } = require("./headerAnalysis");

const URL_REGEX = /\bhttps?:\/\/[^\s"'<>\)\]]+/gi;

const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "loan"];
const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];
const HIGH_VALUE_BRANDS = [
  "microsoft", "office365", "outlook", "google", "gmail", "paypal", "apple",
  "amazon", "netflix", "bankofamerica", "wellsfargo", "chase", "dropbox",
  "docusign", "adobe", "linkedin", "facebook", "instagram",
];

function extractUrlsFromText(text = "") {
  return [...new Set((text.match(URL_REGEX) || []).map((u) => u.trim()))];
}

/** Extract <a href> targets from HTML body too, since visible text != actual href (classic phishing trick) */
function extractUrlsFromHtml(html = "") {
  const results = [];
  try {
    const $ = cheerio.load(html);
    $("a").each((_, el) => {
      const href = $(el).attr("href");
      const text = $(el).text().trim();
      if (href && href.startsWith("http")) {
        results.push({ href, displayText: text });
      }
    });
  } catch (_) {
    /* not valid HTML, ignore */
  }
  return results;
}

function domainOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Heuristic red-flag scoring for a single URL (0-100, higher = more suspicious)
 */
function heuristicScoreUrl(url, displayText = null) {
  const findings = [];
  let score = 0;
  const domain = domainOf(url);
  if (!domain) {
    return { url, score: 50, findings: [{ type: "unparseable_url", severity: "medium", detail: "URL could not be parsed." }] };
  }

  const tld = domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 20;
    findings.push({ type: "suspicious_tld", severity: "medium", detail: `Uses a TLD (.${tld}) commonly abused for disposable phishing infrastructure.` });
  }

  if (URL_SHORTENERS.some((s) => domain.includes(s))) {
    score += 15;
    findings.push({ type: "url_shortener", severity: "medium", detail: "URL uses a shortening service, which obscures the true destination." });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    score += 30;
    findings.push({ type: "ip_literal_url", severity: "high", detail: "URL host is a raw IP address rather than a domain name — very rarely legitimate in corporate mail." });
  }

  if ((domain.match(/-/g) || []).length >= 3) {
    score += 10;
    findings.push({ type: "excessive_hyphens", severity: "low", detail: "Domain contains an unusually high number of hyphens, a common typosquatting pattern." });
  }

  if (domain.length > 30) {
    score += 8;
    findings.push({ type: "long_domain", severity: "low", detail: "Unusually long domain name, often used to bury a real brand name inside a longer malicious string." });
  }

  // Brand impersonation / homoglyph check
  for (const brand of HIGH_VALUE_BRANDS) {
    if (domain.includes(brand)) continue; // exact-ish contains -> could be legit subdomain, skip flatly flagging
    const base = domain.split(".")[0];
    const dist = levenshtein(base, brand);
    if (dist > 0 && dist <= 2 && base.length >= brand.length - 2) {
      score += 35;
      findings.push({
        type: "brand_lookalike",
        severity: "critical",
        detail: `Domain "${domain}" closely resembles the trusted brand "${brand}" (edit distance ${dist}) — likely typosquat/homoglyph impersonation.`,
      });
    }
  }

  // Mismatch between visible link text and actual href (classic HTML phishing trick)
  if (displayText && /https?:\/\//i.test(displayText)) {
    const shownDomain = domainOf(displayText.match(URL_REGEX)?.[0] || "");
    if (shownDomain && shownDomain !== domain) {
      score += 30;
      findings.push({
        type: "href_text_mismatch",
        severity: "critical",
        detail: `Displayed link text shows "${shownDomain}" but the actual hyperlink points to "${domain}" — the visible text is deceptive.`,
      });
    }
  }

  if (url.includes("@")) {
    score += 20;
    findings.push({ type: "userinfo_trick", severity: "high", detail: "URL contains an '@' symbol before the real host, a classic trick to disguise the true destination (e.g. https://paypal.com@evil.tld/)." });
  }

  return { url, domain, score: Math.min(score, 100), findings };
}

/** VirusTotal URL reputation lookup (requires VT_API_KEY) */
async function vtLookupUrl(url) {
  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return { available: false };
  try {
    const urlId = Buffer.from(url).toString("base64").replace(/=+$/, "");
    const resp = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
      timeout: 8000,
    });
    const stats = resp.data?.data?.attributes?.last_analysis_stats || {};
    return {
      available: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
    };
  } catch (e) {
    return { available: false, error: "VirusTotal lookup failed or URL not yet indexed." };
  }
}

/** Google Safe Browsing check (requires SAFE_BROWSING_API_KEY) */
async function safeBrowsingLookup(urls) {
  const apiKey = process.env.SAFE_BROWSING_API_KEY;
  if (!apiKey || urls.length === 0) return { available: false };
  try {
    const resp = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: "phishguard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.map((u) => ({ url: u })),
        },
      },
      { timeout: 8000 }
    );
    return { available: true, matches: resp.data?.matches || [] };
  } catch (e) {
    return { available: false, error: "Safe Browsing lookup failed." };
  }
}

/**
 * Decode a QR code image buffer and return payload URL(s), then score them the same way.
 * Uses jimp + jsqr (pure JS, no native deps).
 */
async function analyzeQrCodeImage(imageBuffer) {
  const Jimp = require("jimp");
  const jsQR = require("jsqr");
  try {
    const image = await Jimp.read(imageBuffer);
    const { data, width, height } = image.bitmap;
    const code = jsQR(new Uint8ClampedArray(data), width, height);
    if (!code) return { found: false };
    const payload = code.data;
    const isUrl = /^https?:\/\//i.test(payload);
    return {
      found: true,
      payload,
      isUrl,
      analysis: isUrl ? heuristicScoreUrl(payload) : null,
      warning: !isUrl
        ? null
        : "QR-code phishing ('quishing') often bypasses email link scanners entirely since the malicious URL only exists as pixel data.",
    };
  } catch (e) {
    return { found: false, error: "Could not decode image as QR code." };
  }
}

/**
 * Full pipeline: given raw text + optional HTML body, extract every URL,
 * dedupe, heuristically score, and enrich with any configured reputation APIs.
 */
async function analyzeContentUrls(plainText = "", html = "") {
  const plainUrls = extractUrlsFromText(plainText);
  const htmlLinks = extractUrlsFromHtml(html);

  const combined = new Map();
  plainUrls.forEach((u) => combined.set(u, { url: u, displayText: null }));
  htmlLinks.forEach((l) => combined.set(l.href, { url: l.href, displayText: l.displayText }));

  const results = [];
  for (const { url, displayText } of combined.values()) {
    const heuristic = heuristicScoreUrl(url, displayText);
    const [vt, sb] = await Promise.all([vtLookupUrl(url), safeBrowsingLookup([url])]);

    let finalScore = heuristic.score;
    if (vt.available && vt.malicious > 0) finalScore = Math.max(finalScore, 90);
    if (sb.available && sb.matches?.length > 0) finalScore = Math.max(finalScore, 95);

    results.push({
      ...heuristic,
      displayText,
      verifiedIntel: {
        virusTotal: vt,
        safeBrowsing: sb,
      },
      finalScore,
      verdict: finalScore >= 70 ? "malicious" : finalScore >= 35 ? "suspicious" : "likely_benign",
    });
  }

  return results.sort((a, b) => b.finalScore - a.finalScore);
}

module.exports = { extractUrlsFromText, extractUrlsFromHtml, heuristicScoreUrl, analyzeQrCodeImage, analyzeContentUrls, vtLookupUrl, safeBrowsingLookup };
