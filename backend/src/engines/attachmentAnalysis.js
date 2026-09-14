/**
 * attachmentAnalysis.js
 * Metadata extraction (EXIF/doc properties), macro-in-office-doc heuristic,
 * basic LSB steganography signal check for images, and optional VirusTotal
 * file-hash reputation lookup.
 *
 * IMPORTANT LIMITATION (documented in report output): true steganography
 * detection and malware sandboxing require dedicated statistical/forensic
 * tooling (e.g. StegExpose, chi-square LSB analysis at scale, or a real
 * detonation sandbox). What's implemented here is a first-pass statistical
 * screen that flags candidates for deeper manual/tool-based forensic review —
 * it is NOT a definitive stego verdict.
 */

const fs = require("fs");
const path = require("path");
const axios = require("axios");
const exifr = require("exifr");
const { sha256OfFile } = require("../utils/hashUtils");

const MACRO_ENABLED_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm"];
const HIGH_RISK_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".hta", ".jar", ".msi", ".ps1", ".lnk"];
const DOUBLE_EXTENSION_REGEX = /\.\w{2,5}\.(exe|scr|js|vbs|bat|cmd|hta|jar|pdf|docx?|xlsx?)$/i;

/** Simple chi-square-style test on LSBs of pixel data as a stego "candidate" flag, not a verdict. */
async function lsbAnomalyScreen(filePath) {
  try {
    const Jimp = require("jimp");
    const image = await Jimp.read(filePath);
    const { data } = image.bitmap;
    let lsbOnes = 0;
    let sampled = 0;
    for (let i = 0; i < data.length; i += 4) {
      // sample the red channel LSB
      lsbOnes += data[i] & 1;
      sampled++;
      if (sampled >= 200000) break; // cap sampling for performance
    }
    const ratio = lsbOnes / sampled;
    // In a "clean" natural image LSBs are close to random ~0.5; extreme skew OR
    // suspiciously perfect 0.5 can both indicate embedded payloads depending on
    // the stego method, so we flag deviation from the *expected natural variance* instead.
    const deviation = Math.abs(ratio - 0.5);
    const flagged = deviation < 0.002 || deviation > 0.15;
    return {
      performed: true,
      lsbOneRatio: Number(ratio.toFixed(4)),
      sampledPixels: sampled,
      flaggedAsCandidate: flagged,
      note: flagged
        ? "LSB distribution deviates from typical natural-image variance — candidate for deeper steganalysis (e.g. StegExpose, zsteg). This is a screening signal, not proof of hidden data."
        : "LSB distribution within expected natural-image range. Does not rule out steganography using non-LSB techniques.",
    };
  } catch (e) {
    return { performed: false, reason: "File is not a readable raster image or could not be processed." };
  }
}

async function extractMetadata(filePath, originalName) {
  const ext = path.extname(originalName).toLowerCase();
  const stats = fs.statSync(filePath);
  const base = {
    originalName,
    extension: ext,
    sizeBytes: stats.size,
    createdOnDisk: stats.birthtime,
  };

  if ([".jpg", ".jpeg", ".png", ".tiff", ".heic"].includes(ext)) {
    try {
      const exif = await exifr.parse(filePath, true);
      return { ...base, type: "image", exif: exif || null };
    } catch {
      return { ...base, type: "image", exif: null };
    }
  }

  return { ...base, type: "other" };
}

function analyzeFilenameRisk(originalName) {
  const findings = [];
  const ext = path.extname(originalName).toLowerCase();

  if (HIGH_RISK_EXTENSIONS.includes(ext)) {
    findings.push({
      type: "high_risk_extension",
      severity: "critical",
      detail: `File extension "${ext}" is a high-risk executable/script type rarely legitimate as an unsolicited email attachment.`,
    });
  }

  if (MACRO_ENABLED_EXTENSIONS.includes(ext)) {
    findings.push({
      type: "macro_enabled_office_doc",
      severity: "high",
      detail: `Macro-enabled Office format (${ext}) detected — a leading vector for maldoc payload delivery (VBA macro droppers).`,
    });
  }

  if (DOUBLE_EXTENSION_REGEX.test(originalName)) {
    findings.push({
      type: "double_extension",
      severity: "critical",
      detail: `Filename "${originalName}" uses a double extension trick to disguise the true file type (e.g. invoice.pdf.exe).`,
    });
  }

  if (/\s{2,}/.test(originalName) || /[\u200B-\u200D\uFEFF]/.test(originalName)) {
    findings.push({
      type: "hidden_unicode_or_spacing",
      severity: "high",
      detail: "Filename contains hidden unicode characters or abnormal spacing, sometimes used to hide the real extension from view.",
    });
  }

  return findings;
}

async function vtLookupFileHash(sha256) {
  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return { available: false };
  try {
    const resp = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
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
    return { available: false, error: "Hash not found in VirusTotal or lookup failed (file may be unseen/zero-day)." };
  }
}

/**
 * Full pipeline for one uploaded attachment.
 */
async function analyzeAttachment(filePath, originalName) {
  const sha256 = await sha256OfFile(filePath);
  const metadata = await extractMetadata(filePath, originalName);
  const filenameFindings = analyzeFilenameRisk(originalName);
  const ext = path.extname(originalName).toLowerCase();

  let stegoScreen = { performed: false, reason: "Not an image file." };
  if ([".jpg", ".jpeg", ".png", ".bmp"].includes(ext)) {
    stegoScreen = await lsbAnomalyScreen(filePath);
  }

  const vt = await vtLookupFileHash(sha256);

  const allFindings = [...filenameFindings];
  if (stegoScreen.flaggedAsCandidate) {
    allFindings.push({
      type: "stego_candidate",
      severity: "medium",
      detail: stegoScreen.note,
    });
  }
  if (vt.available && vt.malicious > 0) {
    allFindings.push({
      type: "vt_malicious_hash",
      severity: "critical",
      detail: `VirusTotal: ${vt.malicious}/${vt.totalEngines} engines flag this exact file hash as malicious.`,
    });
  }

  const severityWeight = { critical: 30, high: 20, medium: 10, low: 4 };
  const attachmentRiskScore = Math.min(
    100,
    allFindings.reduce((acc, f) => acc + (severityWeight[f.severity] || 0), 0)
  );

  return {
    sha256,
    metadata,
    stegoScreen,
    virusTotal: vt,
    findings: allFindings,
    attachmentRiskScore,
  };
}

module.exports = { analyzeAttachment, lsbAnomalyScreen, analyzeFilenameRisk, vtLookupFileHash };
