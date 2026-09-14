const crypto = require("crypto");
const fs = require("fs");

/**
 * Compute SHA256 of a string (email body, header text, etc.)
 */
function sha256OfString(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

/**
 * Compute SHA256 of a file on disk (attachments) - streamed so large files don't blow memory.
 */
function sha256OfFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

/**
 * Build a chain-of-custody record for an artifact.
 */
function buildCustodyRecord(label, hash, extra = {}) {
  return {
    label,
    sha256: hash,
    hashedAt: new Date().toISOString(),
    ...extra,
  };
}

module.exports = { sha256OfString, sha256OfFile, buildCustodyRecord };
