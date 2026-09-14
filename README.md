# PhishForensics — Phishing Incident Analysis Platform

A working local web app for cybersecurity consultants to analyze phishing incidents
(email + attachments + employee questionnaire) and generate a detailed,
password-protected PDF report with CVSS scoring, OWASP/MITRE mapping,
psychological/forensic breakdown, and mitigation recommendations.

## What's real vs. heuristic (read this first)

Being upfront so your client reports are defensible:

- **Deterministic / verified:** SPF/DKIM/DMARC parsing, SHA256 hashing, filename/extension
  red flags, homoglyph/lookalike domain math, HTML href-vs-display-text mismatch, QR decode.
- **Heuristic (flags candidates, not certainties):** NLP persuasion-tactic detection, the
  LSB steganography screen (a real statistical signal, but not a substitute for dedicated
  stego tools like StegExpose/zsteg), CVSS vector derivation (this maps a social-engineering
  incident onto CVSS 3.1's fields — a legitimate consulting technique, but a judgment call,
  not an official CVE score).
- **Real threat intel (only if you provide API keys):** VirusTotal file/URL reputation,
  Google Safe Browsing. Without keys, these sections just report "not available" instead of
  guessing.
- **Psychological analysis** is pattern-based (Cialdini's principles / SANS human-risk
  categories) from questionnaire answers — it's a training-focused behavioral analysis,
  not a clinical assessment of any employee.

## Setup

### 1. Backend

```bash
cd backend
npm install
cp .env.example .env
# edit .env and add any API keys you have (VirusTotal, Safe Browsing, etc.)
npm start
```

Backend runs on `http://localhost:4000` by default.

**Password-protected PDF export requires `qpdf` installed on your system:**
- macOS: `brew install qpdf`
- Ubuntu/Debian: `sudo apt-get install qpdf`
- Windows: install via [qpdf releases](https://github.com/qpdf/qpdf/releases) and add to PATH

If `qpdf` isn't found, the report still generates — just without password protection —
and the API response tells you so.

### 2. Frontend

The backend serves the frontend automatically — no separate frontend server or
build step is needed. After starting the backend, open:

`http://localhost:4000`

The frontend can still be opened as a static site for development, but set the
"Case backend URL" field to the running backend URL in that mode.

```bash
cd frontend
# Optional: use a separate static server during frontend-only development:
npx serve .
```

When served by the backend, the default backend URL is already correct.

## Using it

**Full Case Analysis tab** — paste the raw phishing email (with headers), optionally
separate plain-text/HTML body, drop in attachments and a QR code image if relevant,
add each affected employee's questionnaire answers, then hit Analyze. Review the
on-screen report, then generate the password-protected PDF.

**Quick Triage tab** — for one-off checks: a single URL, a raw header block, or a
single attachment/image, without building a full case.

**Questionnaire tab** — download the JSON template to send to employees or use as
an interview script; upload completed responses to auto-populate the case form.

## Project structure

```
backend/
  src/
    engines/
      headerAnalysis.js       - SPF/DKIM/DMARC, spoofing, routing anomalies
      urlAnalysis.js           - URL/QR extraction, red-flag scoring, VT/SafeBrowsing lookups
      contentAnalysis.js       - NLP persuasion-tactic detection
      attachmentAnalysis.js    - metadata, stego screen, VT file-hash lookup
      riskScoring.js           - CVSS derivation, OWASP/MITRE mapping, composite severity
      psychAnalysis.js         - per-employee + org-level psychological/forensic analysis
      mitigationEngine.js      - technical/policy/training recommendations
      reportGenerator.js       - PDF report + charts + password protection
    utils/hashUtils.js         - SHA256 chain-of-custody helpers
    server.js                  - Express API
frontend/
  index.html, app.js           - the web UI (vanilla JS, Chart.js from CDN)
```

## API reference (quick)

- `POST /api/case/analyze` (multipart) — full pipeline, returns the `incident` JSON
- `POST /api/case/report` (JSON: `{incident, password}`) — generates the PDF, returns a download URL + SHA256
- `GET /api/case/report/download?file=...` — serves the generated PDF
- `POST /api/triage/url`, `/api/triage/headers`, `/api/triage/attachment`, `/api/triage/qr` — standalone quick checks
- `GET /api/questionnaire/template` — downloadable JSON questionnaire template

## Extending it further

Natural next additions, whenever you want them:
- Word/.docx export alongside PDF
- A results history/database (currently each case is stateless per request)
- Auth (this has none right now — don't expose the backend on the open internet as-is)
- URLScan.io / AbuseIPDB integrations (stubs are easy to add next to the VT calls in `urlAnalysis.js`)
