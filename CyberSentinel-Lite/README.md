# CyberSentinel Lite

A mini Cybersecurity Governance, Risk and Compliance (GRC) Management
Platform. Built as a B.Tech Cybersecurity capstone project.

It demonstrates asset management, risk assessment, ISO/IEC 27001:2022
inspired control assessment, evidence integrity with SHA-256, audit
logging and reporting, backed by a persistent SQLite database.

> **Disclaimer:** This is an academic prototype. It does **not** certify
> ISO 27001 compliance, and it is **not** production-grade security. Do not
> use it with real sensitive data or expose it to the internet without an
> independent security review.

## Features

- **Dashboard** - live counts of assets, risks by level, control
  assessment progress and recent audit activity.
- **Asset Management** - add, view, update and delete assets (Server,
  Endpoint, Application, Database, Network) with owner and criticality.
- **Risk Management** - risks with likelihood x impact scoring (1-5 each),
  levels Low / Medium / High / Critical, treatment plans, mitigation
  status and residual risk assessment.
- **Compliance Management** - 12 sample controls inspired by ISO/IEC
  27001:2022 Annex A, assessed as Implemented, Partially Implemented,
  Not Implemented or Not Applicable, with notes and completion statistics.
- **Evidence Management** - file upload with type and size validation,
  SHA-256 hash recorded at upload, per-file integrity verification and
  safe download.
- **Audit Logging** - append-only record of logins, asset/risk changes,
  control assessments, evidence uploads/verifications and report
  downloads. Audit records cannot be edited or deleted in the app.
- **Reporting** - risk and control summaries on screen, downloadable CSV
  reports and a printable view.

## Risk calculation

Inherent Risk Score = Likelihood x Impact (each 1 to 5).

| Score | Level    |
|-------|----------|
| 1-4   | Low      |
| 5-9   | Medium   |
| 10-16 | High     |
| 17-25 | Critical |

Residual risk uses the same formula and levels after treatment.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

Then open http://127.0.0.1:5000 in a browser.

On first run the app creates `cybersentinel.db` and seeds it with sample
data: 6 assets, 6 risks covering all four levels, 12 controls (3 already
assessed) and the demo administrator account.

### Demo login

- Username: `admin`
- Password: `Admin@123`

Change the demo password after your first login in a real deployment, and
set a strong secret key:

```bash
export CYBERSENTINEL_SECRET_KEY="a-long-random-secret"
```

## Running the tests

```bash
.venv/bin/python -m pytest tests/ -v
```

Tests use a temporary database, so they never touch `cybersentinel.db`.
They cover risk-level boundaries, the likelihood x impact calculation,
SHA-256 evidence hashing, login failure, unauthenticated access,
append-only audit logging and CSV report downloads.

## Project structure

```
cybersentinel-lite/
  app.py                  Single-file Flask application
  requirements.txt
  README.md
  cybersentinel.db        SQLite database (created on first run)
  uploads/                Uploaded evidence files (UUID-prefixed names)
  static/css/style.css    Custom styles (Bootstrap 5 vendored locally in static/vendor, so the app works offline with no CDN)
  templates/              Jinja2 templates (base, login, dashboard,
                          assets, risks, compliance, evidence,
                          audit, reports, error)
  tests/test_app.py       pytest test suite
```

## Security notes

- Passwords are hashed with Werkzeug PBKDF2-SHA256
  (`generate_password_hash` / `check_password_hash`). Password hashes are
  never returned in any response.
- Every route except login requires a server-side session
  (`login_required` decorator).
- All SQL uses parameterized queries (stdlib `sqlite3`); no SQL is built
  from string formatting.
- All form input is validated server-side: required fields, allowed
  categories/statuses and 1-5 ranges for likelihood and impact.
- Evidence uploads are limited to PDF, TXT, CSV, PNG, JPG, DOCX and XLSX
  files up to 5 MB. Filenames are sanitized with `secure_filename` and
  stored with a UUID prefix, so uploads cannot overwrite files or escape
  the uploads directory. Downloads serve only the exact stored filename
  recorded in the database.
- Sessions last 30 minutes, cookies are HttpOnly and SameSite=Lax.
  `SESSION_COOKIE_SECURE` is False only because this is a local HTTP
  demo; set it to True behind HTTPS.
- The secret key comes from the `CYBERSENTINEL_SECRET_KEY` environment
  variable when set, otherwise a random key is generated per process
  (which invalidates existing sessions on restart).
- Important actions are written to an append-only audit log; the
  application has no route or function that edits or deletes audit rows.

## Screenshots

Take screenshots after running the app locally: Dashboard, Assets,
Risks, Compliance, Evidence, Audit Log and Reports pages.
