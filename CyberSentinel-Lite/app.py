"""
CyberSentinel Lite - Mini Cybersecurity GRC Management Platform.

B.Tech Cybersecurity Capstone Project (academic prototype).

Stack: Flask + SQLite (stdlib sqlite3, parameterized queries only).
Security: Werkzeug password hashing, server-side authorization on every
route, input validation, safe file uploads (extension/size checks,
secure_filename, UUID-prefixed storage), SHA-256 evidence integrity,
append-only audit log.

This application does NOT certify ISO 27001 compliance and is not
production-grade security. It is a local demonstration prototype.
"""

import csv
import hashlib
import io
import os
import sqlite3
import uuid
from datetime import datetime, timedelta

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybersentinel.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

ALLOWED_EXTENSIONS = {"pdf", "txt", "csv", "png", "jpg", "jpeg", "docx", "xlsx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

ASSET_CATEGORIES = ["Server", "Endpoint", "Application", "Database", "Network"]
CRITICALITIES = ["Low", "Medium", "High", "Critical"]
RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
MITIGATION_STATUSES = ["Open", "In Progress", "Mitigated", "Accepted"]
CONTROL_STATUSES = [
    "Implemented",
    "Partially Implemented",
    "Not Implemented",
    "Not Applicable",
]

# 12 sample controls inspired by ISO/IEC 27001:2022 Annex A.
# Titles and descriptions follow the standard's control themes.
CONTROLS = [
    ("A.5.1", "Policies for information security",
     "Information security policy and topic-specific policies are defined, "
     "approved by management, published and communicated."),
    ("A.5.2", "Information security roles and responsibilities",
     "Information security roles and responsibilities are defined and "
     "allocated according to the needs of the organization."),
    ("A.5.3", "Segregation of duties",
     "Conflicting duties and conflicting areas of responsibility are "
     "segregated."),
    ("A.5.7", "Threat intelligence",
     "Information relating to information security threats is collected and "
     "analysed to produce threat intelligence."),
    ("A.5.10", "Acceptable use of information and other associated assets",
     "Rules for the acceptable use and procedures for handling information "
     "and other associated assets are identified, documented and implemented."),
    ("A.5.15", "Access control",
     "Rules to control physical and logical access to information and other "
     "associated assets are established and implemented."),
    ("A.5.19", "Supplier relationships",
     "Processes and procedures are defined and implemented to manage the "
     "information security risks associated with the use of suppliers' "
     "products or services."),
    ("A.5.23", "Information security for use of cloud services",
     "Processes for acquisition, use, management and exit from cloud "
     "services are established in accordance with the organization's "
     "information security requirements."),
    ("A.5.24", "Incident management planning and preparation",
     "The organization plans and prepares for managing information security "
     "incidents by defining, establishing and communicating incident "
     "management processes, roles and responsibilities."),
    ("A.8.2", "Privileged access rights",
     "The allocation and use of privileged access rights is restricted and "
     "managed."),
    ("A.8.3", "Information access restriction",
     "Access to information and other associated assets is restricted in "
     "accordance with the established topic-specific policy on access "
     "control."),
    ("A.8.5", "Secure authentication",
     "Secure authentication technologies and procedures are implemented "
     "based on information access restrictions and the topic-specific "
     "policy on access control."),
]

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "CYBERSENTINEL_SECRET_KEY"
) or os.urandom(24)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # local demo over HTTP only
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["DATABASE"] = DB_PATH
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def risk_level(score):
    """Return the risk level for an inherent or residual score (1-25)."""
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def compute_sha256(file_bytes):
    """Return the SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path=None):
    """Create tables and seed sample data if the tables are empty."""
    path = db_path or app.config["DATABASE"]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            owner TEXT NOT NULL,
            criticality TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            asset_id INTEGER NOT NULL REFERENCES assets(id),
            likelihood INTEGER NOT NULL,
            impact INTEGER NOT NULL,
            inherent_score INTEGER NOT NULL,
            level TEXT NOT NULL,
            treatment TEXT,
            mitigation_status TEXT NOT NULL,
            residual_likelihood INTEGER,
            residual_impact INTEGER,
            residual_score INTEGER,
            residual_level TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            clause TEXT NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id INTEGER UNIQUE NOT NULL REFERENCES controls(id),
            status TEXT NOT NULL,
            notes TEXT,
            assessed_by TEXT NOT NULL,
            assessed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            content_type TEXT,
            sha256 TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            related_risk_id INTEGER REFERENCES risks(id),
            uploaded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id INTEGER,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT
        );
        """
    )
    conn.commit()
    seed_data(conn)
    conn.close()


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def seed_data(conn):
    """Insert demo data only when the tables are empty. Idempotent."""
    now = _now()

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) "
            "VALUES (?, ?, ?)",
            ("admin", generate_password_hash("Admin@123"), now),
        )

    if conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0:
        assets = [
            ("Web Server", "Server",
             "Public-facing web server hosting the company portal.",
             "A. Sharma", "High"),
            ("HR Database", "Database",
             "Database storing employee records and payroll data.",
             "R. Verma", "Critical"),
            ("Finance Application", "Application",
             "Internal finance and invoicing application.",
             "S. Iyer", "High"),
            ("Employee Laptop Fleet", "Endpoint",
             "Standard issue laptops for all staff.",
             "IT Support", "Medium"),
            ("Perimeter Firewall", "Network",
             "Edge firewall protecting the corporate network.",
             "N. Patel", "Critical"),
            ("Backup Server", "Server",
             "Nightly backup server for critical systems.",
             "A. Sharma", "Medium"),
        ]
        for name, category, desc, owner, crit in assets:
            conn.execute(
                "INSERT INTO assets (name, category, description, owner, "
                "criticality, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, category, desc, owner, crit, now),
            )

    if conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 0:
        for code, title, desc in CONTROLS:
            conn.execute(
                "INSERT INTO controls (code, title, clause, description) "
                "VALUES (?, ?, ?, ?)",
                (code, title, "ISO/IEC 27001:2022 Annex A", desc),
            )

    if conn.execute("SELECT COUNT(*) FROM risks").fetchone()[0] == 0:
        # (title, description, asset_id, likelihood, impact,
        #  treatment, mitigation_status, residual_likelihood, residual_impact)
        risks = [
            ("Ransomware attack on HR database",
             "Ransomware could encrypt the HR database and expose or destroy "
             "employee records.",
             2, 5, 5,
             "Deploy endpoint detection and response, enforce offline "
             "backups and test restores quarterly.",
             "In Progress", 2, 4),
            ("Phishing leading to credential theft",
             "Staff may fall for phishing emails and disclose credentials "
             "for internal systems.",
             4, 4, 4,
             "Run phishing awareness training and enforce multi-factor "
             "authentication for all users.",
             "In Progress", 2, 3),
            ("Unpatched web server vulnerability",
             "Missing security patches on the public web server could allow "
             "remote exploitation.",
             1, 4, 3,
             "Apply patches within 14 days of release and scan weekly.",
             "Open", 2, 2),
            ("Insider misuse of finance application",
             "A privileged user could misuse finance application access to "
             "alter payment records.",
             3, 3, 3,
             "Enforce segregation of duties and review privileged access "
             "quarterly.",
             "Open", 2, 2),
            ("Firewall misconfiguration",
             "A firewall rule error could expose internal services to the "
             "internet.",
             5, 3, 3,
             "Peer-review all firewall changes and audit rules monthly.",
             "Mitigated", 1, 2),
            ("Backup failure leaves data unrecoverable",
             "If nightly backups fail silently, a system failure could "
             "cause permanent data loss.",
             6, 1, 2,
             "Monitor backup jobs daily and test a full restore monthly.",
             "In Progress", 1, 1),
        ]
        for (title, desc, asset_id, lik, imp, treatment, status,
             rlik, rimp) in risks:
            score = lik * imp
            rscore = rlik * rimp
            conn.execute(
                "INSERT INTO risks (title, description, asset_id, "
                "likelihood, impact, inherent_score, level, treatment, "
                "mitigation_status, residual_likelihood, residual_impact, "
                "residual_score, residual_level, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (title, desc, asset_id, lik, imp, score, risk_level(score),
                 treatment, status, rlik, rimp, rscore,
                 risk_level(rscore), now),
            )

    if conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0] == 0:
        assessments = [
            (1, "Implemented",
             "Information security policy approved and published on the "
             "intranet."),
            (2, "Implemented",
             "Roles and responsibilities documented in the security charter."),
            (6, "Partially Implemented",
             "Access control rules exist for core systems; review of legacy "
             "systems still pending."),
        ]
        for control_id, status, notes in assessments:
            conn.execute(
                "INSERT INTO assessments (control_id, status, notes, "
                "assessed_by, assessed_at) VALUES (?, ?, ?, ?, ?)",
                (control_id, status, notes, "admin", now),
            )

    if conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO audit_log (action, entity, entity_id, username, "
            "timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
            ("seed", "system", None, "admin", now,
             "Sample data seeded on first run."),
        )
        conn.execute(
            "INSERT INTO audit_log (action, entity, entity_id, username, "
            "timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
            ("seed", "system", None, "admin", now,
             "Demo administrator account created."),
        )

    conn.commit()


def log_audit(action, entity, entity_id, username, details=""):
    """Append one row to the audit log. There is no update or delete path."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (action, entity, entity_id, username, "
        "timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
        (action, entity, entity_id, username, _now(), details),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html"), 400
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["username"] = user["username"]
            log_audit("login", "user", user["id"], user["username"],
                      "User logged in.")
            flash("Welcome back, %s." % user["username"], "success")
            next_page = request.args.get("next") or url_for("dashboard")
            if not next_page.startswith("/"):
                next_page = url_for("dashboard")
            return redirect(next_page)
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    username = session.get("username", "unknown")
    log_audit("logout", "user", None, username, "User logged out.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    total_assets = db.execute(
        "SELECT COUNT(*) FROM assets").fetchone()[0]
    total_risks = db.execute(
        "SELECT COUNT(*) FROM risks").fetchone()[0]
    level_rows = db.execute(
        "SELECT level, COUNT(*) AS c FROM risks GROUP BY level").fetchall()
    level_counts = {row["level"]: row["c"] for row in level_rows}
    for level in RISK_LEVELS:
        level_counts.setdefault(level, 0)

    total_controls = db.execute(
        "SELECT COUNT(*) FROM controls").fetchone()[0]
    assessed = db.execute(
        "SELECT COUNT(*) FROM assessments").fetchone()[0]
    status_rows = db.execute(
        "SELECT status, COUNT(*) AS c FROM assessments GROUP BY status"
    ).fetchall()
    status_counts = {row["status"]: row["c"] for row in status_rows}
    for status in CONTROL_STATUSES:
        status_counts.setdefault(status, 0)
    pct_complete = (
        round(assessed * 100 / total_controls) if total_controls else 0
    )

    recent = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 10").fetchall()
    return render_template(
        "dashboard.html",
        total_assets=total_assets,
        total_risks=total_risks,
        level_counts=level_counts,
        total_controls=total_controls,
        assessed=assessed,
        pct_complete=pct_complete,
        status_counts=status_counts,
        recent=recent,
    )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@app.route("/assets")
@login_required
def assets_list():
    db = get_db()
    assets = db.execute(
        "SELECT * FROM assets ORDER BY name").fetchall()
    return render_template("assets.html", assets=assets)


def _validate_asset_form(form):
    name = form.get("name", "").strip()
    category = form.get("category", "").strip()
    description = form.get("description", "").strip()
    owner = form.get("owner", "").strip()
    criticality = form.get("criticality", "").strip()
    if not name:
        return None, "Asset name is required."
    if len(name) > 120:
        return None, "Asset name must be 120 characters or fewer."
    if category not in ASSET_CATEGORIES:
        return None, "Invalid asset category."
    if not owner:
        return None, "Asset owner is required."
    if criticality not in CRITICALITIES:
        return None, "Invalid criticality."
    return {
        "name": name, "category": category, "description": description,
        "owner": owner, "criticality": criticality,
    }, None


@app.route("/assets/add", methods=["GET", "POST"])
@login_required
def asset_add():
    if request.method == "POST":
        data, error = _validate_asset_form(request.form)
        if error:
            flash(error, "danger")
            return render_template(
                "asset_form.html", asset=None,
                categories=ASSET_CATEGORIES, criticalities=CRITICALITIES,
                form_data=request.form), 400
        db = get_db()
        cur = db.execute(
            "INSERT INTO assets (name, category, description, owner, "
            "criticality, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (data["name"], data["category"], data["description"],
             data["owner"], data["criticality"], _now()),
        )
        db.commit()
        log_audit("create", "asset", cur.lastrowid,
                  session["username"], "Asset '%s' created." % data["name"])
        flash("Asset added.", "success")
        return redirect(url_for("assets_list"))
    return render_template(
        "asset_form.html", asset=None, categories=ASSET_CATEGORIES,
        criticalities=CRITICALITIES, form_data=None)


@app.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
def asset_edit(asset_id):
    db = get_db()
    asset = db.execute(
        "SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if asset is None:
        abort(404)
    if request.method == "POST":
        data, error = _validate_asset_form(request.form)
        if error:
            flash(error, "danger")
            return render_template(
                "asset_form.html", asset=asset,
                categories=ASSET_CATEGORIES, criticalities=CRITICALITIES,
                form_data=request.form), 400
        db.execute(
            "UPDATE assets SET name = ?, category = ?, description = ?, "
            "owner = ?, criticality = ? WHERE id = ?",
            (data["name"], data["category"], data["description"],
             data["owner"], data["criticality"], asset_id),
        )
        db.commit()
        log_audit("update", "asset", asset_id, session["username"],
                  "Asset '%s' updated." % data["name"])
        flash("Asset updated.", "success")
        return redirect(url_for("assets_list"))
    return render_template(
        "asset_form.html", asset=asset, categories=ASSET_CATEGORIES,
        criticalities=CRITICALITIES, form_data=None)


@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def asset_delete(asset_id):
    db = get_db()
    asset = db.execute(
        "SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if asset is None:
        abort(404)
    linked = db.execute(
        "SELECT COUNT(*) FROM risks WHERE asset_id = ?",
        (asset_id,)).fetchone()[0]
    if linked:
        flash(
            "Cannot delete '%s': %d risk(s) still reference this asset. "
            "Delete or reassign those risks first."
            % (asset["name"], linked), "danger")
        return redirect(url_for("assets_list"))
    db.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    db.commit()
    log_audit("delete", "asset", asset_id, session["username"],
              "Asset '%s' deleted." % asset["name"])
    flash("Asset deleted.", "success")
    return redirect(url_for("assets_list"))


# ---------------------------------------------------------------------------
# Risks
# ---------------------------------------------------------------------------

def _parse_int(form, field):
    try:
        return int(form.get(field, ""))
    except (TypeError, ValueError):
        return None


def _validate_risk_form(form, db):
    title = form.get("title", "").strip()
    description = form.get("description", "").strip()
    asset_id = _parse_int(form, "asset_id")
    likelihood = _parse_int(form, "likelihood")
    impact = _parse_int(form, "impact")
    treatment = form.get("treatment", "").strip()
    mitigation_status = form.get("mitigation_status", "").strip()
    residual_likelihood = _parse_int(form, "residual_likelihood")
    residual_impact = _parse_int(form, "residual_impact")
    if not title:
        return None, "Risk title is required."
    if asset_id is None or db.execute(
            "SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        return None, "Please select a valid asset."
    if likelihood is None or not 1 <= likelihood <= 5:
        return None, "Likelihood must be a whole number from 1 to 5."
    if impact is None or not 1 <= impact <= 5:
        return None, "Impact must be a whole number from 1 to 5."
    if mitigation_status not in MITIGATION_STATUSES:
        return None, "Invalid mitigation status."
    # Residual values are optional; both must be given together if used.
    if (residual_likelihood is None) != (residual_impact is None):
        return None, ("Residual likelihood and residual impact must be "
                      "entered together, or both left blank.")
    if residual_likelihood is not None and not (
            1 <= residual_likelihood <= 5 and 1 <= residual_impact <= 5):
        return None, "Residual likelihood and impact must be from 1 to 5."
    score = likelihood * impact
    if residual_likelihood is not None:
        rscore = residual_likelihood * residual_impact
        rlevel = risk_level(rscore)
    else:
        rscore = None
        rlevel = None
    return {
        "title": title, "description": description, "asset_id": asset_id,
        "likelihood": likelihood, "impact": impact,
        "inherent_score": score, "level": risk_level(score),
        "treatment": treatment, "mitigation_status": mitigation_status,
        "residual_likelihood": residual_likelihood,
        "residual_impact": residual_impact,
        "residual_score": rscore, "residual_level": rlevel,
    }, None


@app.route("/risks")
@login_required
def risks_list():
    level = request.args.get("level", "").strip()
    db = get_db()
    if level and level in RISK_LEVELS:
        risks = db.execute(
            "SELECT r.*, a.name AS asset_name FROM risks r "
            "JOIN assets a ON a.id = r.asset_id WHERE r.level = ? "
            "ORDER BY r.inherent_score DESC, r.title",
            (level,)).fetchall()
    else:
        level = ""
        risks = db.execute(
            "SELECT r.*, a.name AS asset_name FROM risks r "
            "JOIN assets a ON a.id = r.asset_id "
            "ORDER BY r.inherent_score DESC, r.title").fetchall()
    return render_template(
        "risks.html", risks=risks, selected_level=level,
        levels=RISK_LEVELS)


@app.route("/risks/add", methods=["GET", "POST"])
@login_required
def risk_add():
    db = get_db()
    assets = db.execute("SELECT * FROM assets ORDER BY name").fetchall()
    if request.method == "POST":
        data, error = _validate_risk_form(request.form, db)
        if error:
            flash(error, "danger")
            return render_template(
                "risk_form.html", risk=None, assets=assets,
                mitigation_statuses=MITIGATION_STATUSES,
                form_data=request.form), 400
        cur = db.execute(
            "INSERT INTO risks (title, description, asset_id, likelihood, "
            "impact, inherent_score, level, treatment, mitigation_status, "
            "residual_likelihood, residual_impact, residual_score, "
            "residual_level, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (data["title"], data["description"], data["asset_id"],
             data["likelihood"], data["impact"], data["inherent_score"],
             data["level"], data["treatment"], data["mitigation_status"],
             data["residual_likelihood"], data["residual_impact"],
             data["residual_score"], data["residual_level"], _now()),
        )
        db.commit()
        log_audit("create", "risk", cur.lastrowid, session["username"],
                  "Risk '%s' created (score %d, %s)."
                  % (data["title"], data["inherent_score"], data["level"]))
        flash("Risk added.", "success")
        return redirect(url_for("risks_list"))
    return render_template(
        "risk_form.html", risk=None, assets=assets,
        mitigation_statuses=MITIGATION_STATUSES, form_data=None)


@app.route("/risks/<int:risk_id>/edit", methods=["GET", "POST"])
@login_required
def risk_edit(risk_id):
    db = get_db()
    risk = db.execute(
        "SELECT * FROM risks WHERE id = ?", (risk_id,)).fetchone()
    if risk is None:
        abort(404)
    assets = db.execute("SELECT * FROM assets ORDER BY name").fetchall()
    if request.method == "POST":
        data, error = _validate_risk_form(request.form, db)
        if error:
            flash(error, "danger")
            return render_template(
                "risk_form.html", risk=risk, assets=assets,
                mitigation_statuses=MITIGATION_STATUSES,
                form_data=request.form), 400
        db.execute(
            "UPDATE risks SET title = ?, description = ?, asset_id = ?, "
            "likelihood = ?, impact = ?, inherent_score = ?, level = ?, "
            "treatment = ?, mitigation_status = ?, residual_likelihood = ?, "
            "residual_impact = ?, residual_score = ?, residual_level = ? "
            "WHERE id = ?",
            (data["title"], data["description"], data["asset_id"],
             data["likelihood"], data["impact"], data["inherent_score"],
             data["level"], data["treatment"], data["mitigation_status"],
             data["residual_likelihood"], data["residual_impact"],
             data["residual_score"], data["residual_level"], risk_id),
        )
        db.commit()
        log_audit("update", "risk", risk_id, session["username"],
                  "Risk '%s' updated (score %d, %s)."
                  % (data["title"], data["inherent_score"], data["level"]))
        flash("Risk updated.", "success")
        return redirect(url_for("risks_list"))
    return render_template(
        "risk_form.html", risk=risk, assets=assets,
        mitigation_statuses=MITIGATION_STATUSES, form_data=None)


@app.route("/risks/<int:risk_id>/delete", methods=["POST"])
@login_required
def risk_delete(risk_id):
    db = get_db()
    risk = db.execute(
        "SELECT * FROM risks WHERE id = ?", (risk_id,)).fetchone()
    if risk is None:
        abort(404)
    db.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
    db.commit()
    log_audit("delete", "risk", risk_id, session["username"],
              "Risk '%s' deleted." % risk["title"])
    flash("Risk deleted.", "success")
    return redirect(url_for("risks_list"))


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

@app.route("/compliance", methods=["GET", "POST"])
@login_required
def compliance():
    db = get_db()
    if request.method == "POST":
        control_id = _parse_int(request.form, "control_id")
        status = request.form.get("status", "").strip()
        notes = request.form.get("notes", "").strip()
        control = None
        if control_id is not None:
            control = db.execute(
                "SELECT * FROM controls WHERE id = ?",
                (control_id,)).fetchone()
        if control is None:
            flash("Please select a valid control.", "danger")
            return redirect(url_for("compliance"))
        if status not in CONTROL_STATUSES:
            flash("Invalid assessment status.", "danger")
            return redirect(url_for("compliance"))
        db.execute(
            "INSERT INTO assessments (control_id, status, notes, "
            "assessed_by, assessed_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(control_id) DO UPDATE SET status = excluded.status, "
            "notes = excluded.notes, assessed_by = excluded.assessed_by, "
            "assessed_at = excluded.assessed_at",
            (control_id, status, notes, session["username"], _now()),
        )
        db.commit()
        log_audit("assess", "control", control_id, session["username"],
                  "Control %s assessed as '%s'."
                  % (control["code"], status))
        flash("Control %s assessed as '%s'."
              % (control["code"], status), "success")
        return redirect(url_for("compliance"))

    controls = db.execute(
        "SELECT c.*, a.status, a.notes, a.assessed_by, a.assessed_at "
        "FROM controls c LEFT JOIN assessments a ON a.control_id = c.id "
        "ORDER BY c.code").fetchall()
    total = len(controls)
    assessed = sum(1 for c in controls if c["status"])
    pct = round(assessed * 100 / total) if total else 0
    status_counts = {s: 0 for s in CONTROL_STATUSES}
    for c in controls:
        if c["status"]:
            status_counts[c["status"]] += 1
    return render_template(
        "compliance.html", controls=controls, total=total,
        assessed=assessed, pct=pct, status_counts=status_counts,
        statuses=CONTROL_STATUSES)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@app.route("/evidence", methods=["GET", "POST"])
@login_required
def evidence_list():
    db = get_db()
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            flash("Please choose a file to upload.", "danger")
            return redirect(url_for("evidence_list"))
        if not allowed_file(uploaded.filename):
            flash(
                "File type not allowed. Allowed types: %s."
                % ", ".join(sorted(ALLOWED_EXTENSIONS)), "danger")
            return redirect(url_for("evidence_list"))
        file_bytes = uploaded.read()
        if len(file_bytes) == 0:
            flash("The uploaded file is empty.", "danger")
            return redirect(url_for("evidence_list"))
        if len(file_bytes) > MAX_FILE_SIZE:
            flash("File is larger than the 5 MB limit.", "danger")
            return redirect(url_for("evidence_list"))
        related_risk_id = _parse_int(request.form, "related_risk_id")
        if related_risk_id is not None and db.execute(
                "SELECT 1 FROM risks WHERE id = ?",
                (related_risk_id,)).fetchone() is None:
            flash("Selected risk does not exist.", "danger")
            return redirect(url_for("evidence_list"))
        safe_name = secure_filename(uploaded.filename)
        stored = "%s_%s" % (uuid.uuid4().hex, safe_name)
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
        with open(path, "wb") as fh:
            fh.write(file_bytes)
        digest = compute_sha256(file_bytes)
        cur = db.execute(
            "INSERT INTO evidence (filename, stored_filename, file_size, "
            "content_type, sha256, uploaded_by, related_risk_id, "
            "uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (safe_name, stored, len(file_bytes),
             uploaded.content_type or "", digest, session["username"],
             related_risk_id, _now()),
        )
        db.commit()
        log_audit("upload", "evidence", cur.lastrowid, session["username"],
                  "Evidence '%s' uploaded (SHA-256 %s)." % (safe_name, digest))
        flash("Evidence uploaded. SHA-256 recorded.", "success")
        return redirect(url_for("evidence_list"))

    items = db.execute(
        "SELECT e.*, r.title AS risk_title FROM evidence e "
        "LEFT JOIN risks r ON r.id = e.related_risk_id "
        "ORDER BY e.id DESC").fetchall()
    risks = db.execute(
        "SELECT id, title FROM risks ORDER BY title").fetchall()
    return render_template("evidence.html", items=items, risks=risks)


@app.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@login_required
def evidence_verify(evidence_id):
    db = get_db()
    item = db.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if item is None:
        abort(404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], item["stored_filename"])
    if not os.path.isfile(path):
        log_audit("verify", "evidence", evidence_id, session["username"],
                  "Verification FAILED: file missing from disk.")
        flash("Integrity check FAILED: file is missing from storage.",
              "danger")
        return redirect(url_for("evidence_list"))
    with open(path, "rb") as fh:
        digest = compute_sha256(fh.read())
    if digest == item["sha256"]:
        log_audit("verify", "evidence", evidence_id, session["username"],
                  "Verification passed: hash matches.")
        flash("Integrity verified: hash matches the recorded SHA-256.",
              "success")
    else:
        log_audit("verify", "evidence", evidence_id, session["username"],
                  "Verification FAILED: hash mismatch.")
        flash("Integrity check FAILED: hash does not match the recorded "
              "SHA-256.", "danger")
    return redirect(url_for("evidence_list"))


@app.route("/evidence/<int:evidence_id>/download")
@login_required
def evidence_download(evidence_id):
    db = get_db()
    item = db.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if item is None:
        abort(404)
    # Serve only the exact stored filename recorded in the database,
    # from the uploads directory. No user-supplied path is ever used.
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], item["stored_filename"],
        as_attachment=True, download_name=item["filename"])


# ---------------------------------------------------------------------------
# Audit log (read-only: no update or delete routes exist)
# ---------------------------------------------------------------------------

@app.route("/audit")
@login_required
def audit_list():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("audit.html", rows=rows)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route("/reports")
@login_required
def reports():
    db = get_db()
    level_rows = db.execute(
        "SELECT level, COUNT(*) AS c FROM risks GROUP BY level").fetchall()
    level_counts = {row["level"]: row["c"] for row in level_rows}
    for level in RISK_LEVELS:
        level_counts.setdefault(level, 0)
    risks = db.execute(
        "SELECT r.*, a.name AS asset_name FROM risks r "
        "JOIN assets a ON a.id = r.asset_id "
        "ORDER BY r.inherent_score DESC").fetchall()
    controls = db.execute(
        "SELECT c.code, c.title, a.status, a.assessed_by, a.assessed_at "
        "FROM controls c LEFT JOIN assessments a ON a.control_id = c.id "
        "ORDER BY c.code").fetchall()
    assessed = sum(1 for c in controls if c["status"])
    return render_template(
        "reports.html", level_counts=level_counts, risks=risks,
        controls=controls, total_controls=len(controls),
        assessed=assessed)


@app.route("/reports/risks.csv")
@login_required
def risks_csv():
    db = get_db()
    risks = db.execute(
        "SELECT r.title, a.name AS asset, r.likelihood, r.impact, "
        "r.inherent_score, r.level, r.mitigation_status, "
        "r.residual_score, r.residual_level, r.treatment "
        "FROM risks r JOIN assets a ON a.id = r.asset_id "
        "ORDER BY r.inherent_score DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Title", "Asset", "Likelihood", "Impact",
                     "Inherent Score", "Level", "Mitigation Status",
                     "Residual Score", "Residual Level", "Treatment"])
    for r in risks:
        writer.writerow([r["title"], r["asset"], r["likelihood"],
                         r["impact"], r["inherent_score"], r["level"],
                         r["mitigation_status"], r["residual_score"],
                         r["residual_level"], r["treatment"]])
    log_audit("report", "report", None, session["username"],
              "Risk summary CSV downloaded.")
    return app.response_class(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=risk_summary.csv"})


@app.route("/reports/controls.csv")
@login_required
def controls_csv():
    db = get_db()
    controls = db.execute(
        "SELECT c.code, c.title, a.status, a.notes, a.assessed_by, "
        "a.assessed_at FROM controls c "
        "LEFT JOIN assessments a ON a.control_id = c.id "
        "ORDER BY c.code").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Code", "Control", "Status", "Notes", "Assessed By",
                     "Assessed At"])
    for c in controls:
        writer.writerow([c["code"], c["title"], c["status"] or "Not assessed",
                         c["notes"] or "", c["assessed_by"] or "",
                         c["assessed_at"] or ""])
    log_audit("report", "report", None, session["username"],
              "Control assessment CSV downloaded.")
    return app.response_class(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=control_assessment.csv"})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):
    return render_template("error.html", code=404,
                           message="The page you requested was not found."), 404


@app.errorhandler(413)
def request_too_large(error):
    flash("File is larger than the 5 MB limit.", "danger")
    return redirect(url_for("evidence_list"))


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "error.html", code=500,
        message="Something went wrong on the server. Please try again."), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
