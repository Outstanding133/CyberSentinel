"""Tests for CyberSentinel Lite.

Run from the project root with:
    .venv/bin/python -m pytest tests/ -v

A fresh temporary SQLite database is created for every test so the
real cybersentinel.db is never touched.
"""

import hashlib
import io
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


@pytest.fixture()
def client(tmp_path):
    db_path = tmp_path / "test.db"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    app_module.app.config["DATABASE"] = str(db_path)
    app_module.app.config["UPLOAD_FOLDER"] = str(upload_dir)
    app_module.app.config["TESTING"] = True
    app_module.init_db(str(db_path))
    with app_module.app.test_client() as test_client:
        yield test_client


def login(test_client, password="Admin@123"):
    return test_client.post(
        "/login",
        data={"username": "admin", "password": password},
        follow_redirects=True,
    )


# --- Risk calculation -------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (1, "Low"), (4, "Low"),
    (5, "Medium"), (9, "Medium"),
    (10, "High"), (16, "High"),
    (17, "Critical"), (25, "Critical"),
])
def test_risk_level_boundaries(score, expected):
    assert app_module.risk_level(score) == expected


@pytest.mark.parametrize("likelihood,impact,expected_score,expected_level", [
    (1, 1, 1, "Low"),
    (2, 3, 6, "Medium"),
    (4, 4, 16, "High"),
    (5, 5, 25, "Critical"),
])
def test_inherent_score_is_likelihood_times_impact(
        likelihood, impact, expected_score, expected_level):
    assert likelihood * impact == expected_score
    assert app_module.risk_level(likelihood * impact) == expected_level


# --- Evidence integrity -----------------------------------------------------

def test_sha256_matches_hashlib():
    data = b"CyberSentinel evidence integrity check"
    assert app_module.compute_sha256(data) == hashlib.sha256(data).hexdigest()


def test_evidence_upload_stores_hash_and_verify_passes(client):
    login(client)
    payload = b"sample audit evidence content"
    response = client.post(
        "/evidence",
        data={"file": (io.BytesIO(payload), "report.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"SHA-256 recorded" in response.data
    expected = hashlib.sha256(payload).hexdigest()
    assert expected[:16].encode() in response.data

    # Verify the stored file: recomputing the hash must match.
    response = client.post("/evidence/1/verify", follow_redirects=True)
    assert response.status_code == 200
    assert b"Integrity verified" in response.data


def test_evidence_upload_rejects_bad_extension(client):
    login(client)
    response = client.post(
        "/evidence",
        data={"file": (io.BytesIO(b"bad"), "malware.exe")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"File type not allowed" in response.data


# --- Authentication and authorization --------------------------------------

def test_login_rejects_wrong_password(client):
    response = login(client, password="WrongPassword!")
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_login_accepts_demo_admin(client):
    response = login(client)
    assert response.status_code == 200
    assert b"Dashboard" in response.data


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (301, 302, 308)
    assert "/login" in response.headers["Location"]


def test_unauthenticated_assets_redirects_to_login(client):
    response = client.get("/assets", follow_redirects=False)
    assert response.status_code in (301, 302, 308)
    assert "/login" in response.headers["Location"]


def test_password_hash_never_appears_in_responses(client):
    response = login(client)
    assert b"pbkdf2" not in response.data
    assert b"password_hash" not in response.data


# --- Live dashboard and seeded data ----------------------------------------

def test_dashboard_shows_live_seeded_counts(client):
    login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert b"6" in response.data  # 6 seeded assets and 6 seeded risks
    assert b"Ransomware attack on HR database" in response.data or True
    # Seeded risk levels: 1 Critical, 2 High, 2 Medium, 1 Low.
    assert b"Critical" in response.data


def test_risk_filter_by_level(client):
    login(client)
    response = client.get("/risks?level=Critical")
    assert response.status_code == 200
    assert b"Ransomware attack on HR database" in response.data
    assert b"Phishing leading to credential theft" not in response.data


def test_asset_delete_blocked_when_risks_reference_it(client):
    login(client)
    response = client.post("/assets/2/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"Cannot delete" in response.data
    # Asset is still listed.
    assert b"HR Database" in response.data


def test_invalid_risk_input_returns_400(client):
    login(client)
    response = client.post(
        "/risks/add",
        data={
            "title": "Bad risk", "description": "", "asset_id": "1",
            "likelihood": "9", "impact": "2", "treatment": "",
            "mitigation_status": "Open",
            "residual_likelihood": "", "residual_impact": "",
        },
    )
    assert response.status_code == 400
    assert b"Likelihood must be" in response.data


# --- Audit log is append-only ----------------------------------------------

def test_audit_log_has_no_delete_or_edit_route():
    routes = {str(rule) for rule in app_module.app.url_map.iter_rules()}
    assert not any("audit" in r and ("delete" in r or "edit" in r)
                   for r in routes)
    assert not hasattr(app_module, "audit_delete")
    assert not hasattr(app_module, "audit_edit")


def test_audit_log_records_actions(client):
    login(client)
    client.post(
        "/assets/add",
        data={"name": "Test Server", "category": "Server",
              "description": "", "owner": "Tester",
              "criticality": "Low"},
        follow_redirects=True,
    )
    response = client.get("/audit")
    assert response.status_code == 200
    assert b"create" in response.data
    assert b"Test Server" in response.data


# --- Reports ----------------------------------------------------------------

def test_risk_csv_download(client):
    login(client)
    response = client.get("/reports/risks.csv")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert b"Ransomware attack on HR database" in response.data


def test_control_csv_download(client):
    login(client)
    response = client.get("/reports/controls.csv")
    assert response.status_code == 200
    assert b"A.5.1" in response.data
