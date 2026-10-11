
import os
from urllib.parse import urlparse

import joblib
import psycopg2
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Load the trained machine-learning model and vectorizer
MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "phishing_model.pkl"
)
VECTORIZER_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "url_vectorizer.pkl"
)

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


# PostgreSQL database connection
def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "securelink_db"),
        user=os.getenv("DB_USER", "securelink_user"),
        password=os.getenv("DB_PASSWORD")
    )


# Validate and analyse the submitted URL
def check_url(url):
    if not isinstance(url, str) or not url.strip():
        return "INVALID LINK", 0

    url = url.strip()
    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or any(char.isspace() for char in url)
        or parsed.username is not None
        or parsed.password is not None
    ):
        return "INVALID LINK", 0

    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "bank", "password", "confirm"
    ]

    suspicious_tlds = (".xyz", ".tk", ".ml", ".ga", ".cf")
    url_lower = url.lower()
    hostname = parsed.hostname.lower()

    score = 0

    for word in suspicious_words:
        if word in url_lower:
            score += 1

    if hostname.endswith(suspicious_tlds):
        score += 3

    # Add a risk point contribution from the trained ML model.
    # This assumes model label 1 means phishing and label 0 means safe.
    try:
        features = vectorizer.transform([url])
        prediction = str(model.predict(features)[0]).strip().lower()

        malicious_labels = {
            "1", "phishing", "malicious", "unsafe", "bad"
        }

        if prediction in malicious_labels:
            score += 3

    except Exception:
        app.logger.exception("Machine-learning prediction failed")

    if score >= 3:
        return "MALICIOUS / PHISHING LINK", score

    return "SAFE LINK", score


# Save scan results to PostgreSQL
def save_scan(url, result, risk_score, ip_address):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO url_scans
                    (url, result, risk_score, ip_address)
                VALUES (%s, %s, %s, %s)
                """,
                (url, result, risk_score, ip_address)
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def scan_and_save(url, ip_address):
    result, risk_score = check_url(url)
    save_scan(url, result, risk_score, ip_address)
    return result, risk_score


# Main website
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    risk_score = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            try:
                result, risk_score = scan_and_save(
                    url, request.remote_addr
                )
            except Exception:
                app.logger.exception("URL scan failed")
                result = "SCAN ERROR - PLEASE CHECK DATABASE"

    return render_template(
        "index.html",
        result=result,
        risk_score=risk_score,
        url=url
    )


# URL scanning API
@app.route("/api/check-url", methods=["POST"])
def api_check_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    url = url.strip()

    try:
        result, risk_score = scan_and_save(
            url, request.remote_addr
        )

        return jsonify({
            "url": url,
            "result": result,
            "risk_score": risk_score
        })

    except Exception:
        app.logger.exception("API URL scan failed")
        return jsonify({"error": "Unable to scan URL"}), 500


# Recent scan history API
@app.route("/api/history", methods=["GET"])
def api_history():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, url, result, risk_score,
                       ip_address, scanned_at
                FROM url_scans
                ORDER BY id DESC
                LIMIT 100
                """
            )
            rows = cursor.fetchall()

        history = [
            {
                "id": row[0],
                "url": row[1],
                "result": row[2],
                "risk_score": row[3],
                "ip_address": row[4],
                "scanned_at": (
                    row[5].isoformat() if row[5] else None
                )
            }
            for row in rows
        ]

        return jsonify(history)

    except Exception:
        app.logger.exception("Unable to retrieve scan history")
        return jsonify({"error": "Unable to retrieve history"}), 500

    finally:
        connection.close()


# Dashboard statistics API
@app.route("/api/stats", methods=["GET"])
def api_stats():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM url_scans")
            total_scans = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM url_scans WHERE result = %s",
                ("SAFE LINK",)
            )
            safe_links = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT COUNT(*) FROM url_scans
                WHERE result IN (%s, %s)
                """,
                ("MALICIOUS / PHISHING LINK", "INVALID LINK")
            )
            malicious_links = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM url_scans WHERE result = %s",
                ("SUSPICIOUS LINK",)
            )
            suspicious_links = cursor.fetchone()[0]

        return jsonify({
            "total_scans": total_scans,
            "safe_links": safe_links,
            "malicious_links": malicious_links,
            "suspicious_links": suspicious_links
        })

    except Exception:
        app.logger.exception("Unable to retrieve statistics")
        return jsonify({"error": "Unable to retrieve statistics"}), 500

    finally:
        connection.close()


# Security dashboard page
@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


# Health check endpoint for deployment
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)


