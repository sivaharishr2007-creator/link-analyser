"""
SecureSite Auditor - Web Application Security Scanner
Main Flask Application Controller
"""

import json
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    Response,
    flash,
)
from config import Config
from database import (
    init_db,
    save_scan,
    get_scan,
    get_recent_scans,
    delete_scan,
    clear_all_scans,
    get_dashboard_stats,
)
from scanner import run_security_scan
from reports import generate_csv_report, generate_html_report

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database schema on startup
with app.app_context():
    init_db()


@app.context_processor
def inject_global_data():
    """Injects common utility variables and metadata into all templates."""
    return {
        "app_name": "SecureSite Auditor",
        "app_version": "1.0.0",
        "academic_context": "B.Tech CSE (AI & Data Science) Cybersecurity Training Tool",
    }


# -------------------------------------------------------------
# Frontend Page Routes
# -------------------------------------------------------------

@app.route("/")
def dashboard():
    """Main dashboard overview featuring high-level metrics and quick scan launcher."""
    stats = get_dashboard_stats()
    recent_scans = get_recent_scans(limit=8)
    return render_template(
        "index.html",
        stats=stats,
        recent_scans=recent_scans,
        active_page="dashboard"
    )


@app.route("/scan")
def scan_page():
    """Dedicated scan page with target configuration and real-time scanner view."""
    target_preset = request.args.get("url", "")
    return render_template(
        "scan.html",
        preset_url=target_preset,
        active_page="scan"
    )


@app.route("/scan/<scan_id>")
def results_page(scan_id):
    """Detailed visual audit report for a persistent scan record."""
    scan_data = get_scan(scan_id)
    if not scan_data:
        flash(f"Scan record '{scan_id}' was not found or was executed in ephemeral mode.", "warning")
        return redirect(url_for("history_page"))

    return render_template(
        "results.html",
        scan=scan_data,
        active_page="scan"
    )


@app.route("/history")
def history_page():
    """Interactive scan history table with search query filtering."""
    query = request.args.get("q", "").strip()
    scans = get_recent_scans(limit=100, search_query=query if query else None)
    return render_template(
        "history.html",
        scans=scans,
        search_query=query,
        active_page="history"
    )


@app.route("/knowledge-base")
def knowledge_base():
    """Security knowledge base and server configuration remediation repository."""
    return render_template(
        "knowledge_base.html",
        active_page="knowledge-base"
    )


@app.route("/methodology")
def methodology():
    """Methodology, SSRF defense architecture, and security boundary documentation."""
    return render_template(
        "methodology.html",
        active_page="methodology"
    )


# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_run_scan():
    """
    Launches a defensive security scan against the validated target.
    Accepts JSON: { "url": "https://example.com", "ephemeral": false }
    """
    data = request.get_json(silent=True) or request.form.to_dict()
    target_url = (data.get("url") or "").strip()
    is_ephemeral = str(data.get("ephemeral", "false")).lower() in ("true", "1", "yes", "on")

    if not target_url:
        return jsonify({
            "success": False,
            "error": "A target URL or hostname is required."
        }), 400

    # Execute scan through orchestrator engine
    scan_result = run_security_scan(target_url, is_ephemeral=is_ephemeral)

    # Persist to SQLite if not ephemeral and scan succeeded or has findings
    if not is_ephemeral:
        save_scan(scan_result)

    return jsonify(scan_result)


@app.route("/api/scan/<scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Retrieves full scan JSON by ID."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found or was ephemeral."}), 404
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/delete", methods=["POST", "DELETE"])
def api_delete_scan(scan_id):
    """Deletes an individual scan from persistent storage."""
    deleted = delete_scan(scan_id)
    if not deleted:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({"success": True, "message": f"Scan {scan_id} deleted."})


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears all scan history from the database."""
    count = clear_all_scans()
    return jsonify({"success": True, "deleted_count": count})


# -------------------------------------------------------------
# Report Export Endpoints
# -------------------------------------------------------------

@app.route("/export/<scan_id>/html")
def export_html(scan_id):
    """Downloads standalone, printable HTML report for a scan ID."""
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan record not found.", "danger")
        return redirect(url_for("history_page"))

    html_content = generate_html_report(scan)
    filename = f"securesite_audit_{scan.get('target_host', 'report')}_{scan_id[:8]}.html"
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/export/<scan_id>/csv")
def export_csv(scan_id):
    """Downloads RFC 4180 CSV report for a scan ID."""
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan record not found.", "danger")
        return redirect(url_for("history_page"))

    csv_content = generate_csv_report(scan)
    filename = f"securesite_audit_{scan.get('target_host', 'report')}_{scan_id[:8]}.csv"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/export/ephemeral/html", methods=["POST"])
def export_ephemeral_html():
    """Exports ephemeral scan result posted directly from client memory as HTML."""
    try:
        data = request.get_json(force=True)
        html_content = generate_html_report(data)
        host = data.get("target_host", "ephemeral")
        filename = f"securesite_audit_{host}_ephemeral.html"
        return Response(
            html_content,
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {e}"}), 400


@app.route("/export/ephemeral/csv", methods=["POST"])
def export_ephemeral_csv():
    """Exports ephemeral scan result posted directly from client memory as CSV."""
    try:
        data = request.get_json(force=True)
        csv_content = generate_csv_report(data)
        host = data.get("target_host", "ephemeral")
        filename = f"securesite_audit_{host}_ephemeral.csv"
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {e}"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
