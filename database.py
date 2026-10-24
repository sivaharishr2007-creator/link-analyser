"""
Database persistence layer using SQLite for SecureSite Auditor.

Supports scan history storage, query filtering, analytics aggregation,
and ephemeral (in-memory / no-storage) mode toggle.
"""

import json
import sqlite3
from typing import Any
from config import Config


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """Creates a connection with row factory enabled."""
    if db_path is None:
        try:
            from flask import current_app
            db_path = current_app.config.get("DATABASE_PATH", Config.DATABASE_PATH)
        except (RuntimeError, ImportError):
            db_path = Config.DATABASE_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = None) -> None:
    """Initializes tables and indices for scan history persistence."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                target_host TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                security_score INTEGER NOT NULL,
                letter_grade TEXT NOT NULL,
                grade_label TEXT,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                pass_count INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0.0,
                is_ephemeral INTEGER DEFAULT 0,
                full_results_json TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_host ON scans(target_host)")
        conn.commit()


def save_scan(scan_result: dict[str, Any], db_path: str = None) -> bool:
    """
    Saves a scan result to SQLite unless ephemeral mode is active.
    Returns True if stored, False if ephemeral.
    """
    if scan_result.get("is_ephemeral", False):
        return False  # Ephemeral scan: strictly in-memory, no persistence

    counts = scan_result.get("findings_summary", {})
    
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans (
                id, target_url, target_host, timestamp, security_score,
                letter_grade, grade_label, critical_count, high_count,
                medium_count, low_count, info_count, pass_count,
                duration_seconds, is_ephemeral, full_results_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_result["scan_id"],
            scan_result.get("normalized_url") or scan_result.get("input_url") or "unknown",
            scan_result.get("target_host") or "unknown",
            scan_result.get("timestamp") or "",
            scan_result.get("security_score", 0),
            scan_result.get("letter_grade", "F"),
            scan_result.get("grade_label", ""),
            counts.get("CRITICAL", 0),
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            counts.get("INFO", 0),
            counts.get("PASS", 0),
            scan_result.get("duration_seconds", 0.0),
            0,
            json.dumps(scan_result)
        ))
        conn.commit()
    return True


def get_scan(scan_id: str, db_path: str = None) -> dict[str, Any] | None:
    """Retrieves full scan dictionary by ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT full_results_json FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            return json.loads(row["full_results_json"])
    return None


def get_recent_scans(limit: int = 50, search_query: str = None, db_path: str = None) -> list[dict[str, Any]]:
    """Retrieves list of recent scan records with optional search filter."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        if search_query:
            term = f"%{search_query.strip()}%"
            cursor.execute("""
                SELECT id, target_url, target_host, timestamp, security_score,
                       letter_grade, grade_label, critical_count, high_count,
                       medium_count, low_count, info_count, pass_count, duration_seconds
                FROM scans
                WHERE target_url LIKE ? OR target_host LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (term, term, limit))
        else:
            cursor.execute("""
                SELECT id, target_url, target_host, timestamp, security_score,
                       letter_grade, grade_label, critical_count, high_count,
                       medium_count, low_count, info_count, pass_count, duration_seconds
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def delete_scan(scan_id: str, db_path: str = None) -> bool:
    """Deletes a single scan by ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def clear_all_scans(db_path: str = None) -> int:
    """Deletes all persistent scan history."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
        return cursor.rowcount


def get_dashboard_stats(db_path: str = None) -> dict[str, Any]:
    """Calculates summary metrics across all historical scans for the dashboard."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                AVG(security_score) as avg_score,
                SUM(critical_count) as total_critical,
                SUM(high_count) as total_high,
                SUM(medium_count) as total_medium,
                SUM(low_count) as total_low,
                SUM(pass_count) as total_pass
            FROM scans
        """)
        row = cursor.fetchone()
        
        if not row or row["total_scans"] == 0:
            return {
                "total_scans": 0,
                "avg_score": 0,
                "total_critical": 0,
                "total_high": 0,
                "total_medium": 0,
                "total_low": 0,
                "total_pass": 0,
                "grade_distribution": {},
            }

        # Calculate grade distribution
        cursor.execute("SELECT letter_grade, COUNT(*) as count FROM scans GROUP BY letter_grade")
        grade_dist = {r["letter_grade"]: r["count"] for r in cursor.fetchall()}

        return {
            "total_scans": row["total_scans"],
            "avg_score": round(row["avg_score"] or 0, 1),
            "total_critical": row["total_critical"] or 0,
            "total_high": row["total_high"] or 0,
            "total_medium": row["total_medium"] or 0,
            "total_low": row["total_low"] or 0,
            "total_pass": row["total_pass"] or 0,
            "grade_distribution": grade_dist,
        }
