"""
Pytest configuration and test fixtures for SecureSite Auditor.
"""

import os
import tempfile
import pytest
from app import app
from database import init_db


@pytest.fixture
def test_client():
    """Provides a configured Flask test client with an isolated temporary SQLite database."""
    db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)  # Close OS handle immediately so SQLite can access it exclusively
    app.config["TESTING"] = True
    app.config["DATABASE_PATH"] = temp_db_path
    
    with app.app_context():
        init_db(temp_db_path)

    with app.test_client() as client:
        yield client

    try:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
    except OSError:
        pass
