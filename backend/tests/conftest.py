"""Shared test configuration.

Environment variables are set before any ``app`` import so that settings, the
database engine and the detector are created against disposable resources.
Default storage is SQLite in a temp directory; set SENTINEL_TEST_DATABASE_URL to
an explicitly disposable PostgreSQL database to run the same suite there.
"""
import os
import tempfile

import pytest

TEMP = tempfile.TemporaryDirectory(prefix='sentinel-tests-')
os.environ['DATABASE_URL'] = os.environ.get('SENTINEL_TEST_DATABASE_URL', f'sqlite:///{TEMP.name}/test.db')
os.environ['SECRET_KEY'] = 'isolated-integration-test-secret-0123456789'
os.environ['SENTINEL_BOOTSTRAP_ADMIN_PASSWORD'] = 'TestOnly-Admin-Password-2026!'
os.environ['SENTINEL_BOOTSTRAP_ANALYST_PASSWORD'] = 'TestOnly-Analyst-Password-2026!'
os.environ['SENTINEL_BOOTSTRAP_USER_PASSWORD'] = 'TestOnly-User-Password-2026!'
os.environ['COOKIE_SECURE'] = 'false'
os.environ['ALLOW_SELF_REGISTRATION'] = 'true'
os.environ['MODEL_DIR'] = os.path.join(TEMP.name, 'models')

PASSWORDS = {
    'admin': os.environ['SENTINEL_BOOTSTRAP_ADMIN_PASSWORD'],
    'analyst': os.environ['SENTINEL_BOOTSTRAP_ANALYST_PASSWORD'],
    'insider_target': os.environ['SENTINEL_BOOTSTRAP_USER_PASSWORD'],
}

from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import engine  # noqa: E402
from app.core.rate_limit import login_throttle  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope='session', autouse=True)
def _dispose_database():
    yield
    # Release pooled SQLite connections before TemporaryDirectory cleanup on Windows.
    engine.dispose()
    TEMP.cleanup()


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    login_throttle.reset()
    yield
    login_throttle.reset()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client, username, password=None):
    response = client.post('/api/auth/login',
                           data={'username': username, 'password': password or PASSWORDS[username]})
    assert response.status_code == 200, response.text
    return {'Authorization': f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin_headers(client):
    return login(client, 'admin')


@pytest.fixture
def analyst_headers(client):
    return login(client, 'analyst')


@pytest.fixture
def user_headers(client):
    return login(client, 'insider_target')
