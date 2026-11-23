"""Authentication, authorization and HTTP-hardening regression tests."""
import base64
import json
from datetime import timedelta
from pathlib import Path

import pytest
from jose import jwt

from conftest import PASSWORDS, login
from app.core.config import settings
from app.core.rate_limit import LoginThrottle
from app.core.security import create_access_token
from app.main import resolve_frontend_file


def test_login_returns_short_lived_token_and_httponly_refresh_cookie(client):
    response = client.post('/api/auth/login', data={'username': 'analyst', 'password': PASSWORDS['analyst']})
    assert response.status_code == 200
    body = response.json()
    assert body['role'] == 'Analyst' and body['expires_in'] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    claims = jwt.get_unverified_claims(body['access_token'])
    assert claims['type'] == 'access' and claims['jti'] and claims['iat'] and claims['exp']
    cookie = response.headers['set-cookie'].lower()
    assert 'sentinel_refresh=' in cookie and 'httponly' in cookie and 'samesite=strict' in cookie
    assert 'path=/api/auth' in cookie
    assert 'refresh' not in body  # the refresh token is never exposed to JavaScript


def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    wrong = client.post('/api/auth/login', data={'username': 'analyst', 'password': 'not-the-password'})
    unknown = client.post('/api/auth/login', data={'username': 'nobody-here', 'password': 'whatever-password'})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_account_lockout_after_repeated_failures(client):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert client.post('/api/auth/login', data={'username': 'analyst', 'password': 'bad-password'}).status_code == 401
    locked = client.post('/api/auth/login', data={'username': 'analyst', 'password': PASSWORDS['analyst']})
    assert locked.status_code == 429
    assert int(locked.headers['retry-after']) > 0
    # Another account is unaffected by this user's lockout.
    assert client.post('/api/auth/login', data={'username': 'admin', 'password': PASSWORDS['admin']}).status_code == 200


def test_throttle_ip_budget_and_lock_expiry():
    now = [0.0]
    throttle = LoginThrottle(clock=lambda: now[0])
    for _ in range(settings.LOGIN_IP_MAX_ATTEMPTS):
        assert throttle.check('someone', '10.0.0.1') == 0
    assert throttle.check('someone', '10.0.0.1') > 0
    assert throttle.check('someone', '10.0.0.2') == 0  # different client IP
    for _ in range(settings.LOGIN_MAX_FAILURES):
        throttle.record_failure('victim')
    assert throttle.check('victim', '10.0.0.3') > 0
    now[0] += settings.LOGIN_LOCKOUT_MINUTES * 60 + 1
    assert throttle.check('victim', '10.0.0.3') == 0


def test_logout_revokes_access_token_and_refresh_cookie(client):
    headers = login(client, 'analyst')
    refresh_cookie = client.cookies.get('sentinel_refresh')
    assert client.get('/api/auth/me', headers=headers).status_code == 200
    assert client.post('/api/auth/logout', headers=headers).status_code == 204
    assert client.get('/api/auth/me', headers=headers).status_code == 401
    # Replaying the captured refresh cookie proves it was revoked server-side,
    # not merely deleted from the browser.
    client.cookies.set('sentinel_refresh', refresh_cookie, path='/api/auth')
    assert client.post('/api/auth/refresh').status_code == 401


def test_logout_with_expired_access_token_still_revokes_refresh_session(client):
    login(client, 'analyst')
    refresh_cookie = client.cookies.get('sentinel_refresh')
    expired = create_access_token({'sub': 'analyst'}, expires_delta=timedelta(seconds=-5))
    assert client.post('/api/auth/logout', headers={'Authorization': f'Bearer {expired}'}).status_code == 204
    client.cookies.set('sentinel_refresh', refresh_cookie, path='/api/auth')
    assert client.post('/api/auth/refresh').status_code == 401


def test_refresh_rotates_and_detects_reuse(client):
    login(client, 'analyst')
    first_cookie = client.cookies.get('sentinel_refresh')
    rotated = client.post('/api/auth/refresh')
    assert rotated.status_code == 200, rotated.text
    second_cookie = client.cookies.get('sentinel_refresh')
    assert second_cookie and second_cookie != first_cookie
    assert client.get('/api/auth/me', headers={'Authorization': f"Bearer {rotated.json()['access_token']}"}).status_code == 200
    # Replaying the old (rotated) token is treated as theft: the live token dies too.
    client.cookies.set('sentinel_refresh', first_cookie, path='/api/auth')
    assert client.post('/api/auth/refresh').status_code == 401
    client.cookies.set('sentinel_refresh', second_cookie, path='/api/auth')
    assert client.post('/api/auth/refresh').status_code == 401


@pytest.mark.parametrize('claims', [
    {'sub': 'admin', 'type': 'refresh'},          # wrong token type
    {'sub': 'ghost-user', 'type': 'access'},      # user does not exist
])
def test_rejects_wrong_type_or_unknown_subject(client, claims):
    token = create_access_token({'sub': claims['sub']})
    if claims['type'] != 'access':
        payload = jwt.get_unverified_claims(token) | {'type': claims['type']}
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert client.get('/api/auth/me', headers={'Authorization': f'Bearer {token}'}).status_code == 401


def test_rejects_expired_forged_and_unsigned_tokens(client):
    expired = create_access_token({'sub': 'admin'}, expires_delta=timedelta(seconds=-5))
    forged = jwt.encode({'sub': 'admin', 'type': 'access', 'jti': 'x', 'exp': 9999999999},
                        'attacker-chosen-secret-0123456789abcdef', algorithm='HS256')
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'admin', 'type': 'access', 'jti': 'x', 'exp': 9999999999})}."
    for token in (expired, forged, unsigned):
        assert client.get('/api/auth/me', headers={'Authorization': f'Bearer {token}'}).status_code == 401


def test_standard_user_is_scoped_to_own_data(client, user_headers, analyst_headers):
    me = client.get('/api/auth/me', headers=user_headers).json()
    logged = client.post('/api/activities/log', headers=user_headers, json={
        'action_type': 'FILE_READ', 'bytes_transferred': 3.5, 'is_sensitive_file': False})
    assert logged.status_code == 200, logged.text
    client.post('/api/activities/log', headers=analyst_headers, json={'action_type': 'LOGIN'})
    own = client.get('/api/activities/recent', headers=user_headers).json()
    assert own and all(row['user_id'] == me['id'] for row in own)
    every = client.get('/api/activities/recent', headers=analyst_headers).json()
    assert any(row['user_id'] != me['id'] for row in every)
    for method, path in [('get', '/api/alerts/'), ('get', '/api/incidents/'), ('get', '/api/users/'),
                         ('get', '/api/analytics/dashboard-stats'), ('post', '/api/activities/analyze'),
                         ('get', '/api/research/results')]:
        kwargs = {'json': {}} if method == 'post' else {}
        assert getattr(client, method)(path, headers=user_headers, **kwargs).status_code == 403, path


def test_activity_input_validation(client, user_headers):
    for bad in ({'action_type': 'DROP TABLE'}, {'action_type': 'LOGIN', 'bytes_transferred': -1},
                {'action_type': 'LOGIN', 'privilege_level': 9}, {'action_type': 'LOGIN', 'unexpected': 1}):
        assert client.post('/api/activities/log', headers=user_headers, json=bad).status_code == 422


def test_admin_user_management_and_deactivation(client, admin_headers, analyst_headers, user_headers):
    new_user = {'username': 'managed-user', 'email': 'managed@example.com',
                'password': 'TestOnly-Managed-Password-2026!', 'role': 'User'}
    # Only administrators can provision accounts.
    assert client.post('/api/users/', headers=analyst_headers, json=new_user).status_code == 403
    assert client.post('/api/users/', headers=user_headers, json=new_user).status_code == 403
    created = client.post('/api/users/', headers=admin_headers, json=new_user)
    assert created.status_code == 201, created.text
    target = created.json()
    assert target['role'] == 'User'
    assert client.post('/api/users/', headers=admin_headers, json=new_user).status_code == 409
    assert client.patch(f"/api/users/{target['id']}", headers=analyst_headers, json={'role': 'Analyst'}).status_code == 403
    promoted = client.patch(f"/api/users/{target['id']}", headers=admin_headers, json={'role': 'Analyst'})
    assert promoted.status_code == 200 and promoted.json()['role'] == 'Analyst'
    assert client.patch(f"/api/users/{target['id']}", headers=admin_headers, json={'role': 'Root'}).status_code == 422
    users = client.get('/api/users/', headers=admin_headers).json()
    admin_id = next(u['id'] for u in users if u['username'] == 'admin')
    assert client.patch(f'/api/users/{admin_id}', headers=admin_headers, json={'is_active': False}).status_code == 400
    deactivated = client.patch(f"/api/users/{target['id']}", headers=admin_headers, json={'is_active': False, 'role': 'User'})
    assert deactivated.status_code == 200 and deactivated.json()['is_active'] is False


def test_role_change_applies_to_existing_token_immediately(client, admin_headers):
    created = client.post('/api/users/', headers=admin_headers, json={
        'username': 'temp-analyst', 'email': 'temp-analyst@example.com',
        'password': 'TestOnly-Temp-Analyst-2026!', 'role': 'Analyst'}).json()
    headers = login(client, 'temp-analyst', 'TestOnly-Temp-Analyst-2026!')
    assert client.get('/api/alerts/', headers=headers).status_code == 200
    client.patch(f"/api/users/{created['id']}", headers=admin_headers, json={'role': 'User'})
    # The role is read from the database on every request, not trusted from the JWT.
    assert client.get('/api/alerts/', headers=headers).status_code == 403


def test_deactivated_user_cannot_log_in_or_use_existing_token(client, admin_headers):
    created = client.post('/api/users/', headers=admin_headers, json={
        'username': 'soon-disabled', 'email': 'soon-disabled@example.com',
        'password': 'TestOnly-Disabled-Password-2026!'})
    assert created.status_code == 201, created.text
    headers = login(client, 'soon-disabled', 'TestOnly-Disabled-Password-2026!')
    client.patch(f"/api/users/{created.json()['id']}", headers=admin_headers, json={'is_active': False})
    assert client.get('/api/auth/me', headers=headers).status_code == 401
    again = client.post('/api/auth/login', data={'username': 'soon-disabled',
                                                 'password': 'TestOnly-Disabled-Password-2026!'})
    assert again.status_code == 401


def test_self_registration_can_be_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, 'ALLOW_SELF_REGISTRATION', False)
    response = client.post('/api/auth/register', json={
        'username': 'blocked-signup', 'email': 'blocked@example.com',
        'password': 'TestOnly-Blocked-Password-2026!'})
    assert response.status_code == 403


def test_security_headers(client):
    response = client.get('/health')
    assert "frame-ancestors 'none'" in response.headers['content-security-policy']
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert response.headers['x-frame-options'] == 'DENY'
    assert client.get('/api/auth/me').headers['cache-control'] == 'no-store'


def test_frontend_path_resolution_cannot_escape_dist(tmp_path):
    dist = tmp_path / 'dist'
    (dist / 'assets').mkdir(parents=True)
    (dist / 'index.html').write_text('<html></html>')
    (dist / 'assets' / 'app.js').write_text('ok')
    (tmp_path / 'secret.env').write_text('SECRET_KEY=leak')
    assert resolve_frontend_file(dist, 'assets/app.js') == (dist / 'assets' / 'app.js').resolve()
    for attack in ('../secret.env', 'assets/../../secret.env', '..\\secret.env',
                   str(tmp_path / 'secret.env'), 'assets/\x00.js', ''):
        assert resolve_frontend_file(dist, attack) is None, attack


def test_spa_route_blocks_encoded_traversal(client):
    from app.main import FRONTEND_DIST
    if FRONTEND_DIST is None:
        pytest.skip('Frontend not built; covered by the unit test above')
    for path in ('/..%2f..%2fbackend%2frequirements.txt', '/%2e%2e/%2e%2e/backend/requirements.txt',
                 '/..%5c..%5cbackend%5crequirements.txt'):
        response = client.get(path)
        assert 'fastapi' not in response.text.lower(), path
    assert Path(FRONTEND_DIST, 'index.html').is_file()
