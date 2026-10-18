from conftest import create_project, get_csrf, register_admin
from models import HagarProject

from app import app as flask_app, limiter

STRONG = 'FortPassw0rd!x'


def test_csrf_required_on_admin_forms(client):
    response = client.post('/login', data={'username': 'x', 'password': 'y'})
    assert response.status_code == 400
    assert 'CSRF' in response.get_data(as_text=True)


def test_logout_requires_post(client):
    register_admin(client)
    assert client.get('/logout').status_code == 405


def test_idor_blocked_between_users(client):
    register_admin(client, 'alice', STRONG)
    assert create_project(client).status_code == 302
    with flask_app.app_context():
        project_id = HagarProject.query.first().id

    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    register_admin(client, 'mallory', STRONG)

    assert client.get(f'/hagar/{project_id}').status_code == 403
    assert client.get(f'/hagar/{project_id}/users').status_code == 403
    assert client.get(f'/hagar/{project_id}/download/signup').status_code == 403
    assert client.get(f'/hagar/{project_id}/download/config').status_code == 403
    response = client.post(
        f'/hagar/{project_id}/delete',
        data={'csrf_token': get_csrf(client, '/dashboard')},
    )
    assert response.status_code == 403
    response = client.post(
        f'/hagar/{project_id}/token/rotate',
        data={'csrf_token': get_csrf(client, '/dashboard')},
    )
    assert response.status_code == 403

    with flask_app.app_context():
        assert HagarProject.query.count() == 1


def test_locked_project_gates_downloads_and_delete(client):
    register_admin(client)
    create_project(client, password='ProjectPw0rd!x')
    with flask_app.app_context():
        project_id = HagarProject.query.first().id

    # Pas encore déverrouillé
    assert client.get(f'/hagar/{project_id}/download/signup').status_code == 403
    assert client.post(
        f'/hagar/{project_id}/delete',
        data={'csrf_token': get_csrf(client, '/dashboard')},
    ).status_code == 403

    # Mauvais mot de passe projet
    csrf = get_csrf(client, f'/hagar/{project_id}')
    response = client.post(
        f'/hagar/{project_id}',
        data={'project_password': 'mauvais', 'csrf_token': csrf},
        follow_redirects=True,
    )
    assert 'incorrect' in response.get_data(as_text=True)
    assert client.get(f'/hagar/{project_id}/download/signup').status_code == 403

    # Bon mot de passe
    csrf = get_csrf(client, f'/hagar/{project_id}')
    client.post(
        f'/hagar/{project_id}',
        data={'project_password': 'ProjectPw0rd!x', 'csrf_token': csrf},
    )
    assert client.get(f'/hagar/{project_id}/download/signup').status_code == 200


def test_security_headers_present(client):
    response = client.get('/')
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'default-src' in response.headers['Content-Security-Policy']
    assert response.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'


def test_session_cookie_flags(client):
    token = get_csrf(client, '/register')
    response = client.post(
        '/register',
        data={'username': 'alice', 'password': STRONG, 'csrf_token': token},
    )
    assert response.status_code == 302
    cookie_header = response.headers.get('Set-Cookie', '')
    assert 'HttpOnly' in cookie_header
    assert 'SameSite=Lax' in cookie_header
    # Développement en HTTP local : pas de flag Secure (impossible en local)
    assert 'Secure' not in cookie_header
    assert flask_app.config['SESSION_COOKIE_SECURE'] is False


def test_cors_restricted_to_api(client):
    api_response = client.post(
        '/api/hagar/login',
        data={'identifier': 'a', 'password': 'b'},
        headers={'Origin': 'https://client.example'},
    )
    assert api_response.headers.get('Access-Control-Allow-Origin') == 'https://client.example'

    page_response = client.get('/', headers={'Origin': 'https://evil.example'})
    assert 'Access-Control-Allow-Origin' not in page_response.headers

    preflight = client.options(
        '/api/hagar/login',
        headers={
            'Origin': 'https://client.example',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'x-hagar-token',
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers.get('Access-Control-Allow-Origin') == 'https://client.example'
    assert 'x-hagar-token' in preflight.headers.get('Access-Control-Allow-Headers', '').lower()


def test_rate_limit_on_login(client):
    register_admin(client)
    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    token = get_csrf(client, '/login')

    limiter.enabled = True
    limiter.reset()
    try:
        statuses = []
        for _ in range(11):
            response = client.post(
                '/login',
                data={'username': 'alice', 'password': 'MdpIncorrect1!', 'csrf_token': token},
            )
            statuses.append(response.status_code)
        assert statuses[9] == 200  # 10e tentative encore acceptée
        assert statuses[10] == 429  # 11e bloquée
        assert 'Trop de requêtes' in client.post(
            '/login',
            data={'username': 'alice', 'password': 'x', 'csrf_token': token},
        ).get_data(as_text=True)
    finally:
        limiter.reset()
        limiter.enabled = False


def test_api_rate_limit_returns_json(client):
    limiter.enabled = True
    limiter.reset()
    try:
        last = None
        for _ in range(31):
            last = client.post(
                '/api/hagar/login',
                data={'identifier': 'a', 'password': 'b'},
                headers={'X-Hagar-Token': 'jeton-inexistant'},
            )
        assert last.status_code == 429
        assert last.is_json
        assert last.get_json()['error'] == 'Trop de requêtes. Réessayez plus tard.'
    finally:
        limiter.reset()
        limiter.enabled = False


def test_secret_key_not_hardcoded_default(client):
    secret = flask_app.config['SECRET_KEY']
    assert secret != 'dev-key-hagar-auth'
    assert len(secret) >= 32


def test_generated_files_use_header_token(client):
    register_admin(client)
    assert create_project(client).status_code == 302
    with flask_app.app_context():
        project = HagarProject.query.first()
        token = project.api_token
        project_id = project.id

    signup = client.get(f'/hagar/{project_id}/download/signup').get_data(as_text=True)
    assert 'X-Hagar-Token' in signup
    assert f'/api/hagar/{token}' not in signup
    assert '/api/hagar/register' in signup

    login_page = client.get(f'/hagar/{project_id}/download/login').get_data(as_text=True)
    assert 'X-Hagar-Token' in login_page
    assert '127.0.0.1' not in login_page
    assert f'/api/hagar/{token}' not in login_page
    assert '/api/hagar/login' in login_page
    assert 'http://localhost/api/hagar/login' in login_page


def test_request_too_large_rejected_with_json(client):
    # Pas de jeton : la lecture du body (champ api_token) déclenche le contrôle 413
    response = client.post(
        '/api/hagar/register',
        data={'x': 'y' * (2 * 1024 * 1024)},
    )
    assert response.status_code == 413
    assert response.is_json


def test_download_invalid_type_rejected(client):
    register_admin(client)
    create_project(client)
    with flask_app.app_context():
        project_id = HagarProject.query.first().id
    assert client.get(f'/hagar/{project_id}/download/autre').status_code == 400
