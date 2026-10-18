import atexit
import os
import re
import tempfile

# La configuration doit être en place AVANT l'import de l'application.
_DB_PATH = os.path.join(tempfile.gettempdir(), f'hagar_auth_test_{os.getpid()}.db').replace('\\', '/')
if os.path.exists(_DB_PATH):
    os.remove(_DB_PATH)


def _cleanup_db():
    try:
        os.remove(_DB_PATH)
    except OSError:
        pass


atexit.register(_cleanup_db)

os.environ['DATABASE_URL'] = f'sqlite:///{_DB_PATH}'
os.environ['SECRET_KEY'] = 'test-secret-key-not-for-production'
os.environ['APP_ENV'] = 'development'
os.environ.pop('FLASK_DEBUG', None)
os.environ.pop('BEHIND_PROXY', None)

import pytest

from app import app as flask_app
from app import limiter
from models import db

flask_app.config['TESTING'] = True
# Désactivé par défaut : seul le test dédié l'active (sinon les tests se limitent entre eux).
limiter.enabled = False


@pytest.fixture(autouse=True)
def fresh_db():
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    yield


@pytest.fixture()
def client():
    with flask_app.test_client() as test_client:
        yield test_client


def get_csrf(client, path):
    response = client.get(path)
    assert response.status_code == 200, f'GET {path} -> {response.status_code}'
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f'Jeton CSRF absent de {path}'
    return match.group(1).decode()


def register_admin(client, username='alice', password='FortPassw0rd!x'):
    token = get_csrf(client, '/register')
    response = client.post(
        '/register',
        data={'username': username, 'password': password, 'csrf_token': token},
    )
    assert response.status_code == 302, f'inscription -> {response.status_code}'
    return response


def login_admin(client, username, password):
    token = get_csrf(client, '/login')
    return client.post(
        '/login',
        data={'username': username, 'password': password, 'csrf_token': token},
    )


def create_project(client, name='Projet', password='', labels=None, types=None):
    labels = labels if labels is not None else ['Email', 'Mot de passe']
    types = types if types is not None else ['email', 'password']
    token = get_csrf(client, '/hagar/create')
    response = client.post(
        '/hagar/create',
        data={
            'name': name,
            'password': password,
            'field_label[]': labels,
            'field_type[]': types,
            'csrf_token': token,
        },
    )
    return response
