from conftest import get_csrf, login_admin, register_admin
from models import User, db

from app import app as flask_app


def test_register_rejects_weak_password(client):
    token = get_csrf(client, '/register')
    response = client.post(
        '/register',
        data={'username': 'alice', 'password': 'faible', 'csrf_token': token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert 'caractères' in response.get_data(as_text=True)
    with flask_app.app_context():
        assert User.query.count() == 0


def test_register_rejects_bad_username(client):
    token = get_csrf(client, '/register')
    client.post(
        '/register',
        data={'username': 'a b', 'password': 'FortPassw0rd!x', 'csrf_token': token},
    )
    with flask_app.app_context():
        assert User.query.count() == 0


def test_register_duplicate_username(client):
    register_admin(client, 'alice', 'FortPassw0rd!x')
    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    token = get_csrf(client, '/register')
    response = client.post(
        '/register',
        data={'username': 'alice', 'password': 'FortPassw0rd!x', 'csrf_token': token},
        follow_redirects=True,
    )
    assert 'existe déjà' in response.get_data(as_text=True)
    with flask_app.app_context():
        assert User.query.count() == 1


def test_login_logout_flow(client):
    register_admin(client, 'alice', 'FortPassw0rd!x')
    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})

    response = login_admin(client, 'alice', 'mauvais')
    assert response.status_code == 200  # reste sur la page de connexion
    response = login_admin(client, 'alice', 'FortPassw0rd!x')
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/dashboard')

    # Déconnexion : GET refusé (anti-CSRF), POST accepté
    assert client.get('/logout').status_code == 405
    response = client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_profile_requires_current_password(client):
    register_admin(client, 'alice', 'FortPassw0rd!x')

    # Mauvais mot de passe actuel : refusé, rien ne change
    token = get_csrf(client, '/profile')
    response = client.post(
        '/profile',
        data={
            'username': 'alice2',
            'password': 'NouveauMot123!x',
            'current_password': 'mauvais',
            'csrf_token': token,
        },
        follow_redirects=True,
    )
    assert 'incorrect' in response.get_data(as_text=True)
    with flask_app.app_context():
        user = User.query.filter_by(username='alice').first()
        assert user is not None
        assert user.check_password('FortPassw0rd!x')

    # Nouveau mot de passe trop faible : refusé
    token = get_csrf(client, '/profile')
    response = client.post(
        '/profile',
        data={
            'username': 'alice',
            'password': 'court',
            'current_password': 'FortPassw0rd!x',
            'csrf_token': token,
        },
        follow_redirects=True,
    )
    assert 'caractères' in response.get_data(as_text=True)
    with flask_app.app_context():
        assert User.query.filter_by(username='alice').first().check_password('FortPassw0rd!x')

    # Bon mot de passe actuel + nouveau fort : accepté
    token = get_csrf(client, '/profile')
    response = client.post(
        '/profile',
        data={
            'username': 'alice',
            'password': 'NouveauMot123!x',
            'current_password': 'FortPassw0rd!x',
            'csrf_token': token,
        },
        follow_redirects=True,
    )
    assert 'succès' in response.get_data(as_text=True)
    with flask_app.app_context():
        assert User.query.filter_by(username='alice').first().check_password('NouveauMot123!x')


def test_profile_rejects_username_taken(client):
    register_admin(client, 'alice', 'FortPassw0rd!x')
    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    register_admin(client, 'bob', 'FortPassw0rd!x')
    client.post('/logout', data={'csrf_token': get_csrf(client, '/dashboard')})
    login_admin(client, 'alice', 'FortPassw0rd!x')

    token = get_csrf(client, '/profile')
    response = client.post(
        '/profile',
        data={
            'username': 'bob',
            'password': '',
            'current_password': 'FortPassw0rd!x',
            'csrf_token': token,
        },
        follow_redirects=True,
    )
    assert 'déjà pris' in response.get_data(as_text=True)


def test_legacy_werkzeug_hash_upgraded_on_login(client):
    from werkzeug.security import generate_password_hash

    with flask_app.app_context():
        user = User(username='legacy', password_hash=generate_password_hash('LegacyPw123!x'))
        db.session.add(user)
        db.session.commit()

    response = login_admin(client, 'legacy', 'LegacyPw123!x')
    assert response.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(username='legacy').first()
        assert user.password_hash.startswith('$argon2id$')
        assert user.check_password('LegacyPw123!x')
