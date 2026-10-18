import json

from conftest import create_project, register_admin
from models import HagarField, HagarProject, HagarUser, User, db

from app import app as flask_app, init_schema


def _token():
    with flask_app.app_context():
        return HagarProject.query.first().api_token


def _api_headers(token):
    return {'X-Hagar-Token': token}


def test_register_requires_token(client):
    response = client.post(
        '/api/hagar/register',
        data={'Email': 'bob@x.fr', 'Mot de passe': 'azerty12'},
    )
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Jeton API invalide.'


def test_register_and_login_happy_path(client):
    register_admin(client)
    assert create_project(client).status_code == 302
    token = _token()

    response = client.post(
        '/api/hagar/register',
        data={'Email': 'bob@x.fr', 'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 201

    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'bob@x.fr', 'password': 'azerty12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['user_data']['Email'] == 'bob@x.fr'
    # Le mot de passe ne doit jamais figurer dans la réponse
    assert 'azerty12' not in response.get_data(as_text=True)


def test_password_never_stored_in_plaintext(client):
    register_admin(client)
    create_project(client)
    token = _token()

    client.post(
        '/api/hagar/register',
        data={'Email': 'bob@x.fr', 'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )

    with flask_app.app_context():
        h_user = HagarUser.query.first()
        stored = h_user.get_data()
        assert 'azerty12' not in h_user.data
        assert 'Mot de passe' not in stored
        assert h_user.password_hash.startswith('$argon2id$')
        assert h_user.check_password('azerty12')


def test_register_validation(client):
    register_admin(client)
    create_project(client)
    token = _token()

    # Mot de passe trop faible
    response = client.post(
        '/api/hagar/register',
        data={'Email': 'a@x.fr', 'Mot de passe': 'azerty'},
        headers=_api_headers(token),
    )
    assert response.status_code == 400

    # Champ requis manquant
    response = client.post(
        '/api/hagar/register',
        data={'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 400
    assert 'requis' in response.get_json()['error']

    # Identifiant en double
    client.post(
        '/api/hagar/register',
        data={'Email': 'a@x.fr', 'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )
    response = client.post(
        '/api/hagar/register',
        data={'Email': 'a@x.fr', 'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 400
    assert 'existe déjà' in response.get_json()['error']


def test_login_invalid_credentials(client):
    register_admin(client)
    create_project(client)
    token = _token()
    client.post(
        '/api/hagar/register',
        data={'Email': 'bob@x.fr', 'Mot de passe': 'azerty12'},
        headers=_api_headers(token),
    )

    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'bob@x.fr', 'password': 'mauvais12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 401

    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'inconnu@x.fr', 'password': 'azerty12'},
        headers=_api_headers(token),
    )
    assert response.status_code == 401

    response = client.post('/api/hagar/login', data={}, headers=_api_headers(token))
    assert response.status_code == 400


def test_passwordless_project_creation_rejected(client):
    register_admin(client)
    response = create_project(
        client,
        labels=['Email'],
        types=['email'],
    )
    # Redirige vers la création (refusé) : aucun projet créé
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/hagar/create')
    with flask_app.app_context():
        assert HagarProject.query.count() == 0


def test_password_cannot_be_first_field(client):
    register_admin(client)
    response = create_project(
        client,
        labels=['Mot de passe', 'Email'],
        types=['password', 'email'],
    )
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/hagar/create')
    with flask_app.app_context():
        assert HagarProject.query.count() == 0


def test_duplicate_field_label_rejected(client):
    register_admin(client)
    response = create_project(
        client,
        labels=['Email', 'email', 'Mot de passe'],
        types=['email', 'text', 'password'],
    )
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/hagar/create')
    with flask_app.app_context():
        assert HagarProject.query.count() == 0


def test_legacy_no_password_sentinel_migrated(client):
    register_admin(client)
    with flask_app.app_context():
        owner = User.query.first()
        project = HagarProject(name='Legacy', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        db.session.add(HagarField(project_id=project.id, label='Email', field_type='email'))
        db.session.add(
            HagarUser(
                project_id=project.id,
                identifier='old@x.fr',
                password_hash='no_password',
                data=json.dumps({'Email': 'old@x.fr'}),
            )
        )
        db.session.commit()

    init_schema()

    with flask_app.app_context():
        h_user = HagarUser.query.first()
        assert h_user.password_hash is None

    token = _token()
    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'old@x.fr', 'password': 'nimporte'},
        headers=_api_headers(token),
    )
    assert response.status_code == 401
    assert 'mot de passe' in response.get_json()['error'].lower()


def test_legacy_plaintext_password_scrubbed_from_data(client):
    register_admin(client)
    with flask_app.app_context():
        owner = User.query.first()
        project = HagarProject(name='Legacy', owner_id=owner.id)
        db.session.add(project)
        db.session.flush()
        db.session.add(HagarField(project_id=project.id, label='Email', field_type='email'))
        db.session.add(HagarField(project_id=project.id, label='Mot de passe', field_type='password'))
        db.session.add(
            HagarUser(
                project_id=project.id,
                identifier='old@x.fr',
                password_hash='no_password',
                data=json.dumps({'Email': 'old@x.fr', 'Mot de passe': 'SecretEnClair1'}),
            )
        )
        db.session.commit()

    init_schema()

    with flask_app.app_context():
        h_user = HagarUser.query.first()
        assert 'SecretEnClair1' not in h_user.data
        assert h_user.get_data() == {'Email': 'old@x.fr'}


def test_token_rotation_invalidates_old_token(client):
    register_admin(client)
    create_project(client, password='ProjectPw0rd!x')
    old_token = _token()

    with flask_app.app_context():
        project = HagarProject.query.first()
        project_id = project.id

    # Rotation : projet verrouillé -> 403
    from conftest import get_csrf
    response = client.post(
        f'/hagar/{project_id}/token/rotate',
        data={'csrf_token': get_csrf(client, '/dashboard')},
    )
    assert response.status_code == 403

    # Déverrouiller puis tourner
    page = client.get(f'/hagar/{project_id}')
    assert page.status_code == 200
    csrf = get_csrf(client, f'/hagar/{project_id}')
    client.post(
        f'/hagar/{project_id}',
        data={'project_password': 'ProjectPw0rd!x', 'csrf_token': csrf},
    )
    response = client.post(
        f'/hagar/{project_id}/token/rotate',
        data={'csrf_token': get_csrf(client, f'/hagar/{project_id}')},
    )
    assert response.status_code == 302

    new_token = _token()
    assert new_token != old_token

    # L'ancien jeton ne donne plus accès à l'API
    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'a', 'password': 'b'},
        headers=_api_headers(old_token),
    )
    assert response.status_code == 401
    response = client.post(
        '/api/hagar/login',
        data={'identifier': 'a', 'password': 'b'},
        headers=_api_headers(new_token),
    )
    assert response.status_code == 401  # jeton valide, identifiants invalides
    assert 'Jeton' not in response.get_json()['error']


def test_api_token_form_field_fallback(client):
    register_admin(client)
    create_project(client)
    token = _token()
    response = client.post(
        '/api/hagar/register',
        data={'Email': 'c@x.fr', 'Mot de passe': 'azerty12', 'api_token': token},
    )
    assert response.status_code == 201


def test_old_url_token_route_returns_json_404(client):
    register_admin(client)
    create_project(client)
    token = _token()
    response = client.post(f'/api/hagar/{token}/login', data={'identifier': 'a'})
    assert response.status_code == 404
    assert response.is_json
    assert response.get_json()['error'] == 'Page introuvable.'
