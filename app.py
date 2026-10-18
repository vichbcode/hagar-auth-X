import io
import logging
import os
import secrets
from datetime import timedelta

from dotenv import load_dotenv
from flask import (Flask, abort, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, session, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from flask_migrate import Migrate
from flask_talisman import DENY, Talisman
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from sqlalchemy.exc import OperationalError
from werkzeug.exceptions import HTTPException

from models import (HagarField, HagarProject, HagarUser, User, db,
                    dummy_verify, password_needs_rehash, verify_password)
import turso_dialect  # noqa: F401 — enregistre le dialecte « turso » (Turso Cloud)
from validators import (ALLOWED_FIELD_TYPES, MAX_FIELD_VALUE_LENGTH,
                        MAX_IDENTIFIER_LENGTH, MAX_NAME_LENGTH,
                        PASSWORD_RULES_HINT, validate_admin_password,
                        validate_end_user_password, validate_label,
                        validate_project_password, validate_username)

load_dotenv()

APP_ENV = os.environ.get('APP_ENV', 'development').strip().lower()
IS_PRODUCTION = APP_ENV == 'production'


def _env_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


def _load_secret_key():
    key = os.environ.get('SECRET_KEY', '').strip()
    if key:
        return key
    if IS_PRODUCTION:
        raise RuntimeError(
            'SECRET_KEY absente : définissez-la dans .env avant de démarrer en production '
            '(génération : python -c "import secrets; print(secrets.token_hex(32))").'
        )
    logging.getLogger('hagar').warning(
        'SECRET_KEY absente : clé éphémère générée pour cette session '
        '(valide uniquement en développement).'
    )
    return secrets.token_hex(32)


app = Flask(__name__)


def _database_uri():
    """Traduit DATABASE_URL en URI SQLAlchemy.

    - ``libsql://base.org.turso.io`` (URL Turso canonique) → dialecte ``turso``
      (transport HTTP via turso_serverless, multiplateforme).
    - Tout autre valeur (dont ``sqlite:///...``) est utilisée telle quelle.
    """
    url = os.environ.get('DATABASE_URL', 'sqlite:///hagar_auth.db').strip()
    if url.startswith('libsql://'):
        return 'turso:///' + url
    return url


# --- Configuration ---
app.config['SECRET_KEY'] = _load_secret_key()
SESSION_COOKIE_SECURE = _env_flag('SESSION_COOKIE_SECURE', IS_PRODUCTION)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SQLALCHEMY_DATABASE_URI'] = _database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1 Mo par requête

# --- Limites de débit (Flask-Limiter) ---
app.config['RATELIMIT_STORAGE_URI'] = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

_HTTP_MESSAGES = {
    400: 'Requête invalide.',
    403: 'Accès refusé.',
    404: 'Page introuvable.',
    405: 'Méthode non autorisée.',
    413: 'Contenu trop volumineux (1 Mo maximum).',
    429: 'Trop de requêtes. Réessayez plus tard.',
    500: 'Erreur interne du serveur.',
}


def _on_rate_limit_breach(request_limit):
    path = request.path
    if path.startswith('/api/'):
        return make_response(jsonify({'error': 'Trop de requêtes. Réessayez plus tard.'}), 429)
    return make_response(
        render_template('error.html', code=429, message=_HTTP_MESSAGES[429]), 429
    )


app.config['RATELIMIT_ON_BREACH_CALLBACK'] = _on_rate_limit_breach

# --- En-têtes de sécurité (Flask-Talisman) ---
# NB : script-src 'unsafe-inline' est nécessaire tant que les scripts sont
# inline dans les templates (dette à lever en les déplaçant dans static/).
CONTENT_SECURITY_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    'font-src': ['https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:'],
    'connect-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
}

talisman = Talisman(
    app,
    content_security_policy=CONTENT_SECURITY_POLICY,
    frame_options=DENY,
    force_https=IS_PRODUCTION,
    force_https_permanent=IS_PRODUCTION,
    strict_transport_security=IS_PRODUCTION,
    referrer_policy='strict-origin-when-cross-origin',
    session_cookie_secure=SESSION_COOKIE_SECURE,
    session_cookie_http_only=True,
    session_cookie_samesite='Lax',
)


# --- Helpers de limitation de débit ---
def client_ip():
    return get_remote_address()


def _ip_and_username():
    return f'{get_remote_address()}|{request.form.get("username", "")}'


def _ip_and_api_token():
    token = request.headers.get('X-Hagar-Token', '') or request.form.get('api_token', '')
    return f'{get_remote_address()}|{token}'


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=app.config['RATELIMIT_STORAGE_URI'],
)

csrf = CSRFProtect(app)
# CORS strictement limité à l'API publique (jamais sur les pages administrateurs).
# Les pages générées chez les clients appellent l'API depuis d'autres origines.
CORS(app, resources={r'/api/*': {'origins': '*'}})

if _env_flag('BEHIND_PROXY', False):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(
    level=logging.INFO if IS_PRODUCTION else logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- Helpers de session / sécurité ---

def _start_user_session(user):
    """Démarre une session propre après authentification (anti fixation de session)."""
    session.clear()
    login_user(user)
    session.permanent = True


def get_owned_project_or_404(project_id):
    """Récupère un projet en vérifiant une bonne fois pour toutes qu'il appartient à l'utilisateur."""
    project = db.get_or_404(HagarProject, project_id)
    if project.owner_id != current_user.id:
        abort(403)
    return project


def check_project_access(project):
    # Si aucun mot de passe n'est défini pour le projet, l'accès est libre
    if not project.password_hash:
        return True

    session_key = f'unlocked_{project.id}'

    if request.method == 'POST' and 'project_password' in request.form:
        password_input = request.form.get('project_password')
        if project.check_password(password_input):
            session[session_key] = True
            return True
        flash('Mot de passe du Hagar incorrect.', 'error')
        return False

    if session.get(session_key):
        return True

    return False


def _project_from_api_token():
    """Authentifie la requête API par le jeton (header X-Hagar-Token ou champ api_token)."""
    token = (request.headers.get('X-Hagar-Token', '') or request.form.get('api_token', '')).strip()
    if not token or len(token) > 128:
        return None
    return HagarProject.query.filter_by(api_token=token).first()


def public_user_data(project, h_user):
    """Données d'un utilisateur fin, jamais les champs mot de passe."""
    data = h_user.get_data()
    for field in project.fields:
        if field.field_type == 'password':
            data.pop(field.label, None)
    return data


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/confidentialite')
def privacy():
    return render_template('legal/privacy.html')


@app.route('/mentions-legales')
def legal():
    return render_template('legal/mentions.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per hour', methods=['POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        error = validate_username(username) or validate_admin_password(password)
        if error:
            flash(error, 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Ce pseudo existe déjà.', 'error')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _start_user_session(user)
        return redirect(url_for('dashboard'))
    return render_template('auth/register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute', key_func=_ip_and_username, methods=['POST'])
@limiter.limit('30 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if password_needs_rehash(user.password_hash):
                user.set_password(password)
                db.session.commit()
            _start_user_session(user)
            app.logger.info('Connexion admin réussie : user=%s ip=%s', username, client_ip())
            return redirect(url_for('dashboard'))
        if user is None:
            dummy_verify(password)
        app.logger.warning('Échec de connexion admin : user=%s ip=%s', username, client_ip())
        flash('Pseudo ou mot de passe invalide.', 'error')
    return render_template('auth/login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password') or ''
        new_username = (request.form.get('username') or '').strip()
        new_password = request.form.get('password') or ''

        if not current_user.check_password(current_password):
            flash('Mot de passe actuel incorrect.', 'error')
            return render_template('auth/profile.html')

        if new_username and new_username != current_user.username:
            error = validate_username(new_username)
            if error:
                flash(error, 'error')
                return render_template('auth/profile.html')
            if User.query.filter(User.username == new_username, User.id != current_user.id).first():
                flash('Ce pseudo est déjà pris.', 'error')
                return render_template('auth/profile.html')
            current_user.username = new_username

        if new_password:
            error = validate_admin_password(new_password)
            if error:
                flash(error, 'error')
                return render_template('auth/profile.html')
            current_user.set_password(new_password)

        db.session.commit()
        app.logger.info('Profil mis à jour : user=%s', current_user.username)
        flash('Profil mis à jour avec succès !', 'success')
    return render_template('auth/profile.html')


@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    session.clear()
    flash('Votre compte et toutes les données associées ont été supprimés définitivement.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # "Verrouillé tout le temps" : on oublie les déverrouillages dès qu'on revient au dashboard
    keys_to_remove = [key for key in session.keys() if key.startswith('unlocked_')]
    for key in keys_to_remove:
        session.pop(key)

    projects = current_user.projects
    return render_template('dashboard.html', projects=projects)


@app.route('/hagar/create', methods=['GET', 'POST'])
@login_required
def create_hagar():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        project_password = request.form.get('password') or ''
        labels = request.form.getlist('field_label[]')
        types = request.form.getlist('field_type[]')

        if not name or len(name) > MAX_NAME_LENGTH:
            flash(f'Nom du Hagar requis (1 à {MAX_NAME_LENGTH} caractères).', 'error')
            return redirect(url_for('create_hagar'))

        if project_password:
            error = validate_project_password(project_password)
            if error:
                flash(error, 'error')
                return redirect(url_for('create_hagar'))
            for existing_project in current_user.projects:
                if existing_project.password_hash and existing_project.check_password(project_password):
                    flash('Sécurité : Vous utilisez déjà ce mot de passe pour un autre Hagar. Veuillez en choisir un différent.', 'error')
                    return redirect(url_for('create_hagar'))

        clean_fields = []
        seen_labels = set()
        for label, ftype in zip(labels, types):
            clean_label, error = validate_label(label)
            if error:
                flash(error, 'error')
                return redirect(url_for('create_hagar'))
            if ftype not in ALLOWED_FIELD_TYPES:
                flash(f'Type de champ non autorisé : {ftype}', 'error')
                return redirect(url_for('create_hagar'))
            label_key = clean_label.casefold()
            if label_key in seen_labels:
                flash(f'Le champ « {clean_label} » est en double.', 'error')
                return redirect(url_for('create_hagar'))
            seen_labels.add(label_key)
            clean_fields.append((clean_label, ftype))

        if not clean_fields:
            flash('Ajoutez au moins un champ à votre formulaire.', 'error')
            return redirect(url_for('create_hagar'))
        if clean_fields[0][1] == 'password':
            flash("Le premier champ ne peut pas être un mot de passe : il sert d'identifiant unique.", 'error')
            return redirect(url_for('create_hagar'))
        if not any(ftype == 'password' for _, ftype in clean_fields):
            flash('Sécurité : ajoutez au moins un champ de type « Mot de passe » pour authentifier vos utilisateurs.', 'error')
            return redirect(url_for('create_hagar'))

        project = HagarProject(name=name, owner_id=current_user.id)
        if project_password:
            project.set_password(project_password)

        db.session.add(project)
        db.session.flush()

        for clean_label, ftype in clean_fields:
            db.session.add(HagarField(project_id=project.id, label=clean_label, field_type=ftype))

        db.session.commit()
        flash('Hagar créé avec succès !', 'success')
        return redirect(url_for('hagar_details', project_id=project.id))

    return render_template('hagar/create.html')


@app.route('/hagar/<int:project_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit('10 per minute', methods=['POST'])
def hagar_details(project_id):
    project = get_owned_project_or_404(project_id)

    if not check_project_access(project):
        return render_template('hagar/unlock.html', project=project)

    display_token = not project.token_viewed
    if display_token:
        project.token_viewed = True
        db.session.commit()

    return render_template('hagar/details.html', project=project, display_token=display_token)


@app.route('/hagar/<int:project_id>/users', methods=['GET', 'POST'])
@login_required
@limiter.limit('10 per minute', methods=['POST'])
def hagar_users(project_id):
    project = get_owned_project_or_404(project_id)

    if not check_project_access(project):
        return render_template('hagar/unlock.html', project=project)

    users = project.users
    fields = project.fields
    return render_template('hagar/users.html', project=project, users=users, fields=fields)


@app.route('/hagar/<int:project_id>/token/rotate', methods=['POST'])
@login_required
def rotate_api_token(project_id):
    project = get_owned_project_or_404(project_id)

    if project.password_hash and not session.get(f'unlocked_{project.id}'):
        abort(403)

    project.api_token = secrets.token_hex(32)
    project.token_viewed = False
    db.session.commit()
    app.logger.info('Rotation du jeton API : project=%s owner=%s', project.id, current_user.id)
    flash('Nouveau jeton API généré : l\'ancien est immédiatement révoqué. Mettez à jour vos fichiers intégrés (inscription/connexion/config).', 'success')
    return redirect(url_for('hagar_details', project_id=project.id))


@app.route('/hagar/<int:project_id>/download/<type>')
@login_required
def download_file(project_id, type):
    project = get_owned_project_or_404(project_id)

    if project.password_hash and not session.get(f'unlocked_{project.id}'):
        abort(403)

    if type == 'signup':
        filename = 'inscription.html'
        content = render_template('hagar/gen_signup.html', project=project)
    elif type == 'login':
        filename = 'connexion.html'
        content = render_template('hagar/gen_login.html', project=project)
    elif type == 'config':
        filename = 'hagar_config.js'
        content = f"const HAGAR_CONFIG = {{\n  api_token: '{project.api_token}',\n  base_url: '{request.host_url.rstrip('/')}'\n}};"
    else:
        abort(400)

    return send_file(io.BytesIO(content.encode('utf-8')), mimetype='text/plain', as_attachment=True, download_name=filename)


@app.route('/hagar/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_hagar(project_id):
    project = get_owned_project_or_404(project_id)

    if project.password_hash and not session.get(f'unlocked_{project.id}'):
        abort(403)

    db.session.delete(project)
    db.session.commit()
    flash(f'Le Hagar "{project.name}" a été supprimé.', 'success')
    return redirect(url_for('dashboard'))


# --- API publique (les pages générées chez les clients en appellent) ---
# Authentification par le jeton du projet : header X-Hagar-Token de préférence,
# champ de formulaire api_token en secours. Jamais dans l'URL (ni logs ni historique).

@app.route('/api/hagar/register', methods=['POST'])
@csrf.exempt
@limiter.limit('30 per minute', methods=['POST'])
@limiter.limit('60 per minute', key_func=_ip_and_api_token, methods=['POST'])
def hagar_api_register():
    project = _project_from_api_token()
    if project is None:
        return jsonify({'error': 'Jeton API invalide.'}), 401

    if not project.fields:
        return jsonify({'error': 'Ce projet n\'a pas de champ configuré.'}), 400

    password_labels = {f.label for f in project.fields if f.field_type == 'password'}
    identifier = None
    password = None
    data = {}

    for field in project.fields:
        value = request.form.get(field.label)
        if value is None and field.field_type in ('checkbox', 'radio'):
            value = ''  # case non cochée / radio absent du POST
        if value is None:
            if field.is_required:
                return jsonify({'error': f'Le champ « {field.label} » est requis.'}), 400
            value = ''
        value = value.strip() if isinstance(value, str) else str(value)
        if len(value) > MAX_FIELD_VALUE_LENGTH:
            return jsonify({'error': f'Le champ « {field.label} » est trop long.'}), 400

        if identifier is None:
            identifier = value
        if field.field_type == 'password':
            password = value

        # Les mots de passe ne sont JAMAIS stockés dans la colonne JSON data
        if field.label in password_labels:
            continue
        data[field.label] = value

    if not identifier:
        return jsonify({'error': 'Identifiant requis.'}), 400
    if len(identifier) > MAX_IDENTIFIER_LENGTH:
        return jsonify({'error': f'L\'identifiant ne peut pas dépasser {MAX_IDENTIFIER_LENGTH} caractères.'}), 400

    if not password_labels:
        return jsonify({'error': 'Ce projet ne possède pas de champ mot de passe : recréez-le avec un champ « Mot de passe » (obligatoire depuis la mise à jour de sécurité).'}), 400
    if not password:
        return jsonify({'error': 'Mot de passe requis.'}), 400
    error = validate_end_user_password(password)
    if error:
        return jsonify({'error': error}), 400

    if HagarUser.query.filter_by(project_id=project.id, identifier=identifier).first():
        return jsonify({'error': 'L\'utilisateur existe déjà.'}), 400

    h_user = HagarUser(project_id=project.id, identifier=identifier)
    h_user.set_password(password)
    h_user.set_data(data)

    db.session.add(h_user)
    db.session.commit()
    app.logger.info('Inscription API : project=%s identifier=%s ip=%s', project.id, identifier, client_ip())
    return jsonify({'message': 'Inscription réussie !'}), 201


@app.route('/api/hagar/login', methods=['POST'])
@csrf.exempt
@limiter.limit('30 per minute', methods=['POST'])
@limiter.limit('60 per minute', key_func=_ip_and_api_token, methods=['POST'])
def hagar_api_login():
    project = _project_from_api_token()
    if project is None:
        return jsonify({'error': 'Jeton API invalide.'}), 401

    identifier = (request.form.get('identifier') or '').strip()
    password = request.form.get('password') or ''
    if not identifier or not password:
        return jsonify({'error': 'Identifiant et mot de passe requis.'}), 400

    h_user = HagarUser.query.filter_by(project_id=project.id, identifier=identifier).first()
    if h_user is None:
        dummy_verify(password)
        app.logger.warning('Échec connexion API : project=%s identifier=%s ip=%s', project.id, identifier, client_ip())
        return jsonify({'error': 'Identifiants invalides.'}), 401

    if not h_user.password_hash:
        # Compte hérité créé avant l'exigence de mot de passe (sentinel "no_password")
        return jsonify({'error': 'Ce compte ne possède pas de mot de passe. Réinscrivez-vous avec un mot de passe.'}), 401

    if not h_user.check_password(password):
        app.logger.warning('Échec connexion API : project=%s identifier=%s ip=%s', project.id, identifier, client_ip())
        return jsonify({'error': 'Identifiants invalides.'}), 401

    if password_needs_rehash(h_user.password_hash):
        h_user.set_password(password)
        db.session.commit()
    app.logger.info('Connexion API réussie : project=%s identifier=%s ip=%s', project.id, identifier, client_ip())
    return jsonify({'message': 'Connexion réussie !', 'user_data': public_user_data(project, h_user)}), 200


# --- Gestion des erreurs ---

@app.errorhandler(HTTPException)
def handle_http_exception(exc):
    # Respecte une réponse déjà construite (ex : callback de limite de débit)
    if getattr(exc, 'response', None) is not None:
        return exc.response
    if isinstance(exc, CSRFError):
        message = 'Jeton de sécurité (CSRF) expiré ou invalide. Rechargez la page et réessayez.'
    else:
        message = _HTTP_MESSAGES.get(exc.code) or exc.description or 'Erreur.'
    if request.path.startswith('/api/'):
        return jsonify({'error': message}), exc.code or 500
    return render_template('error.html', code=exc.code or 500, message=message), exc.code or 500


# --- Initialisation du schéma + migrations de sécurité idempotentes ---

def _scrub_plaintext_passwords():
    """ retire les mots de passe éventuellement stockés en clair dans data (ancienne version)."""
    try:
        h_users = db.session.scalars(db.select(HagarUser)).all()
    except OperationalError:
        db.session.rollback()
        return
    for h_user in h_users:
        try:
            data = h_user.get_data()
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        project = db.session.get(HagarProject, h_user.project_id)
        if project is None:
            continue
        pw_labels = {f.label for f in project.fields if f.field_type == 'password'}
        if pw_labels & set(data):
            for label in pw_labels:
                data.pop(label, None)
            h_user.set_data(data)
    db.session.commit()


def init_schema():
    """Crée les tables et applique les migrations de sécurité (sans effet si déjà fait)."""
    with app.app_context():
        db.create_all()
        for ddl in (
            'ALTER TABLE hagar_project ADD COLUMN password_hash VARCHAR(256)',
            'ALTER TABLE hagar_project ADD COLUMN token_viewed BOOLEAN DEFAULT 0',
        ):
            try:
                db.session.execute(db.text(ddl))
                db.session.commit()
            except OperationalError:
                db.session.rollback()
        # Ancien sentinel "no_password" → NULL (vérifié proprement par verify_password)
        try:
            db.session.execute(db.text(
                "UPDATE hagar_user SET password_hash = NULL WHERE password_hash = 'no_password'"
            ))
            db.session.commit()
        except OperationalError:
            db.session.rollback()
        _scrub_plaintext_passwords()


init_schema()


if __name__ == '__main__':
    debug = (not IS_PRODUCTION) and _env_flag('FLASK_DEBUG', True)
    app.run(debug=debug)
