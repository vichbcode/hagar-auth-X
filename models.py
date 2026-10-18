from datetime import datetime, timezone
import json
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import (
    Argon2Error,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash

db = SQLAlchemy()

# Argon2id : algorithme recommandé pour le hachage de mots de passe.
# Les anciens hashes Werkzeug (PBKDF2) restent vérifiables et sont
# automatiquement ré-hachés en Argon2 lors d'une connexion réussie.
_password_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

# Hash factice : vérifié quand un compte n'existe pas, pour que le temps
# de réponse soit identique (protection anti-énumération de comptes).
_DUMMY_HASH = _password_hasher.hash(secrets.token_urlsafe(16))


def utcnow():
    """Horodatage UTC naïf (compatible SQLite, sans DeprecationWarning)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(stored_hash, password) -> bool:
    """Vérifie un hash Argon2 (nouveau format) ou Werkzeug (héritage)."""
    if not stored_hash or not password:
        return False
    if stored_hash.startswith("$argon2"):
        try:
            return _password_hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError, Argon2Error):
            return False
    try:
        return check_password_hash(stored_hash, password)
    except (ValueError, TypeError):
        return False


def dummy_verify(password) -> bool:
    """Vérification factice pour uniformiser les temps de réponse."""
    verify_password(_DUMMY_HASH, password)
    return False


def password_needs_rehash(stored_hash) -> bool:
    """True si le hash doit être régénéré (héritage Werkzeug ou paramètres obsolètes)."""
    if not stored_hash:
        return False
    if not stored_hash.startswith("$argon2"):
        return True
    try:
        return _password_hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, Argon2Error):
        return True


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    projects = db.relationship('HagarProject', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = hash_password(password)

    def check_password(self, password):
        return verify_password(self.password_hash, password)


class HagarProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) # Optional project password
    api_token = db.Column(db.String(64), unique=True, default=lambda: secrets.token_hex(32))
    token_viewed = db.Column(db.Boolean, default=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    fields = db.relationship('HagarField', backref='project', lazy=True, cascade="all, delete-orphan")
    users = db.relationship('HagarUser', backref='project', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        if password:
            self.password_hash = hash_password(password)
        else:
            self.password_hash = None

    def check_password(self, password):
        if not self.password_hash:
            return True
        return verify_password(self.password_hash, password)


class HagarField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('hagar_project.id'), nullable=False)
    label = db.Column(db.String(100), nullable=False)
    field_type = db.Column(db.String(50), nullable=False)
    is_required = db.Column(db.Boolean, default=True)


class HagarUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('hagar_project.id'), nullable=False)
    # Each registered user has at least an identifier (usually the first field) and a password
    identifier = db.Column(db.String(150), nullable=False)
    # NULL uniquement pour les comptes hérités créés avant l'exigence de mot de passe
    password_hash = db.Column(db.String(256), nullable=True)
    # JSON de tous les champs SAUF les mots de passe (jamais stockés en clair)
    data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password):
        self.password_hash = hash_password(password)

    def check_password(self, password):
        return verify_password(self.password_hash, password)

    def get_data(self):
        return json.loads(self.data)

    def set_data(self, data_dict):
        self.data = json.dumps(data_dict, ensure_ascii=False)
