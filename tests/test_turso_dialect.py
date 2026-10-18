import os
import sqlite3
import tempfile

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

import turso_dialect  # noqa: F401 — enregistre le dialecte « turso »
from turso_dialect import TursoDialect

FAKE_URL = 'turso:///libsql://hagar-auth-vichbcode.aws-eu-west-1.turso.io'


def test_url_parsing():
    parsed = make_url(FAKE_URL)
    assert parsed.drivername == 'turso'
    assert parsed.database == 'libsql://hagar-auth-vichbcode.aws-eu-west-1.turso.io'


def test_create_connect_args_uses_env_token(monkeypatch):
    monkeypatch.setenv('TURSO_AUTH_TOKEN', 'secret-jeton')
    dialect = TursoDialect()
    parsed = make_url(FAKE_URL)
    args, opts = dialect.create_connect_args(parsed)
    assert args == ['libsql://hagar-auth-vichbcode.aws-eu-west-1.turso.io']
    assert opts == {'auth_token': 'secret-jeton'}


def test_create_connect_args_missing_token(monkeypatch):
    monkeypatch.delenv('TURSO_AUTH_TOKEN', raising=False)
    dialect = TursoDialect()
    with pytest.raises(RuntimeError, match='TURSO_AUTH_TOKEN'):
        dialect.create_connect_args(make_url(FAKE_URL))


def test_create_connect_args_local_fallback():
    dialect = TursoDialect()
    args, opts = dialect.create_connect_args(make_url('turso://'))
    assert args == []
    assert opts == {}


def test_dialect_end_to_end_with_stubbed_transport(monkeypatch):
    """Simule Turso avec sqlite3 en fichier pour valider tout le plumbing."""
    fd, dbfile = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    os.remove(dbfile)

    import turso_serverless
    monkeypatch.setattr(
        turso_serverless, 'connect',
        lambda url, **kw: sqlite3.connect(dbfile, timeout=30),
    )
    monkeypatch.setenv('TURSO_AUTH_TOKEN', 'test-token')

    engine = create_engine(FAKE_URL)
    with engine.connect() as conn:
        conn.execute(text('CREATE TABLE t (id INTEGER PRIMARY KEY, nom TEXT)'))
        conn.execute(text('INSERT INTO t (nom) VALUES (:n)'), {'n': 'alice'})
        conn.commit()
        assert conn.execute(text('SELECT nom FROM t')).scalar() == 'alice'
    engine.dispose()

    # Couche ORM complète (équivalent Flask-SQLAlchemy)
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = FAKE_URL
    db = SQLAlchemy(app)

    class Item(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        nom = db.Column(db.String(50))

    with app.app_context():
        db.create_all()
        db.session.add(Item(nom='bob'))
        db.session.commit()
        assert db.session.execute(db.select(Item.nom)).scalar() == 'bob'
        tables = db.session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).scalars().all()
        assert 'item' in tables
        db.engine.dispose()

    try:
        os.remove(dbfile)
    except OSError:
        pass  # Windows peut garder le fichier verrouillé jusqu'au GC


def test_app_uri_rewriting():
    from app import _database_uri

    current = os.environ.get('DATABASE_URL')
    try:
        os.environ['DATABASE_URL'] = 'libsql://mon-base.turso.io'
        assert _database_uri() == 'turso:///libsql://mon-base.turso.io'
        os.environ['DATABASE_URL'] = 'sqlite:///local.db'
        assert _database_uri() == 'sqlite:///local.db'
    finally:
        if current is not None:
            os.environ['DATABASE_URL'] = current
