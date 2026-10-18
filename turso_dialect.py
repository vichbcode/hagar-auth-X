"""Dialecte SQLAlchemy pour les bases Turso / libSQL.

Utilise le driver ``turso_serverless`` (HTTP, pur Python) plutôt que
``libsql_experimental`` (extension native qui n'existe pas sous Windows).
Compatible Windows, Linux et macOS — requis partout où l'application se
connecte à ``libsql://``.

Enregistrement : ``registry.register("turso", "turso_dialect", "TursoDialect")``
est appelé au bas du module. URL supportée :

    turso:///libsql://<base>.<org>.turso.io

Le jeton d'authentification est lu dans la requête (``?auth_token=``) ou,
de préférence, dans la variable d'environnement ``TURSO_AUTH_TOKEN``.
"""

import os
import re

from sqlalchemy.dialects import registry
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite

_TURSO_SCHEMES = ('libsql://', 'turso://', 'http://', 'https://')


class TursoDialect(SQLiteDialect_pysqlite):
    driver = 'turso_serverless'
    supports_statement_cache = True

    @classmethod
    def import_dbapi(cls):
        import turso_serverless
        # SQLiteDialect_pysqlite lit sqlite_version_info au chargement du
        # dialecte ; la version réelle est détectée dans on_connect().
        if not hasattr(turso_serverless, 'sqlite_version_info'):
            turso_serverless.sqlite_version_info = (3, 45, 0)
        return turso_serverless

    def on_connect(self):
        def connect(conn):
            # Les PRAGMA SQLite (foreign_keys, JSON, ...) et create_function()
            # ne sont pas supportés sur le transport HTTP. L'engine Turso est
            # récent : on suppose les fonctionnalités modernes (RETURNING...).
            try:
                cursor = conn.cursor()
                cursor.execute('select sqlite_version()')
                row = cursor.fetchone()
                cursor.close()
                if row and row[0]:
                    parts = re.findall(r'\d+', str(row[0]))[:3]
                    self._version = tuple(int(p) for p in parts) if parts else (3, 45, 0)
            except Exception:
                self._version = (3, 45, 0)
        return connect

    def create_connect_args(self, url):
        database = url.database or ''
        if database.startswith('turso://'):
            database = 'libsql://' + database[len('turso://'):]
        opts = {}
        token = url.query.get('auth_token') or os.environ.get('TURSO_AUTH_TOKEN', '').strip()
        if database.startswith(_TURSO_SCHEMES):
            if not token:
                raise RuntimeError(
                    'TURSO_AUTH_TOKEN absente : générez-la avec '
                    '"turso db tokens create <base>" puis ajoutez-la dans .env.'
                )
            return ([database], {'auth_token': token})
        # Repli : base locale ou mémoire (utile pour les tests avec
        # connect_args={'database': ':memory:'} et un module stubbé).
        if database:
            return ([database], {})
        return ([], {})


registry.register('turso', 'turso_dialect', 'TursoDialect')
