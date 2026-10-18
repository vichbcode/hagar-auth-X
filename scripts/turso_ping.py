"""Vérifie la connexion à la base Turso et liste son schéma.

Usage (depuis la racine du projet, .env renseigné) :
    .venv\\Scripts\\python.exe scripts/turso_ping.py

Nécessite TURSO_AUTH_TOKEN dans .env ou dans l'environnement.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

REMOTE_URL = os.environ.get('DATABASE_URL', '').strip()
TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '').strip()


def main():
    if not REMOTE_URL.startswith('libsql://'):
        print(f'DATABASE_URL n\'est pas une URL Turso : {REMOTE_URL or "(vide)"}')
        sys.exit(1)
    if not TOKEN:
        print('TURSO_AUTH_TOKEN absente : générez-la avec '
              '"turso db tokens create hagar-auth-vichbcode" puis '
              'ajoutez-la dans .env.')
        sys.exit(1)

    import turso_serverless

    print(f'Connexion à {REMOTE_URL} ...')
    conn = turso_serverless.connect(REMOTE_URL, auth_token=TOKEN)

    version = conn.execute('select sqlite_version()').fetchone()[0]
    print(f'OK — moteur : sqlite_version={version}')

    tables = [
        row[0]
        for row in conn.execute(
            "select name from sqlite_master where type='table' order by name"
        ).fetchall()
    ]
    if tables:
        print('Tables présentes :', ', '.join(tables))
        for table in tables:
            count = conn.execute(f'select count(*) from "{table}"').fetchone()[0]
            print(f'  - {table} : {count} ligne(s)')
    else:
        print('Aucune table : lancez ensuite l\'application '
              '(init_schema crée le schéma au démarrage).')
    conn.close()


if __name__ == '__main__':
    main()
