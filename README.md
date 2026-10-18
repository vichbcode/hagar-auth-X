# Hagar-Auth

Service d'authentification externalisée : créez des projets avec des champs
personnalisés, générez des fichiers d'inscription/connexion pour vos clients,
et communiquez via une API REST sécurisée par jeton.

## Stack

- Python 3.13 · Flask 3 · SQLAlchemy · Waitress
- Base de données : **Turso Cloud** (libSQL, transport HTTP) ou SQLite local
- Argon2id pour les mots de passe (repli vérification sur hashes Werkzeug legacy)
- CSRF (Flask-WTF) · CORS restreint · Rate limiting (Flask-Limiter) · En-têtes (Talisman)

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # puis éditer SECRET_KEY
```

Générer une clé secrète :

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Configuration (`.env`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SECRET_KEY` | — (obligatoire) | Signature des sessions/CSRF |
| `DATABASE_URL` | `sqlite:///hagar_auth.db` | `libsql://...` = Turso Cloud ; sinon SQLite |
| `TURSO_AUTH_TOKEN` | — | Jeton d'accès Turso (obligatoire si URL libsql) |
| `APP_ENV` | `development` | `production` active HSTS, cookies `Secure`, HTTPS forcé |
| `FLASK_DEBUG` | — | `1` active le rechargement auto (jamais en prod) |
| `MAX_CONTENT_LENGTH` | `1048576` (1 Mo) | Taille max des requêtes |
| `BEHIND_PROXY` | — | `1` si derrière un proxy (active `ProxyFix`, X-Forwarded-For/Proto) |
| `RATELIMIT_ENABLED` | `1` | `0` désactive temporairement les limites |

## Base de données Turso (cloud)

Le projet est configuré pour **Turso Cloud** via le driver HTTP pur Python
`turso_serverless` (fonctionne sous Windows, Linux et macOS — contrairement au
driver natif `libsql-experimental` qui n'a pas de binaire Windows).

1. Créer la base : `turso db create hagar-auth-vichbcode`
2. Générer un jeton : `turso db tokens create hagar-auth-vichbcode`
3. Coller le jeton dans `.env` → `TURSO_AUTH_TOKEN=...`
4. Vérifier : `.\.venv\Scripts\python.exe scripts\turso_ping.py`
5. Démarrer l'application : `init_schema()` crée les tables (et applique les
   migrations de sécurité) au premier lancement.

Le schéma Turso est compatible SQLite. Pour un retour en local :
`DATABASE_URL=sqlite:///hagar_auth.db` (ou supprimez la variable).

## Développement

```powershell
$env:FLASK_DEBUG = "1"; flask --app app run
# ou
.\.venv\Scripts\python.exe app.py
```

Tests :

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Au premier démarrage, `init_schema()` crée les tables et applique les
migrations de sécurité idempotentes : rehash des anciens hashes vers Argon2,
nettoyage des mots de passe laissés en clair dans les données JSON, remplacement
du jeton hérité `"no_password"` par un champ sans mot de passe.

## Production

```powershell
$env:APP_ENV = "production"
waitress-serve --host 127.0.0.1 --port 8000 app:app
```

Placer un reverse proxy (nginx, Caddy…) devant avec HTTPS. Si le proxy
gère le TLS, définir `BEHIND_PROXY=1` pour lire les en-têtes `X-Forwarded-*`.

Dans `APP_ENV=production` : HSTS activé, cookies de session `Secure`,
redirection HTTP→HTTPS, `SESSION_COOKIE_SECURE` et `FORCE_HTTPS` suivent
l'environnement.

## API (fournisseurs / clients finaux)

Toutes les routes `/api/*`. Authentification par **en-tête** `X-Hagar-Token`
(ancien format d'URL `/api/hagar/<token>/...` supprimé, renvoie du JSON 404).

### Inscription

```
POST /api/hagar/register
X-Hagar-Token: <jeton>
Content-Type: application/x-www-form-urlencoded

Email=client@exemple.fr&Mot de passe=azerty12
```

Les clés du formulaire sont les **libellés de champs du projet** (le champ
« Mot de passe » est obligatoire à la création d'un projet). Réponses :
`201` créé · `400` validation (mdp faible, champ requis manquant, identifiant
existant) · `401` jeton invalide · `404` ancienne URL token · `413` corps > 2 Mo
· `429` rate limit — tous en JSON `{"error": "..."}`.

### Connexion

```
POST /api/hagar/login
X-Hagar-Token: <jeton>

identifier=client@exemple.fr&password=azerty12
```

`200` avec les données utilisateur (jamais le mot de passe) · `401` identifiants
invalides, ou compte migré hérité sans mot de passe · `400` champs manquants.

### Limites

- API : 30 req/min par IP + 60/min par IP+jeton
- Login admin : 10/min par utilisateur+IP, 30/min par IP
- Création de compte admin : 5/h · Démarrage de session projet : 10/min

Désactivables temporairement avec `RATELIMIT_ENABLED=0` (ne pas laisser actif
en production).

## Interface d'administration

- `/register` — création compte admin (mots de passe forts : min. 12 caractères
  avec 3 catégories)
- `/hagar/create` — création de projet (champ « Mot de passe » obligatoire,
  en deuxième position minimum)
- Détail projet verrouillé par mot de passe projet : téléchargements des
  fichiers HTML générés, rotation du jeton API, suppression
- `/profile` — changement de mot de passe exigeant le mot de passe actuel
- `/logout` — POST uniquement (anti-CSRF)

## Fichiers générés

Les fichiers HTML de signup/login utilisent l'en-tête `X-Hagar-Token`
(le jeton n'apparaît plus dans l'URL). L'URL de l'API est déduite du
`Host` de la requête (pas d'adresse codée en dur).

## Base de données en production

- Turso : le schéma est créé/ migré automatiquement au démarrage par
  `init_schema()` (tables, colonnes manquantes, nettoyage des mots de passe
  hérités). Vérification manuelle : `python scripts/turso_ping.py`.
- SQLite local : même mécanisme, base dans `instance/`.
- Flask-Migrate est branché (`flask --app app db upgrade`) si vous préférez
  des migrations explicites.
- Après déploiement : créez un mot de passe fort pour le compte admin,
  et recréez tout projet hérité sans champ mot de passe (l'API refuse
  les projets hérités sans mdp avec un message explicite).
