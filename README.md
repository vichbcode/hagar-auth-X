# Hagar-Auth

Service d'authentification **clé en main** : vous créez un projet (« Hagar »),
vous définissez les champs de votre choix, et l'app génère des formulaires
d'inscription/connexion prêts à intégrer sur n'importe quel site. Les comptes
de vos utilisateurs sont stockés de façon sécurisée, et vous consultez la liste
des inscrits depuis votre tableau de bord.

Vous n'avez pas à écrire de backend : vous déposez les fichiers générés et
l'authentification fonctionne.

---

## Comment ça marche

```
Votre site (fichiers générés)          Hagar-Auth                Tableau de bord
┌───────────────────────┐        ┌────────────────────┐        ┌──────────────────┐
│ inscription.html      │  POST  │  /api/hagar/       │  crée  │  liste des       │
│ connexion.html        │ ─────► │    register/login  │ ─────► │  utilisateurs    │
│ (jeton X-Hagar-Token) │        │  (stockage sécurisé)│        │  du projet       │
└───────────────────────┘        └────────────────────┘        └──────────────────┘
```

Chaque projet possède sa **propre clé API** (jeton) et sa **propre structure de
champs**. Les fichiers générés embarquent ce jeton : ils enregistrent et
connectent uniquement les utilisateurs de ce projet.

---

## Utilisation pas à pas

### 1. Créer un compte administrateur

- Allez sur `/register` et choisissez un pseudo et un mot de passe fort
  (minimum 12 caractères, au moins 3 catégories de caractères).
- Ensuite, connectez-vous via `/login`.

### 2. Créer un Hagar (votre projet)

- Cliquez sur **Créer un nouveau Hagar**.
- Donnez-lui un **nom** (ex. « Boutique Alpha »).
- Optionnel : un **mot de passe de projet** qui protège l'accès aux données
  (les fichiers générés, la clé API et la liste des utilisateurs).
- Définissez la **structure des utilisateurs** : une liste de champs
  (nom + type). Le **premier champ** sert d'identifiant unique
  (ex. Email, Pseudo, ID).
- **Un champ « Mot de passe » est obligatoire** : sans lui, l'inscription est
  refusée. Il ne peut pas être le premier champ (le premier sert d'identifiant).

Types de champs disponibles : texte, email, mot de passe, nombre, date, heure,
date et heure, mois, semaine, lien, téléphone, couleur, case à cocher, radio,
curseur, recherche, champ caché.

### 3. Récupérer la clé API

- Ouvrez le projet : la **clé API** est affichée **une seule fois**, à la
  création. Copiez-la et conservez-la.
- Passé cet écran, elle est masquée. Si vous l'avez perdue, cliquez sur
  **Régénérer la clé API** (attention : l'ancienne cesse immédiatement de
  fonctionner, vos fichiers intégrés doivent être mis à jour).
- Si le projet est protégé par mot de passe, vous devrez le saisir pour voir
  les données et télécharger les fichiers.

### 4. Télécharger les fichiers

Depuis la fiche du projet, trois fichiers sont téléchargeables :

| Fichier | Rôle |
|---|---|
| `inscription.html` | Formulaire d'inscription à intégrer sur votre site |
| `connexion.html` | Formulaire de connexion |
| `hagar_config.js` | Configuration (jeton + URL de l'API) pour vos intégrations |

Les fichiers sont **autonomes** : ouvrez-les dans un navigateur ou hébergez-les
tels quels. Ils appellent directement l'API et affichent un message de succès
ou l'erreur exacte (mot de passe trop faible, champ manquant, champ déjà pris…).

### 5. Intégrer sur votre site

- **Le plus simple** : hébergez `inscription.html` / `connexion.html` sur votre
  site et faites-vous un lien depuis vos pages.
- **Intégration sur mesure** : repérez la clé API dans `hagar_config.js` et
  appelez vous-même les routes décrites ci-dessous.

### 6. Consulter vos utilisateurs

- Ouvrez le projet → **Voir les utilisateurs**.
- La table affiche chaque inscrit, ses données (les mots de passe ne sont
  jamais affichés) et la date d'inscription. C'est là que vous voyez
  immédiatement que quelqu'un s'est inscrit.

### 7. Gérer / supprimer

- **Régénérer la clé API** : révoque l'ancienne clé.
- **Supprimer le Hagar** : supprime le projet et tous ses utilisateurs
  (irréversible, confirmation demandée).

---

## API pour vos intégrations

Toutes les routes sont sous `/api/*` et authentifiées par l'en-tête
`X-Hagar-Token: <clé API du projet>`.

### Inscription — `POST /api/hagar/register`

Les clés du formulaire sont les **libellés de champ du projet**.

```
POST /api/hagar/register
X-Hagar-Token: <clé API>

Pseudo=client&Mot de passe=azerty12
```

Réponses : `201` créé · `400` validation (mot de passe faible, champ requis
manquant, identifiant déjà pris) · `401` jeton invalide · `429` trop de requêtes.
Toujours en JSON `{"error": "..."}` ou `{"message": "..."}`.

### Connexion — `POST /api/hagar/login`

```
POST /api/hagar/login
X-Hagar-Token: <clé API>

identifier=client&password=azerty12
```

`identifier` correspond à la valeur du **premier champ** de la structure
(ex. Pseudo ou Email). Réponses : `200` avec les données utilisateur (jamais le
mot de passe) · `401` identifiants invalides · `400` champs manquants.

### Limites d'usage

- API : 30 requêtes/min par IP et 60/min par IP+projet.
- Connexion administrateur : 10/min par utilisateur+IP.
- Création de compte administrateur : 5/heure.

---

## Sécurité

- Mots de passe utilisateurs et administrateurs hachés (**Argon2id**), jamais
  stockés en clair ni renvoyés par l'API.
- Protection **CSRF** sur toutes les actions du tableau de bord.
- **CORS** limité aux routes API publiques.
- **Rate limiting** contre le bruteforce.
- En production : **HTTPS forcé**, cookies `Secure`, HSTS.
- La clé API n'apparaît **pas** dans l'URL (uniquement dans l'en-tête).

---

## Pages

| Page | Rôle |
|---|---|
| `/` | Accueil / présentation |
| `/register` · `/login` | Compte administrateur |
| `/dashboard` | Liste de vos projets |
| `/hagar/create` | Créer un projet |
| `/hagar/<id>` | Détails, clé API et téléchargements |
| `/hagar/<id>/users` | Utilisateurs inscrits au projet |
| `/profile` | Changer votre mot de passe |
| `/confidentialite` · `/mentions-legales` | Mentions légales |
