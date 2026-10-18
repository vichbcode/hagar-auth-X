"""Point d'entrée WSGI pour Vercel (fonctions serverless Python).

Vercel exécute ce module par requête (cold start = import de app.py,
ce qui déclenche init_schema() contre Turso — idempotent).
"""
from app import app  # noqa: F401
