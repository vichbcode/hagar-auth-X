"""Point d'entrée WSGI pour Vercel (fonctions serverless Python).

Vercel réécrit toutes les routes vers /api/index et le runtime Python reçoit ce
chemin de destination dans PATH_INFO (le chemin d'origine est perdu). Chaque
réécriture (voir vercel.json) transmet donc le chemin d'origine via le paramètre
__hagar_path, que ce middleware restaure dans PATH_INFO avant le routing Flask.
"""
from urllib.parse import parse_qs, urlencode

from app import app as _flask_app

_PARAM = '__hagar_path'
_FUNCTION_PATHS = ('/api/index', '/api/index/')


class VercelPathMiddleware:
    """Restaure le chemin d'origine transmis par la réécriture Vercel."""

    def __init__(self, flask_app):
        self.flask_app = flask_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        query = environ.get('QUERY_STRING', '')
        params = parse_qs(query, keep_blank_values=True)
        if _PARAM in params:
            original = params.pop(_PARAM)[0]
            environ['PATH_INFO'] = '/' + original.strip('/') if original else '/'
            environ['QUERY_STRING'] = urlencode(params, doseq=True)
        elif path in _FUNCTION_PATHS:
            environ['PATH_INFO'] = '/'
        return self.flask_app(environ, start_response)


app = VercelPathMiddleware(_flask_app)
