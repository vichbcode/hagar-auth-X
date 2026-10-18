"""Point d'entrée WSGI pour Vercel (fonctions serverless Python).

Vercel réécrit toutes les routes vers /api/index/<chemin original> et le
runtime Python reçoit ce chemin de destination dans PATH_INFO. Ce middleware
restaure le chemin original (strip du préfixe /api/index) avant le routing
Flask. Le paramètre __hagar_path reste supporté en secours.
"""
from urllib.parse import parse_qs, urlencode

from app import app as _flask_app

_PARAM = '__hagar_path'
_PREFIX = '/api/index'


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
        elif path == _PREFIX or path == _PREFIX + '/':
            environ['PATH_INFO'] = '/'
        elif path.startswith(_PREFIX + '/'):
            environ['PATH_INFO'] = path[len(_PREFIX):]
        return self.flask_app(environ, start_response)


app = VercelPathMiddleware(_flask_app)
