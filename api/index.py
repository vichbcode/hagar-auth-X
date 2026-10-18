"""Point d'entrée WSGI pour Vercel (fonctions serverless Python).

Vercel réécrit toutes les routes vers /api/index/<chemin original> et le
runtime Python reçoit ce chemin de destination dans PATH_INFO. Ce module
restaure le chemin original (strip du préfixe /api/index) avant de déléguer
à Flask. Le paramètre ?__hagar_path= reste supporté en secours.
"""
import sys
from urllib.parse import parse_qs, urlencode

from app import app as _flask_app

_PARAM = '__hagar_path'
_PREFIX = '/api/index'


def _restore_path(environ):
    path = environ.get('PATH_INFO', '')
    query = environ.get('QUERY_STRING', '')
    params = parse_qs(query, keep_blank_values=True)
    if _PARAM in params:
        original = params.pop(_PARAM)[0]
        new_path = '/' + original.strip('/') if original else '/'
        environ['QUERY_STRING'] = urlencode(params, doseq=True)
    elif path == _PREFIX or path == _PREFIX + '/':
        new_path = '/'
    elif path.startswith(_PREFIX + '/'):
        new_path = path[len(_PREFIX):]
    else:
        new_path = path
    environ['PATH_INFO'] = new_path
    print(f'[hagar-vercel] PATH_INFO {path!r} -> {new_path!r}', file=sys.stdout)
    return new_path


def app(environ, start_response):
    final_path = _restore_path(environ)

    def _start_response(status, headers, exc_info=None):
        return start_response(status, list(headers) + [('X-Hagar-Path', final_path)], exc_info)

    return _flask_app(environ, _start_response)
