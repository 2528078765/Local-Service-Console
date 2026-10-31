from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from . import __version__
from .discovery import DEFAULT_EXCLUDES, fixed_roots
from .manager import Manager, atomic_json
from .processes import identity

class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, root, port=17861, seed=True):
        self.root = Path(root).resolve()
        self.token = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(24)
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.manager = Manager(root, seed=seed)
        atomic_json(self.manager.runtime_dir / 'backend.json', {'identity': identity(os.getpid()), 'nonce': self.nonce,
                                                             'url': self.origin, 'version': __version__})

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass  # No URLs/request tokens in console or access logs.

    def reply(self, value, code=200, content_type='application/json; charset=utf-8'):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def guard(self, mutation=False, token=True, api=True):
        expected = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host') != expected:
            self.reply({'error': 'Host 不属于此管理台'}, 403)
            return False
        origin = self.headers.get('Origin')
        if api and (origin and origin != self.server.origin or self.headers.get('Sec-Fetch-Site') in ('cross-site', 'same-site')):
            self.reply({'error': '拒绝跨站来源'}, 403)
            return False
        if mutation and origin != self.server.origin:
            self.reply({'error': '变更请求需要管理台同源 Origin'}, 403)
            return False
        provided = self.headers.get('X-Session-Token', '')
        if token and not secrets.compare_digest(provided, self.server.token):
            self.reply({'error': '会话失效，请刷新管理台'}, 403)
            return False
        return True

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('仅接受 JSON 请求')
        try:
            size = int(self.headers.get('Content-Length', 0))
        except ValueError:
            raise ValueError('请求长度无效')
        if not 0 <= size <= 256 * 1024:
            raise ValueError('请求超过256KB限制')
        value = json.loads(self.rfile.read(size) or '{}')
        if not isinstance(value, dict):
            raise ValueError('请求内容必须为对象')
        return value

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self.guard(token=path.startswith('/api/') and path not in ('/api/bootstrap', '/api/identity'), api=path.startswith('/api/')):
            return
        manager = self.server.manager
        try:
            if path == '/api/identity':
                self.reply({'app': 'local-service-manager', 'nonce': self.server.nonce, 'pid': os.getpid(), 'version': __version__})
            elif path == '/api/bootstrap':
                self.reply({'token': self.server.token, 'services': manager.list_services(), 'scan': manager.scanner.snapshot(),
                            'blacklist_count': len(manager.list_blacklist()),
                            'defaults': {'roots': fixed_roots(), 'excludes': DEFAULT_EXCLUDES},
                            'backend': {'version': __version__, 'warnings': manager.load_errors}})
            elif path == '/api/services':
                self.reply({'services': manager.list_services(), 'blacklist_count': len(manager.list_blacklist())})
            elif path == '/api/scan':
                self.reply(manager.scanner.snapshot())
            elif path == '/api/blacklist':
                self.reply({'entries': manager.list_blacklist()})
            elif path.startswith('/api/services/') and path.endswith('/logs'):
                sid = path.split('/')[3]
                self.reply({'text': manager.logs(sid)})
            elif path in ('/', '/index.html', '/app.js', '/style.css'):
                filename = 'index.html' if path == '/' else path[1:]
                mime = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css'}[Path(filename).suffix]
                self.reply((Path(__file__).resolve().parent.parent / 'static' / filename).read_bytes(), content_type=mime + '; charset=utf-8')
            else:
                self.reply({'error': '未找到此资源'}, 404)
        except KeyError as exc:
            self.reply({'error': str(exc)}, 404)
        except (OSError, ValueError) as exc:
            self.reply({'error': str(exc)}, 400)

    def do_POST(self):
        self.mutate('POST')

    def do_PATCH(self):
        self.mutate('PATCH')

    def do_DELETE(self):
        self.mutate('DELETE')

    def do_OPTIONS(self):
        self.reply({'error': '不提供跨站访问'}, 403)

    def mutate(self, method):
        if not self.guard(mutation=True):
            return
        manager = self.server.manager
        path = urlsplit(self.path).path
        try:
            data = self.body()
            parts = path.strip('/').split('/')
            if method == 'POST' and path == '/api/blacklist':
                count = manager.add_blacklist(data)
                self.reply({'ok': True, 'added': count, 'entries': manager.list_blacklist()})
            elif method == 'DELETE' and len(parts) == 3 and parts[:2] == ['api', 'blacklist']:
                manager.remove_blacklist(parts[2])
                self.reply({'ok': True})
            elif method == 'POST' and path == '/api/services':
                sid = manager.save_config(data)
                self.reply({'id': sid}, 201)
            elif len(parts) == 3 and parts[:2] == ['api', 'services'] and method in ('PATCH', 'DELETE'):
                sid = parts[2]
                if method == 'DELETE':
                    manager.remove(sid)
                else:
                    manager.save_config(data, sid)
                manager.refresh_one(sid) if method == 'PATCH' else None
                self.reply({'ok': True})
            elif len(parts) == 4 and parts[:2] == ['api', 'services'] and method == 'POST':
                if not isinstance(data.get('force', False), bool):
                    raise ValueError('force 必须为布尔值')
                manager.action(parts[2], parts[3], data.get('force', False))
                self.reply({'ok': True, 'accepted': True}, 202)
            elif method == 'POST' and path == '/api/scan':
                self.reply(manager.scanner.start(data.get('roots'), data.get('excludes')), 202)
            elif method == 'POST' and path == '/api/scan/cancel':
                manager.scanner.cancel()
                self.reply({'ok': True})
            elif method == 'POST' and path == '/api/shutdown':
                self.reply({'ok': True, 'message': '后台退出，业务服务继续运行'})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self.reply({'error': '未找到此接口'}, 404)
        except KeyError as exc:
            self.reply({'error': str(exc)}, 404)
        except (ValueError, TypeError, OSError) as exc:
            self.reply({'error': str(exc)}, 400)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=17861)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--no-seed', action='store_true')
    args = parser.parse_args()
    server = AppServer(args.root, args.port, seed=not args.no_seed)
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.manager.close()
        server.server_close()

if __name__ == '__main__':
    main()
