"""Fixed local entrypoint; refuses unrelated listeners, reuses a verified backend."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from lsm.manager import HTTP
from lsm.processes import verified

ROOT = Path(__file__).resolve().parent
URL = 'http://127.0.0.1:17861'

def checked_backend():
    record_file = ROOT / 'runtime' / 'backend.json'
    try:
        record = json.loads(record_file.read_text(encoding='utf-8'))
        if record['url'] != URL or not verified(record['identity']):
            return False
        with HTTP.open(URL + '/api/identity', timeout=1) as response:
            info = json.load(response)
        return info.get('app') == 'local-service-manager' and info.get('nonce') == record['nonce'] and info.get('pid') == record['identity']['pid']
    except (OSError, KeyError, ValueError, urllib.error.URLError):
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stop', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if not checked_backend():
        if args.stop:
            print('未发现经核实的管理后台。业务服务保持原状态。')
            return
        # Bind first to detect collisions. Concurrent launchers are handled by backend bind.
        import socket
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', 17861))
            except OSError:
                # Another valid launcher may be between bind and writing its identity.
                for _ in range(15):
                    time.sleep(.2)
                    if checked_backend():
                        break
                else:
                    raise RuntimeError('端口17861已被其他程序占用，或现有后台身份无法核实。未打开占用者页面。')
        if not checked_backend():
            python = Path(sys.executable)
            pythonw = python.with_name('pythonw.exe')
            executable = str(pythonw if os.name == 'nt' and pythonw.exists() else python)
            options = {'cwd': str(ROOT), 'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
            if os.name == 'nt':
                options['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                options['start_new_session'] = True
            subprocess.Popen([executable, '-m', 'lsm.server'], **options)
            for _ in range(100):
                time.sleep(.1)
                if checked_backend():
                    break
            else:
                raise RuntimeError('管理后台未能启动；请在此目录运行 python -m lsm.server 查看错误。')
    if args.stop:
        with HTTP.open(URL + '/api/bootstrap', timeout=2) as response:
            token = json.load(response)['token']
        request = urllib.request.Request(URL + '/api/shutdown', data=b'{}', headers={
            'Content-Type': 'application/json', 'Origin': URL, 'X-Session-Token': token}, method='POST')
        with HTTP.open(request, timeout=3):
            pass
        print('管理后台已收到退出请求。业务服务继续运行，重开后重新核实。')
    elif not args.no_browser:
        webbrowser.open(URL)
        print(URL)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('无法打开管理台：' + str(exc), file=sys.stderr)
        raise SystemExit(1)
