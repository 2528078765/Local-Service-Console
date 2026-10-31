"""Durable per-run log supervisor. Remains alive when the management server exits."""
from __future__ import annotations
import codecs
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lsm.logging_utils import append_log
from lsm.processes import expand_owned, identity, verified, PROCESS_ERRORS


def report_status(spec, phase, child=None, exit_code=None):
    if not spec.get('status'):
        return
    path = Path(spec['status'])
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'phase': phase, 'child': child, 'exit_code': exit_code}), encoding='utf-8')
    temporary.replace(path)

def main():
    spec = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    command = spec['command']
    if os.name == 'nt':
        signal.signal(signal.SIGBREAK, lambda *_: None)
        signal.signal(signal.SIGINT, lambda *_: None)
        if Path(command[0]).suffix.lower() in ('.cmd', '.bat'):
            command = [os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/s', '/c', '"' + subprocess.list2cmdline(command) + '"']
    env = os.environ.copy()
    env.update(PYTHONUNBUFFERED='1', PYTHONIOENCODING='utf-8')
    env.update(spec.get('env', {}))
    append_log(spec['log'], f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] 启动新的服务实例\n")
    try:
        child = subprocess.Popen(command, cwd=spec['directory'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, bufsize=0)
    except Exception as exc:
        report_status(spec, 'failed')
        append_log(spec['log'], f'启动命令失败：{type(exc).__name__}: {exc}\n')
        return 1
    records = []
    try:
        records = [identity(child.pid)]
    except PROCESS_ERRORS:
        pass
    report_status(spec, 'started', records[0] if records else None)
    def capture():
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        pending = ''
        while True:
            data = child.stdout.read(4096)
            if not data:
                if pending:
                    append_log(spec['log'], pending)
                break
            pending += decoder.decode(data)
            while '\n' in pending:
                line, pending = pending.split('\n', 1)
                append_log(spec['log'], line + '\n')
            # Avoid unbounded lines, retaining enough overlap for common credential fields.
            if len(pending) > 65536:
                append_log(spec['log'], '[已省略超过64KB且无换行的输出]\n')
                pending = ''
    thread = threading.Thread(target=capture, daemon=True)
    thread.start()
    exit_reported = False
    while child.poll() is None or any(verified(r) for r in records):
        if child.returncode is not None and not exit_reported:
            report_status(spec, 'exited', exit_code=child.returncode)
            exit_reported = True
        records = expand_owned(records)
        time.sleep(.15)
    report_status(spec, 'exited', exit_code=child.returncode)
    thread.join(timeout=2)
    append_log(spec['log'], f'\n服务入口进程退出，退出码 {child.returncode}\n')
    return child.returncode or 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    finally:
        Path(sys.argv[1]).unlink(missing_ok=True)
