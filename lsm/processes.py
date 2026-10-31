"""Process identity and verified listener ownership; no process-name/port killing."""
from __future__ import annotations
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import psutil
from .discovery import canonical

PROCESS_ERRORS = (psutil.Error, OSError, RuntimeError, ValueError)

def command_hash(command):
    return hashlib.sha256(json.dumps(command, ensure_ascii=False).encode()).hexdigest()

def identity(pid):
    p = psutil.Process(pid)
    with p.oneshot():
        return {'pid': p.pid, 'created': p.create_time(), 'exe': canonical(p.exe()),
                'cwd': canonical(p.cwd()), 'command_hash': command_hash(p.cmdline())}

def verified(record):
    try:
        current = identity(int(record['pid']))
        return (abs(current['created'] - float(record['created'])) < 0.001 and
                all(current[key] == record[key] for key in ('exe', 'cwd', 'command_hash')) and
                psutil.Process(current['pid']).status() != psutil.STATUS_ZOMBIE)
    except (KeyError, TypeError, *PROCESS_ERRORS):
        return False

def expand_owned(records):
    """Only traverse descendants of a currently reverified recorded parent."""
    known = {r['pid']: r for r in records if verified(r)}
    for record in list(known.values()):
        try:
            for child in psutil.Process(record['pid']).children(recursive=True):
                try:
                    child_record = identity(child.pid)
                    if child_record['created'] >= record['created']:
                        known[child.pid] = child_record
                except PROCESS_ERRORS:
                    pass
        except PROCESS_ERRORS:
            pass
    return list(known.values())

def listening_ports(records):
    ports = {}
    for record in records:
        if not verified(record):
            continue
        p = psutil.Process(record['pid'])
        for conn in p.net_connections(kind='tcp'):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                ports[conn.laddr.port] = record['pid']
    return ports

def project_processes(directory, command=None):
    """Read-only external discovery. Require exact cwd plus recognizable entry args."""
    expected_dir = canonical(directory)
    candidates = []
    expected = set(command[1:] if command else []) - {'-u', '--host', '127.0.0.1', '--port'}
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.pid == os.getpid() or not any(n in (p.info['name'] or '').lower() for n in ('python', 'node', 'uvicorn', 'streamlit')):
                continue
            if canonical(p.cwd()) != expected_dir:
                continue
            args = p.cmdline()[1:]
            # Matching the entry module/script is essential; never claim arbitrary shell cwd.
            anchors = {x for x in expected if not x.isdigit() and not x.startswith('-') and x not in ('web', 'run', 'start', 'dev', 'serve')}
            if anchors and not any(x in args for x in anchors):
                continue
            candidates.append(identity(p.pid))
        except PROCESS_ERRORS:
            continue
    return candidates

def launch(command, directory, capture=False):
    options = dict(cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                   stderr=subprocess.STDOUT, bufsize=0, env=os.environ.copy())
    options['env']['PYTHONUNBUFFERED'] = '1'
    options['env']['PYTHONIOENCODING'] = 'utf-8'
    command = list(command)
    if os.name == 'nt':
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        options.update(startupinfo=startup, creationflags=subprocess.CREATE_NEW_CONSOLE)
        if Path(command[0]).suffix.lower() in ('.cmd', '.bat'):
            # cmd syntax only for explicitly registered batch files; quote metachar paths.
            command = [os.environ.get('COMSPEC', 'C:\\Windows\\System32\\cmd.exe'), '/d', '/s', '/c',
                       '"' + subprocess.list2cmdline(command) + '"']
    else:
        options['start_new_session'] = True
    return subprocess.Popen(command, **options)

def graceful(records, root_record):
    if not root_record or not verified(root_record):
        return False, '启动进程身份已失效，无法安全发送正常退出信号；可检查已核实子进程后选择强制停止'
    if os.name == 'nt':
        helper = Path(__file__).with_name('signal_helper.py')
        result = subprocess.run([sys.executable, str(helper), str(root_record['pid']), json.dumps(root_record)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                creationflags=subprocess.CREATE_NO_WINDOW, timeout=6)
        if result.returncode:
            return False, f'无法连接本实例的独立控制台，正常退出不可用（辅助程序 {result.returncode}）；可选择强制停止'
    else:
        os.killpg(root_record['pid'], signal.SIGTERM)
    return True, ''

def force_stop(records):
    """Only explicit force requests. Reverify each PID immediately before acting."""
    targets = expand_owned(records)
    for record in reversed(targets):
        if verified(record):
            try:
                psutil.Process(record['pid']).kill()
            except PROCESS_ERRORS:
                pass
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline and any(verified(r) for r in targets):
        time.sleep(.1)
    return not any(verified(r) for r in targets)
