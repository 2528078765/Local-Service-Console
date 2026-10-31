from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .discovery import Scanner, canonical, inspect_directory, service_id
from .logging_utils import append_log, tail_log
from . import processes as proc

RUNNING = {'starting', 'stopping', 'running'}
CONFIG_KEYS = {'name', 'description', 'directory', 'command', 'url', 'health_path', 'health_mode', 'enabled', 'timeout', 'adapter', 'version', 'env', 'stop_command', 'discover_url'}
RUNTIME_KEYS = CONFIG_KEYS - {'name', 'description', 'enabled', 'version'}

def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temp.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)

def local_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        return (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')
                and parsed.port is not None and 0 < parsed.port < 65536 and not parsed.username
                and not parsed.password and not parsed.fragment)
    except (ValueError, TypeError):
        return False

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def healthy(service, url):
    if service.get('health_mode') == 'process':
        return True
    if not local_url(url):
        return False
    parsed = urllib.parse.urlsplit(url)
    health = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, service.get('health_path') or parsed.path or '/', '', ''))
    try:
        with HTTP.open(health, timeout=.8) as response:
            if not 200 <= response.status < 400:
                return False
            data = response.read(2048)
            if service.get('adapter') == 'videotono':
                return json.loads(data).get('status') == 'ok'
            return True
    except (OSError, ValueError, urllib.error.URLError):
        return False

def validate(service):
    errors = []
    directory = service.get('directory')
    if not isinstance(service.get('name'), str) or not service.get('name', '').strip():
        errors.append('名称不能为空')
    if not isinstance(directory, str) or not os.path.isabs(directory) or not Path(directory).is_dir():
        errors.append('位置失效：项目目录不存在或不是绝对路径')
    command = service.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x and '\x00' not in x for x in command):
        errors.append('启动命令须为非空参数列表，每行一个参数')
    else:
        executable = command[0]
        if not (Path(executable).is_file() if os.path.isabs(executable) else shutil.which(executable)):
            errors.append('启动程序不存在：' + executable[:160])
        if directory:
            for arg in command[1:]:
                if arg.lower().endswith(('.py', '.ps1', '.cmd', '.bat')) and not arg.startswith('-'):
                    path = Path(arg) if os.path.isabs(arg) else Path(directory) / arg
                    if not path.is_file():
                        errors.append('启动脚本不存在：' + arg[:160])
    mode = service.get('health_mode', 'http')
    if mode not in ('http', 'process'):
        errors.append('检查类型应为 http 或 process')
    if service.get('url') and not local_url(service['url']):
        errors.append('访问地址必须为明确端口的本机 http 地址')
    if mode == 'http' and not service.get('url') and not service.get('discover_url', False):
        errors.append('需填写访问地址后启动；运行时仍会核实真实监听地址')
    if not isinstance(service.get('discover_url', False), bool):
        errors.append('discover_url 必须为布尔值')
    env = service.get('env', {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) and isinstance(v, str) and '\x00' not in v for k, v in env.items()):
        errors.append('环境变量必须为名称到文本值的对象')
    elif any(re.search(r'key|token|secret|password|credential|authorization', key, re.I) for key in env):
        errors.append('管理台不保存密钥类环境变量；请由业务项目自己的安全配置提供')
    stop = service.get('stop_command', [])
    if not isinstance(stop, list) or not all(isinstance(x, str) and x and '\x00' not in x for x in stop):
        errors.append('停止命令须为参数列表或空列表')
    elif stop and not (Path(stop[0]).is_file() if os.path.isabs(stop[0]) else shutil.which(stop[0])):
        errors.append('停止程序不存在：' + stop[0][:160])
    if not isinstance(service.get('health_path', '/'), str) or not service.get('health_path', '/').startswith('/') or service.get('health_path', '/').startswith('//'):
        errors.append('健康检查路径必须以单个 / 开头')
    if not isinstance(service.get('timeout', 60), (int, float)) or not 1 <= service.get('timeout', 60) <= 600:
        errors.append('启动期限须为 1–600 秒')
    if not isinstance(service.get('enabled', True), bool):
        errors.append('enabled 必须为布尔值')
    return errors

def business_process_alive(status_path):
    try:
        value = json.loads(Path(status_path).read_text(encoding='utf-8'))
        record = value.get('child')
        return value.get('phase') == 'started' and isinstance(record, dict) and proc.verified(record)
    except (OSError, ValueError, TypeError):
        return False


class Manager:
    def __init__(self, root, seed=True, monitor=True):
        self.root = Path(root).resolve()
        self.runtime_dir = self.root / 'runtime'
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.runtime_dir / 'services.json'
        self.instances_file = self.runtime_dir / 'instances.json'
        self.blacklist_file = self.runtime_dir / 'blacklist.json'
        self.lock = threading.RLock()
        self.configs, self.instances, self.states, self.operations = {}, {}, {}, {}
        self.load_errors = []
        self.closing = threading.Event()
        # Keep this independent of service registration: removing a row must not erase its scan rule.
        self.blacklist = self._load_blacklist()
        self.configs = self._load(self.config_file, {})
        self.instances = self._load(self.instances_file, {})
        if seed and not self.config_file.exists():
            for directory in (self.root.parent / 'video-to-note-1.4.6', self.root.parent / 'shortvideo-agent'):
                if directory.is_dir():
                    try:
                        candidate = inspect_directory(directory, set(os.listdir(directory)))
                        if candidate:
                            candidate['source'] = 'preset'
                            self.merge(candidate)
                    except (OSError, ValueError) as exc:
                        self.load_errors.append(str(exc))
        self.scanner = Scanner(self.merge, self.root, self.is_blacklisted)
        for sid in self.configs:
            self.states[sid] = {'status': 'checking', 'error': '', 'owned': False}
        self.refresh()
        if monitor:
            threading.Thread(target=self._monitor, daemon=True).start()

    def _load(self, path, default):
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(value, dict) or not all(isinstance(v, dict) for v in value.values()):
                raise ValueError('记录格式应为对象映射')
            return value
        except (OSError, ValueError) as exc:
            # Never replace corrupted input silently; preserve evidence and stop writes to that file.
            backup = path.with_name(path.name + f'.corrupt-{int(time.time())}')
            shutil.copy2(path, backup)
            path.unlink()
            self.load_errors.append(f'{path.name} 损坏，已保留为 {backup.name}：{exc}')
            return default

    def _save(self):
        with self.lock:
            atomic_json(self.blacklist_file, self.blacklist)
            atomic_json(self.config_file, self.configs)
            atomic_json(self.instances_file, self.instances)

    def merge(self, candidate):
        sid = candidate['id']
        with self.lock:
            if self.is_blacklisted(candidate['directory']):
                return False
            existing = self.configs.get(sid)
            if existing:
                # Installation metadata changes; all user fields survive repeated scans.
                existing['discovery'] = candidate['discovery']
                if not existing.get('manual_version'):
                    for key in ('version', 'version_source'):
                        existing[key] = candidate[key]
                if not existing.get('manual'):
                    for key in CONFIG_KEYS:
                        if key in candidate:
                            existing[key] = candidate[key]
            else:
                self.configs[sid] = candidate
            self._save()
            return True

    def _load_blacklist(self):
        if not self.blacklist_file.exists():
            return {}
        # Fail visibly rather than silently discarding exclusions and rediscovering hidden tools.
        value = json.loads(self.blacklist_file.read_text(encoding='utf-8'))
        if not isinstance(value, dict) or any(
                not isinstance(row, dict) or not isinstance(row.get('directory'), str)
                or not os.path.isabs(row['directory'])
                or not all(isinstance(row.get(key), str) for key in ('id', 'name', 'version'))
                or row['id'] != service_id(row['directory'], 'blacklist') for row in value.values()):
            raise ValueError('扫描黑名单文件损坏，请恢复 runtime/blacklist.json 的备份')
        return {canonical(row['directory']): row for row in value.values()}

    def is_blacklisted(self, directory):
        with self.lock:
            return canonical(directory) in self.blacklist

    def list_blacklist(self):
        with self.lock:
            return sorted(copy.deepcopy(list(self.blacklist.values())),
                          key=lambda row: (row['name'].lower(), row['directory']))

    def add_blacklist(self, data):
        if not isinstance(data, dict) or set(data) not in ({'service_ids'}, {'entries'}):
            raise ValueError('请提供服务编号列表或黑名单条目列表')
        with self.lock:
            if 'service_ids' in data:
                ids = data['service_ids']
                if not isinstance(ids, list) or not ids or not all(isinstance(sid, str) for sid in ids):
                    raise ValueError('服务编号必须为非空列表')
                if any(sid not in self.configs for sid in ids):
                    raise KeyError('服务不存在')
                rows = [self.configs[sid] for sid in ids]
            else:
                rows = data['entries']
            if not isinstance(rows, list) or not rows or len(rows) > 2000:
                raise ValueError('黑名单条目须为1–2000项的列表')
            prepared = {}
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError('黑名单条目必须为对象')
                directory = row.get('directory')
                if not isinstance(directory, str) or not os.path.isabs(directory) or '\x00' in directory:
                    raise ValueError('黑名单目录必须为绝对路径')
                path = canonical(directory)
                if Path(path).parent == Path(path):
                    raise ValueError('黑名单针对具体服务目录，不能加入整块磁盘')
                prepared[path] = {'id': service_id(path, 'blacklist'),
                                  'directory': str(Path(directory).absolute()),
                                  'name': str(row.get('name') or Path(directory).name)[:160],
                                  'version': str(row.get('version') or '版本未知')[:100],
                                  'added_at': time.time()}
            matching = [sid for sid, config in self.configs.items()
                        if canonical(config['directory']) in prepared]
            for sid in matching:
                instance = self.instances.get(sid, {})
                state = self.states.get(sid, {})
                if (self.operations.get(sid) or state.get('status') in RUNNING | {'external'}
                        or any(proc.verified(r) for r in instance.get('members', []) + instance.get('stop_members', []))):
                    raise ValueError('运行中的服务不能加入黑名单，请先停止该服务')
            self.blacklist.update(prepared)
            # Shared lock with merge prevents an in-flight scan from resurrecting removed entries.
            for sid in matching:
                self.configs.pop(sid)
                self.instances.pop(sid, None)
                self.states.pop(sid, None)
            self._save()
            return len(prepared)

    def remove_blacklist(self, entry_id):
        with self.lock:
            path = next((path for path, row in self.blacklist.items() if row['id'] == entry_id), None)
            if path is None:
                raise KeyError('黑名单条目不存在')
            self.blacklist.pop(path)
            self._save()

    def save_config(self, data, sid=None):
        if not isinstance(data, dict) or any(k not in CONFIG_KEYS for k in data):
            raise ValueError('配置包含未知字段')
        with self.lock:
            if sid and sid not in self.configs:
                raise KeyError('服务不存在')
            existing = self.configs.get(sid, {})
            if sid and self.operations.get(sid):
                raise ValueError('操作进行中，请稍后修改')
            state = self.states.get(sid, {})
            if (state.get('owned') or state.get('status') == 'external') and any(data.get(k, existing.get(k)) != existing.get(k) for k in RUNTIME_KEYS):
                raise ValueError('请先停止服务再修改运行配置；外部实例需自行退出')
            config = dict(existing)
            config.update(data)
            config.setdefault('description', '')
            config.setdefault('command', [])
            config.setdefault('url', '')
            config.setdefault('health_mode', 'http')
            config.setdefault('health_path', '/')
            config.setdefault('timeout', 60)
            config.setdefault('adapter', 'generic')
            config.setdefault('enabled', True)
            config.setdefault('env', {})
            config.setdefault('stop_command', [])
            config.setdefault('discover_url', False)
            config.setdefault('version', '版本未知')
            config.setdefault('version_source', '手工配置，未提供版本')
            config.setdefault('source', 'manual')
            config.setdefault('discovery', {})
            # Allow incomplete scanned candidates to be saved, but reject invalid manual edits.
            errors = validate(config)
            if errors:
                raise ValueError('；'.join(errors))
            config['directory'] = str(Path(config['directory']).absolute())
            config['manual'] = True
            if 'version' in data and data['version'] != existing.get('version'):
                config['manual_version'] = True
                config['version_source'] = '用户手工填写'
            config['id'] = sid or service_id(config['directory'], 'manual-' + uuid.uuid4().hex)
            self.configs[config['id']] = config
            self._save()
            return config['id']

    def remove(self, sid):
        with self.lock:
            if sid not in self.configs:
                raise KeyError('服务不存在')
            instance = self.instances.get(sid, {})
            if self.operations.get(sid) or any(proc.verified(r) for r in instance.get('members', []) + instance.get('stop_members', [])):
                raise ValueError('请先停止托管实例再移除')
            self.configs.pop(sid)
            self.instances.pop(sid, None)
            self.states.pop(sid, None)
            self._save()

    def log_path(self, sid):
        if sid not in self.configs or not re.fullmatch(r'[a-f0-9]{24}', sid):
            raise KeyError('服务不存在')
        return self.runtime_dir / 'logs' / f'{sid}.log'

    def log(self, sid, message):
        append_log(self.log_path(sid), f"[{time.strftime('%H:%M:%S')}] 管理台：{message}\n")

    def logs(self, sid):
        return tail_log(self.log_path(sid))

    def _owned_url(self, config, members, sid, external=False):
        if config.get('health_mode') == 'process':
            return '', ''
        try:
            ports = proc.listening_ports(members)
        except proc.PROCESS_ERRORS as exc:
            return '', f'无法核实监听归属（权限或系统限制）：{type(exc).__name__}: {exc}'
        candidates = []
        if not external:
            # Log URLs are merely hints and must match a verified owned listener.
            candidates = re.findall(r'http://(?:127\.0\.0\.1|localhost):\d+(?:/[^\s<>\x22\x27]*)?', self.logs(sid))[-15:]
            candidates.reverse()
        if config.get('url'):
            candidates.append(config['url'])
        if len(ports) == 1:
            candidates.append(f'http://127.0.0.1:{next(iter(ports))}/')
        for url in candidates:
            url = url.rstrip(').,;')
            if local_url(url) and urllib.parse.urlsplit(url).port in ports:
                return url, ''
        return '', '尚未发现属于此实例的 HTTP 监听入口'

    def refresh_one(self, sid, allow_external=True):
        with self.lock:
            if sid not in self.configs:
                return
            config = copy.deepcopy(self.configs[sid])
            instance = self.instances.get(sid)
            state = self.states.setdefault(sid, {'status': 'checking', 'error': '', 'owned': False})
            if self.operations.get(sid):
                return
        errors = validate(config)
        helpers = proc.expand_owned(instance.get('stop_members', [])) if instance else []
        if helpers:
            instance['stop_members'] = helpers
            state.update(status='error', owned=True, error='上次停止控制脚本仍在运行；请先选择强制停止清理本实例控制进程，再重启')
            return
        members = proc.expand_owned(instance.get('members', [])) if instance else []
        with self.lock:
            if instance:
                instance['members'] = members
            state['owned'] = bool(members)
        if members:
            url, problem = self._owned_url(config, members, sid)
            good = not problem and healthy(config, url)
            if config.get('health_mode') == 'process':
                good = business_process_alive(instance.get('worker_status_path'))
                if not good:
                    problem = '业务入口进程已退出或无法核实，不能以控制辅助进程代替业务进程'
            with self.lock:
                instance['actual_url'] = url
                failures = 0 if good else state.get('failures', 0) + 1
                state['failures'] = failures
                state['status'] = 'running' if good else ('error' if failures >= 3 else state.get('status', 'checking'))
                state['error'] = '' if good else problem or '进程仍在，HTTP 健康检查未通过'
        else:
            if instance and instance.get('members') == [] and not instance.get('stopped'):
                state.update(status='error', error='托管进程已退出；请查看日志', actual_url='')
            elif errors:
                state.update(status='needs_config', error='；'.join(errors), actual_url='')
            else:
                state.update(status='stopped', error='', actual_url='')
            if allow_external and not errors:
                external = proc.project_processes(config['directory'], config['command'])
                if external:
                    url, problem = self._owned_url(config, external, sid, external=True)
                    if url and healthy(config, url):
                        state.update(status='external', error='此实例从外部启动，仅可打开；管理台不会停止或重启它', actual_url=url, external_pid=external[0]['pid'])
                    else:
                        state.update(status='error', error=problem or '检测到外部项目进程，但入口尚不可用')
        state['checked_at'] = time.time()

    def refresh(self):
        with self.lock:
            ids = list(self.configs)
        for sid in ids:
            try:
                self.refresh_one(sid)
            except Exception as exc:
                with self.lock:
                    self.states.setdefault(sid, {}).update(status='error', error=f'检查失败：{type(exc).__name__}: {exc}')

    def _monitor(self):
        while not self.closing.wait(3):
            self.refresh()
            with self.lock:
                atomic_json(self.instances_file, self.instances)

    def list_services(self):
        with self.lock:
            rows = []
            for sid, config in self.configs.items():
                row = copy.deepcopy(config)
                state = copy.deepcopy(self.states.get(sid, {'status': 'checking'}))
                row.update(state)
                row['validation_errors'] = validate(config)
                instance = self.instances.get(sid, {})
                row.update(operation=self.operations.get(sid),
                           actual_url=instance.get('actual_url', '') if state.get('owned') else state.get('actual_url', ''),
                           pid=next((m['pid'] for m in instance.get('members', []) if proc.verified(m)), state.get('external_pid')),
                           started_at=instance.get('started_at'))
                rows.append(row)
            return sorted(rows, key=lambda r: (r.get('source') != 'preset', r['name'].lower(), r['directory']))

    def action(self, sid, action, force=False):
        if action not in ('start', 'stop', 'restart'):
            raise ValueError('未知操作')
        with self.lock:
            if sid not in self.configs:
                raise KeyError('服务不存在')
            if self.operations.get(sid):
                raise ValueError('此服务已有操作进行中')
            state = self.states.get(sid, {})
            if state.get('status') == 'external':
                raise ValueError('外部实例只读，请使用原工具退出')
            if action in ('start', 'restart') and not self.configs[sid].get('enabled', True):
                raise ValueError('服务已停用，请先启用')
            errors = validate(self.configs[sid])
            if action in ('start', 'restart') and errors:
                raise ValueError('；'.join(errors))
            self.operations[sid] = action
            self.states.setdefault(sid, {}).update(status='starting' if action == 'start' else 'stopping', error='')
        threading.Thread(target=self._perform, args=(sid, action, force), daemon=True).start()

    def _perform(self, sid, action, force):
        try:
            if action in ('stop', 'restart'):
                self._stop(sid, force)
            if action in ('start', 'restart'):
                self._start(sid)
        except Exception as exc:
            with self.lock:
                self.states.setdefault(sid, {}).update(status='error', error=str(exc))
            self.log(sid, f'操作失败：{exc}')
        finally:
            with self.lock:
                self.operations.pop(sid, None)
                self._save()

    def _start(self, sid):
        config = copy.deepcopy(self.configs[sid])
        existing = self.instances.get(sid, {})
        if proc.expand_owned(existing.get('stop_members', [])):
            raise ValueError('上次停止控制进程仍在运行；请先强制停止清理，再启动')
        if proc.expand_owned(existing.get('members', [])):
            # No duplicate spawn, including an unhealthy earlier instance.
            raise ValueError('已有经核实的托管进程；请先打开或停止原实例')
        external = proc.project_processes(config['directory'], config['command'])
        if external:
            raise ValueError('检测到同目录的外部服务进程；不会重复启动，请使用原实例或先自行退出')
        if config.get('url') and config.get('adapter') != 'autovid':
            parsed = urllib.parse.urlsplit(config['url'])
            with socket.socket() as sock:
                sock.settimeout(.3)
                if sock.connect_ex(('127.0.0.1', parsed.port)) == 0:
                    raise ValueError(f'端口 {parsed.port} 已被占用；不会停止或接管占用者')
        token = uuid.uuid4().hex
        spec_path = self.runtime_dir / 'workers' / f'{sid}-{token}.json'
        status_path = spec_path.with_suffix('.status.json')
        spec = {'command': config['command'], 'directory': config['directory'], 'log': str(self.log_path(sid)), 'env': config.get('env', {}), 'status': str(status_path)}
        atomic_json(spec_path, spec)
        worker_command = [sys.executable.replace('pythonw.exe', 'python.exe'), '-u', str(Path(__file__).with_name('worker.py')), str(spec_path)]
        process = proc.launch(worker_command, config['directory'])
        # Keep the Popen handle owned until exit (also prevents unreaped handles/warnings).
        threading.Thread(target=process.wait, daemon=True).start()
        try:
            root = proc.identity(process.pid)
        except proc.PROCESS_ERRORS:
            # A vanished launcher must not lead to guesses about other PIDs.
            raise ValueError('启动器立即退出，无法核实身份；请查看日志')
        instance = {'instance_id': token, 'root': root, 'members': [root], 'actual_url': '',
                    'started_at': time.time(), 'stopped': False, 'worker_status_path': str(status_path)}
        with self.lock:
            self.instances[sid] = instance
            self.states[sid].update(status='starting', owned=True, error='')
            self._save()
        self.log(sid, '已创建独立实例，正在核实进程、监听和健康检查')
        deadline = time.monotonic() + config.get('timeout', 60)
        last_problem = ''
        child_ready_since = None
        while time.monotonic() < deadline:
            members = proc.expand_owned(instance['members'])
            instance['members'] = members
            if not members:
                raise ValueError('服务进程已退出，请查看启动日志')
            url, problem = self._owned_url(config, members, sid)
            last_problem = problem
            # A dedicated Windows console may have auxiliary descendants. Only the
            # supervisor's explicit spawned-business identity can satisfy process mode.
            try:
                worker_status = json.loads(status_path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                worker_status = {}
            business_child = worker_status.get('child')
            has_child = (worker_status.get('phase') == 'started' and isinstance(business_child, dict)
                         and proc.verified(business_child))
            if config.get('health_mode') == 'process' and worker_status.get('phase') in ('failed', 'exited'):
                raise ValueError('业务入口进程已退出，请查看启动日志')
            child_ready_since = (child_ready_since or time.monotonic()) if has_child else None
            ready = (has_child and time.monotonic() - child_ready_since >= 1) if config.get('health_mode') == 'process' else not problem and healthy(config, url)
            if ready:
                with self.lock:
                    instance['actual_url'] = url
                    self.states[sid].update(status='running', owned=True, error='', failures=0)
                self.log(sid, '服务已通过身份与健康检查：' + (url or '进程模式'))
                return
            time.sleep(.4)
        raise ValueError('启动超时；' + (last_problem or 'HTTP 健康检查未通过') + '。仍存活的本次实例已保留，请检查日志或停止')

    def _stop(self, sid, force):
        instance = self.instances.get(sid)
        if not instance:
            self.states[sid].update(status='stopped', owned=False, error='')
            return
        helpers = proc.expand_owned(instance.get('stop_members', []))
        if helpers:
            if not force:
                raise ValueError('存在上次停止控制进程；请选择强制停止清理，防止影响后续实例')
            if not proc.force_stop(helpers):
                raise ValueError('停止控制进程仍无法清理，已阻止重启')
            instance['stop_members'] = []
        records = proc.expand_owned(instance.get('members', []))
        instance['members'] = records
        if not records:
            instance.update(stopped=True, actual_url='')
            self.states[sid].update(status='stopped', owned=False, error='')
            return
        try:
            previous_ports = set(proc.listening_ports(records))
        except proc.PROCESS_ERRORS:
            previous_ports = set()
        self.log(sid, '用户请求' + ('强制停止（仅核实的本实例进程）' if force else '正常停止'))
        if force:
            if not proc.force_stop(records):
                raise ValueError('部分经核实进程仍未退出；未扩大终止范围')
        else:
            stop_command = self.configs[sid].get('stop_command', [])
            if stop_command:
                # An explicit user-owned stop script runs only after ownership is reverified.
                child = next((r for r in records if r['pid'] != instance.get('root', {}).get('pid')), None)
                if not child or not proc.verified(child):
                    raise ValueError('未核实业务进程，拒绝执行停止脚本')
                command = [arg.replace('{pid}', str(child['pid'])) for arg in stop_command]
                stopper = proc.launch(command, self.configs[sid]['directory'])
                try:
                    stop_records = [proc.identity(stopper.pid)]
                except proc.PROCESS_ERRORS:
                    stop_records = []
                instance['stop_members'] = stop_records
                self._save()
                deadline = time.monotonic() + 15
                while stopper.poll() is None and time.monotonic() < deadline:
                    stop_records = proc.expand_owned(stop_records)
                    instance['stop_members'] = stop_records
                    time.sleep(.1)
                if stopper.poll() is None or any(proc.verified(r) for r in stop_records):
                    # Cleanup applies only to this newly-created control command, never business.
                    cleaned = proc.force_stop(stop_records)
                    stopper.wait(timeout=5)
                    instance['stop_members'] = [] if cleaned else stop_records
                    raise ValueError('停止脚本超时或遗留控制进程；已清理本次停止辅助进程，业务实例未强制终止；可选择强制停止')
                instance['stop_members'] = []
                ok, problem = stopper.returncode == 0, '停止脚本返回错误，业务实例未强制终止'
            else:
                ok, problem = proc.graceful(records, instance.get('root'))
            if not ok:
                raise ValueError(problem)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                records = proc.expand_owned(records)
                instance['members'] = records
                if not records:
                    break
                time.sleep(.2)
            if records:
                raise ValueError('正常停止等待15秒后仍未退出；如确认可中断任务，请选择“强制停止”')
        # No other process gets terminated even when it immediately reuses an old port.
        conflicts = []
        for port in previous_ports:
            with socket.socket() as sock:
                sock.settimeout(.2)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    conflicts.append(str(port))
        instance.update(stopped=True, members=[], actual_url='')
        self.states[sid].update(status='stopped', owned=False, error='')
        if conflicts:
            raise ValueError('本实例已停止，但端口被其他进程占用：' + ', '.join(conflicts) + '；未触碰占用者')
        self.log(sid, '已核实本实例退出')

    def close(self):
        self.closing.set()
        self.scanner.cancel()
        self._save()
