"""Static discovery. This module never imports or executes discovered code."""
from __future__ import annotations

import ctypes
import ast
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
import tomllib
from pathlib import Path
import psutil

MAX_FILE = 256 * 1024
DEFAULT_EXCLUDES = sorted({
    'windows', '$recycle.bin', 'system volume information', 'programdata',
    'node_modules', '.git', '.hg', '.svn', '.venv', 'venv', 'env', '.pylibs',
    '__pycache__', '.cache', 'cache', 'caches', '.npm', '.pnpm-store',
    '.nuget', '.gradle', 'site-packages', 'pipwork', 'vendor', '.idea',
    '.runtime', '.test-tmp', '.pytest_cache', 'runtime', 'test-artifacts',
    'appdata', 'recovery', 'config.msi', 'msocache', 'winsxs',
    '.tools', '.transforms', '.next', '.turbo', '.m2', 'gradle-home', 'pip-cache',
    'build', 'dist', 'target',
})

def canonical(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(str(path))))

def service_id(directory, entry='project'):
    return hashlib.sha256((canonical(directory) + '|' + entry).encode()).hexdigest()[:24]

def read_small(path):
    path = Path(path)
    if path.stat().st_size > MAX_FILE:
        raise ValueError(f'声明文件超过 {MAX_FILE // 1024} KB：{path.name}')
    return path.read_text(encoding='utf-8-sig', errors='replace')

def fixed_roots():
    if os.name != 'nt':
        return [str(Path.home())]
    bits = ctypes.windll.kernel32.GetLogicalDrives()
    return [f'{chr(65+i)}:\\' for i in range(26)
            if bits & (1 << i) and ctypes.windll.kernel32.GetDriveTypeW(f'{chr(65+i)}:\\') == 3]

def python_for(directory):
    for part in ('.venv/Scripts/python.exe', 'venv/Scripts/python.exe', '.venv/bin/python'):
        p = Path(directory) / part
        if p.is_file():
            return str(p)
    # Existing interpreter only; dependency availability is verified on explicit start.
    return sys.executable.replace('pythonw.exe', 'python.exe')

def base_candidate(directory):
    return dict(id=service_id(directory), name=Path(directory).name, description='自动发现的本地项目',
                directory=str(Path(directory).absolute()), version='版本未知', version_source='未提供版本声明',
                command=[], url='', health_path='/', health_mode='http', enabled=True,
                timeout=60, adapter='generic', source='scan', discovery={}, validation_errors=[], env={}, stop_command=[], discover_url=False)

def infer_url(text):
    # Only explicit local URLs or an unambiguous port declaration; never arbitrary remote URLs.
    urls = re.findall(r'https?://(?:127\.0\.0\.1|localhost):\d+(?:/[^\s\x22\x27<>]*)?', text)
    if urls:
        return urls[0].rstrip(').,;')
    ports = re.findall(r'(?:--port(?:=|\s+)|\bport\s*[:=]\s*)(\d{2,5})\b', text, re.I)
    ports = list(dict.fromkeys(ports))
    return f'http://127.0.0.1:{ports[0]}' if len(ports) == 1 and int(ports[0]) < 65536 else ''

def inspect_directory(directory, names):
    """Return zero/one service per installation; ambiguous entrypoints remain configurable."""
    directory = Path(directory)
    out = base_candidate(directory)
    evidence, issues = [], []
    node = None
    if 'package.json' in names:
        node = json.loads(read_small(directory / 'package.json'))
        if not isinstance(node, dict):
            raise ValueError('package.json 应为对象')
        out['name'] = str(node.get('displayName') or node.get('name') or out['name'])[:160]
        if node.get('version'):
            out.update(version=str(node['version'])[:100], version_source='package.json → version')
        scripts = node.get('scripts', {})
        if not isinstance(scripts, dict):
            raise ValueError('package.json scripts 应为对象')
        choices = [key for key in ('start', 'dev', 'serve', 'web') if isinstance(scripts.get(key), str)]
        if choices:
            # A package's explicit start script is its canonical entrypoint.
            choice = 'start' if 'start' in choices else choices[0] if len(choices) == 1 else None
            if choice:
                runner = shutil.which('npm.cmd') or shutil.which('npm')
                out['command'] = [runner or 'npm', 'run', choice]
                out['url'] = infer_url(scripts[choice])
                out['discover_url'] = not bool(out['url'])
                evidence.append(f'package.json scripts.{choice}')
                if not runner:
                    issues.append('未找到 npm，请安装环境或选择可用启动程序')
            else:
                evidence.append('package.json 含多个候选服务脚本：' + '、'.join(choices))
                issues.append('多个启动脚本，请选择唯一入口')
    pyproject = None
    if 'pyproject.toml' in names:
        pyproject = tomllib.loads(read_small(directory / 'pyproject.toml'))
        tool = pyproject.get('tool', {})
        if not isinstance(tool, dict):
            raise ValueError('pyproject.toml tool 应为表')
        meta = pyproject.get('project') or tool.get('poetry', {})
        if not isinstance(meta, dict):
            raise ValueError('pyproject.toml 项目元数据应为表')
        if meta.get('name') and not node:
            out['name'] = str(meta['name'])[:160]
        if meta.get('version') and not node:
            out.update(version=str(meta['version'])[:100], version_source='pyproject.toml → version')
        evidence.append('pyproject.toml')
    # Known adapters are discovered by content on disk, not their expected installation paths.
    if (directory / 'autovid/web/server.py').is_file() and (directory / 'autovid/cli.py').is_file():
        init = read_small(directory / 'autovid/__init__.py')
        match = re.search(r'^__version__\s*=\s*[\x22\x27]([^\x22\x27]+)', init, re.M)
        out.update(name='AutoVid 短视频口播工作台', description='口播、字幕与短视频工作台',
                   adapter='autovid', command=[python_for(directory), '-u', '-m', 'autovid', 'web', '--host', '127.0.0.1', '--port', '8899'],
                   url='http://127.0.0.1:8899/', version=match[1] if match else '版本未知',
                   version_source='autovid/__init__.py → __version__' if match else '未提供版本声明')
        evidence.append('AutoVid CLI + Web 服务源码入口')
        issues = []
    elif (directory / 'backend/main.py').is_file() and 'start.ps1' in names:
        start = read_small(directory / 'start.ps1')
        if 'backend.main:app' in start and 'VideoToNo' in start:
            out.update(name='视频转字幕 VideoToNo', description='本地视频转字幕与笔记工具', adapter='videotono',
                       command=[str(directory / '.venv/Scripts/python.exe'), '-u', '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000'],
                       url='http://127.0.0.1:8000', health_path='/api/health')
            evidence.append('VideoToNo start.ps1 → backend.main:app（管理台独立托管）')
            tree = ast.parse(read_small(directory / 'backend/main.py'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'FastAPI':
                    version = next((kw.value.value for kw in node.keywords if kw.arg == 'version' and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)), None)
                    if version:
                        out.update(version=version, version_source='backend/main.py → FastAPI.version')
                        break
            issues = []
    if not out['command'] and out['adapter'] == 'generic':
        # Only inspect conventional, small Python entrypoints, never arbitrary source trees.
        pychoices = []
        req = read_small(directory / 'requirements.txt') if 'requirements.txt' in names else ''
        for name in ('app.py', 'main.py', 'server.py', 'web.py'):
            if name not in names:
                continue
            text = read_small(directory / name)
            if re.search(r'\b(?:Flask|FastAPI|Streamlit|uvicorn|HTTPServer|ThreadingHTTPServer|gradio)\b', text + req, re.I):
                pychoices.append((name, text))
        if len(pychoices) == 1:
            name, text = pychoices[0]
            evidence.append(f'Python 网页框架入口 {name}')
            py = python_for(directory)
            if 'streamlit' in text.lower():
                out['command'] = [py, '-u', '-m', 'streamlit', 'run', name, '--server.address', '127.0.0.1']
                out['url'] = infer_url(text) or 'http://127.0.0.1:8501'
            elif re.search(r'FastAPI\s*\(', text) and not re.search(r'uvicorn\.run\s*\(', text):
                match = re.search(r'^(\w+)\s*=\s*FastAPI\s*\(', text, re.M)
                if match:
                    out['command'] = [py, '-u', '-m', 'uvicorn', f'{Path(name).stem}:{match[1]}', '--host', '127.0.0.1', '--port', '8000']
                    out['url'] = 'http://127.0.0.1:8000'
            elif re.search(r'__name__\s*==\s*[\x22\x27]__main__[\x22\x27]', text):
                out['command'] = [py, '-u', name]
                out['url'] = infer_url(text)
                out['discover_url'] = not bool(out['url'])
                if not out['url'] and 'Flask(' in text:
                    out['url'] = 'http://127.0.0.1:5000'
            else:
                issues.append('发现网页框架，需确认可执行启动入口')
        elif len(pychoices) > 1:
            evidence.append('多个 Python 网页入口')
            issues.append('多个 Python 入口，请选择启动命令')
    scripts = [name for name in names if re.match(r'^(?:start|serve|launch|run[-_]?web|启动(?:服务)?)(?:[-_].*)?\.(?:cmd|bat|ps1|sh)$', name, re.I)]
    if not out['command'] and scripts:
        evidence.extend(scripts)
        if len(scripts) == 1 and not issues:
            script = directory / scripts[0]
            text = read_small(script)
            if script.suffix.lower() == '.ps1':
                out['command'] = [shutil.which('powershell.exe') or 'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(script)]
            elif script.suffix.lower() in ('.cmd', '.bat'):
                out['command'] = [str(script)]
            else:
                issues.append('Shell 脚本需要手工选择运行环境')
            out['url'] = infer_url(text)
        else:
            issues.append('多个候选脚本，请确认一个启动入口')
    if not any(item != 'pyproject.toml' for item in evidence):
        return None
    if not out['command']:
        issues.append('缺少可确定的启动命令')
    if not out['url'] and not out['discover_url']:
        issues.append('未确定访问地址；可在配置填写地址，或启用启动输出/监听发现')
    # Dynamic URLs can safely be found at start via verified listener; no guessed ports.
    out['discovery'] = {'evidence': list(dict.fromkeys(evidence)), 'issues': list(dict.fromkeys(issues))}
    return out


class Scanner:
    def __init__(self, merge, project_root, is_blacklisted=None):
        self.merge, self.project_root = merge, canonical(project_root)
        self.is_blacklisted = is_blacklisted or (lambda directory: False)
        self.lock, self.cancel_event = threading.Lock(), threading.Event()
        self.state = dict(running=False, checked=0, found=0, skipped=0, blacklisted=0, errors=0, current='', issues=[], roots=[], excludes=DEFAULT_EXCLUDES, partial=False)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.state))

    def start(self, roots=None, excludes=None):
        with self.lock:
            if self.state['running']:
                raise ValueError('已有扫描正在进行')
            roots = roots or fixed_roots()
            if not isinstance(roots, list) or not roots or not all(isinstance(r, str) and os.path.isabs(r) for r in roots):
                raise ValueError('扫描目录必须是绝对路径列表')
            excludes = [] if excludes is None else excludes
            if not isinstance(excludes, list) or not all(isinstance(x, str) and x.strip() for x in excludes):
                raise ValueError('排除项必须是目录名或绝对目录列表')
            excludes = list(dict.fromkeys(DEFAULT_EXCLUDES + excludes))
            self.cancel_event.clear()
            self.state = dict(running=True, cancelled=False, checked=0, found=0, skipped=0, blacklisted=0, errors=0,
                              current='', issues=[], roots=roots, excludes=excludes, partial=False,
                              started_at=time.time(), finished_at=None, process_hints=[], process_metadata_skipped=0,
                              summary='正在遍历，尚无完整覆盖摘要')
        threading.Thread(target=self._run, daemon=True).start()
        return self.snapshot()

    def cancel(self):
        self.cancel_event.set()

    def issue(self, path, message):
        self.state['errors'] += 1
        if len(self.state['issues']) < 100:
            self.state['issues'].append({'path': str(path), 'message': str(message)[:300]})

    def _run(self):
        state = self.state
        names_excluded = {e.lower() for e in state['excludes'] if not os.path.isabs(e)}
        paths_excluded = [canonical(e) for e in state['excludes'] if os.path.isabs(e)]
        # The management application itself must never offer its internal server modules as tools.
        paths_excluded += [self.project_root]
        seen = set()
        try:
            stack = list(reversed(state['roots']))
            # Running process metadata is a read-only discovery clue. Never adopt ownership here.
            listener_pids = set()
            try:
                listener_pids = {c.pid for c in psutil.net_connections(kind='tcp') if c.status == psutil.CONN_LISTEN and c.pid}
            except (psutil.Error, OSError, RuntimeError) as exc:
                self.issue('运行实例线索', f'无法读取监听元数据：{type(exc).__name__}: {exc}')
            for process in psutil.process_iter(['name', 'pid']):
                if self.cancel_event.is_set():
                    break
                try:
                    if not any(n in (process.info['name'] or '').lower() for n in ('python', 'node', 'uvicorn', 'streamlit')):
                        continue
                    cwd = process.cwd()
                    if self.is_blacklisted(cwd):
                        continue
                    if not any(canonical(cwd) == canonical(r) or canonical(cwd).startswith(canonical(r).rstrip('\\/') + os.sep) for r in state['roots']):
                        continue
                    if len(state['process_hints']) < 200:
                        state['process_hints'].append({'pid': process.pid, 'directory': cwd, 'name': process.info['name'],
                                                       'listening': process.pid in listener_pids, 'control': '外部线索，只读'})
                    stack.append(cwd)
                except (psutil.Error, OSError, RuntimeError):
                    state['process_metadata_skipped'] += 1
            while stack and not self.cancel_event.is_set():
                directory = stack.pop()
                norm = canonical(directory)
                if norm in seen:
                    continue
                seen.add(norm)
                if any(norm == e or norm.startswith(e + os.sep) for e in paths_excluded):
                    state['skipped'] += 1
                    continue
                state['current'] = str(directory)
                try:
                    st = os.lstat(directory)
                    if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
                        state['skipped'] += 1
                        continue
                    with os.scandir(directory) as iterator:
                        entries = list(iterator)
                    state['checked'] += 1
                    names = {e.name for e in entries}
                    try:
                        blocked = self.is_blacklisted(directory)
                        if blocked:
                            state['blacklisted'] += 1
                        candidate = None if blocked else inspect_directory(directory, names)
                        if candidate:
                            if self.merge(candidate) is False:
                                state['blacklisted'] += 1
                            else:
                                state['found'] += 1
                    except (OSError, ValueError, TypeError, KeyError, SyntaxError) as exc:
                        self.issue(directory, f'声明解析失败：{exc}')
                    for entry in entries:
                        try:
                            if not entry.is_dir(follow_symlinks=False):
                                continue
                            if entry.name.lower() in names_excluded or entry.is_symlink() or getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & 0x400:
                                state['skipped'] += 1
                                continue
                            stack.append(entry.path)
                        except OSError as exc:
                            self.issue(entry.path, exc)
                except OSError as exc:
                    self.issue(directory, exc)
                # Bounded cancellation latency even on large directories; no artificial percentage.
            state['cancelled'] = self.cancel_event.is_set()
        except Exception as exc:
            self.issue(state['current'], f'扫描中断：{type(exc).__name__}: {exc}')
        finally:
            state['running'] = False
            state['finished_at'] = time.time()
            state['partial'] = bool(state.get('cancelled') or state['errors'])
            state['summary'] = ('已取消，保留部分结果' if state.get('cancelled') else '遍历结束') + f"；检查 {state['checked']} 个目录，发现 {state['found']} 个项目，黑名单忽略 {state['blacklisted']}，排除/跳过 {state['skipped']}，异常 {state['errors']}，进程线索 {len(state.get('process_hints', []))}，进程元数据不可读 {state.get('process_metadata_skipped', 0)}。仅覆盖列出的根目录及未排除区域；不保证识别所有程序。"
