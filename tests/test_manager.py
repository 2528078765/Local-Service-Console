from __future__ import annotations
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lsm.discovery import Scanner, inspect_directory, service_id, DEFAULT_EXCLUDES
from lsm.manager import Manager, HTTP, validate
from lsm import processes as proc
from lsm.logging_utils import redact
from lsm.server import AppServer

ARTIFACTS = Path(__file__).resolve().parent.parent / 'test-artifacts'
ARTIFACTS.mkdir(exist_ok=True)

def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('等待条件超时')

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

HTTP_FIXTURE = '''from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import signal, threading, sys
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"fixture-ready")
    def log_message(self,*args): pass
server=ThreadingHTTPServer(("127.0.0.1",int(sys.argv[1])),Handler)
def stop(*args): threading.Thread(target=server.shutdown,daemon=True).start()
signal.signal(signal.SIGINT,stop)
if hasattr(signal,"SIGBREAK"): signal.signal(signal.SIGBREAK,stop)
signal.signal(signal.SIGTERM,stop)
print("http://127.0.0.1:%s/" % server.server_port,flush=True)
print("api_key=FAKE_PRIVATE_VALUE_123 token=FAKE_TOKEN_456",flush=True)
try: server.serve_forever(poll_interval=.1)
finally: server.server_close()
'''

class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='case-', dir=ARTIFACTS)
        self.root = Path(self.tmp.name)
        self.manager = None

    def tearDown(self):
        if self.manager:
            self.manager.close()
            for instance in self.manager.instances.values():
                proc.force_stop(instance.get('members', []))
        self.tmp.cleanup()

    def make_manager(self):
        self.manager = Manager(self.root / 'manager', seed=False, monitor=False)
        return self.manager

    def http_config(self, port=None, **extra):
        directory = self.root / 'service 中文 空格'
        directory.mkdir(exist_ok=True)
        script = directory / 'server.py'
        script.write_text(HTTP_FIXTURE, encoding='utf-8')
        port = port or free_port()
        config = dict(name='隔离 HTTP 服务', directory=str(directory), command=[sys.executable, '-u', str(script), str(port)],
                      url=f'http://127.0.0.1:{port}/', health_path='/', timeout=8)
        config.update(extra)
        return config

class DiscoveryTests(Fixture):
    def test_versions_same_name_different_paths_and_no_execution(self):
        discovered = []
        samples = self.root / 'samples'
        for index, version in enumerate(('1.0.0', '2.0.0', '1.0.0')):
            folder = samples / str(index)
            folder.mkdir(parents=True)
            (folder / 'package.json').write_text(json.dumps({'name': 'same-name', 'version': version, 'scripts': {'start': 'node server.js --port 5123 && echo executed > MARKER'}}))
            (folder / '.env').write_text('SECRET=DO_NOT_READ')
        script = samples / 'script'
        script.mkdir()
        (script / '启动服务.cmd').write_text('@echo executed > MARKER\npython -m http.server 8123')
        py = samples / 'python'
        py.mkdir()
        (py / 'app.py').write_text('from flask import Flask\napp=Flask(__name__)\nif __name__ == "__main__": app.run(port=5125)')
        damaged = samples / 'damaged'
        damaged.mkdir()
        (damaged / 'package.json').write_text('{"scripts": null}')
        scanner = Scanner(discovered.append, self.root / 'manager')
        scanner.start([str(samples)], [])
        wait_for(lambda: not scanner.snapshot()['running'])
        self.assertEqual(5, len(discovered))
        self.assertEqual(3, len({x['id'] for x in discovered if x['name'] == 'same-name'}))
        self.assertEqual({'1.0.0','2.0.0'}, {x['version'] for x in discovered if x['name']=='same-name'})
        self.assertFalse(list(samples.rglob('MARKER')))
        self.assertGreater(scanner.snapshot()['errors'], 0)
        self.assertIn('node_modules', scanner.snapshot()['excludes'])

    def test_manifest_type_errors_are_local_and_no_import(self):
        folder = self.root / 'project'; folder.mkdir()
        for value in (None, [], 'string'):
            (folder / 'package.json').write_text(json.dumps({'scripts': value}))
            with self.assertRaises(ValueError): inspect_directory(folder, {'package.json'})
        (folder / 'pyproject.toml').write_text('tool="wrong"')
        with self.assertRaises(ValueError): inspect_directory(folder, {'pyproject.toml'})

    def test_pure_python_library_and_manager_modules_are_not_tools(self):
        library=self.root/'library'; library.mkdir()
        (library/'pyproject.toml').write_text('[project]\nname="pure-library"\nversion="1.0"')
        self.assertIsNone(inspect_directory(library,{'pyproject.toml'}))
        manager_root=self.root/'manager'; manager_root.mkdir()
        (manager_root/'server.py').write_text(HTTP_FIXTURE)
        found=[]; scanner=Scanner(found.append,manager_root)
        scanner.start([str(manager_root)])
        wait_for(lambda:not scanner.snapshot()['running'])
        self.assertEqual([],found)
        self.assertGreaterEqual(scanner.snapshot()['skipped'],1)

    @unittest.skipUnless(os.name=='nt','Windows junction handling')
    def test_directory_junction_is_never_followed(self):
        samples=self.root/'samples'; samples.mkdir()
        outside=self.root/'outside'; outside.mkdir()
        (outside/'package.json').write_text('{"scripts":{"start":"node server.js"}}')
        junction=samples/'linked-project'
        result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(junction),str(outside)],capture_output=True)
        if result.returncode: self.skipTest('此环境不能创建目录联接')
        found=[]; scanner=Scanner(found.append,self.root/'manager')
        scanner.start([str(samples)])
        wait_for(lambda:not scanner.snapshot()['running'])
        self.assertFalse(found)
        self.assertGreater(scanner.snapshot()['skipped'],0)
        os.rmdir(junction)

    def test_incremental_merge_and_missing_directory(self):
        manager = self.make_manager()
        folder = self.root / 'node'; folder.mkdir()
        manifest = folder / 'package.json'
        manifest.write_text(json.dumps({'name':'sample','version':'1','scripts':{'start':'node index.js --port 5001'}}))
        candidate = inspect_directory(folder, {'package.json'})
        manager.merge(candidate); manager.merge(candidate)
        self.assertEqual(1, len(manager.configs))
        sid = candidate['id']
        command = [sys.executable, '-m', 'http.server', '5002']
        manager.save_config({'name':'我的自定义名', 'command': command, 'url':'http://127.0.0.1:5002'}, sid)
        candidate['version']='2'; manager.merge(candidate)
        self.assertEqual('我的自定义名', manager.configs[sid]['name'])
        self.assertEqual(command, manager.configs[sid]['command'])
        self.assertEqual('2', manager.configs[sid]['version'])
        manifest.unlink(); folder.rmdir(); manager.refresh()
        self.assertIn('位置失效', ' '.join(manager.list_services()[0]['validation_errors']))

    def test_cancel_and_excluded_dependency(self):
        samples=self.root/'samples'; samples.mkdir()
        for i in range(30): (samples / str(i)).mkdir()
        dependency=samples/'node_modules'; dependency.mkdir()
        (dependency/'package.json').write_text('{"scripts":{"start":"echo bad"}}')
        scanner=Scanner(lambda _: time.sleep(.01), self.root/'manager')
        scanner.start([str(samples)])
        scanner.cancel()
        wait_for(lambda: not scanner.snapshot()['running'])
        self.assertTrue(scanner.snapshot()['cancelled'])
        self.assertTrue(scanner.snapshot()['partial'])

    def test_log_redaction_signed_first_and_later_parameter(self):
        examples = ['api_key=FAKE_PRIVATE_VALUE_123', 'Bearer FAKE_TOKEN_456',
                    'https://example.test/file?token=FAKE_TOKEN_456',
                    'https://example.test/file?x=1&sig=FAKE_TOKEN_456',
                    'token="FAKE_TOKEN_456"', 'sk-fakefakefakefakefake']
        for example in examples:
            output=redact(example)
            self.assertNotIn('FAKE_', output)
            self.assertNotIn('fakefakefake', output)

class LifecycleTests(Fixture):
    def test_real_http_concurrency_restart_recovery_and_graceful_stop(self):
        manager=self.make_manager(); sid=manager.save_config(self.http_config())
        manager.action(sid,'start')
        with self.assertRaises(ValueError): manager.action(sid,'start')
        wait_for(lambda: not manager.operations, 15)
        self.assertEqual('running', manager.states[sid]['status'], manager.states[sid])
        self.assertNotIn('FAKE_PRIVATE_VALUE_123', manager.logs(sid))
        first=manager.instances[sid]['root']
        with self.assertRaises(ValueError): manager.save_config({'directory':str(self.root)},sid)
        with self.assertRaises(ValueError): manager.remove(sid)
        manager.save_config({'name':'新名字'},sid)
        manager.close()
        recovered=Manager(manager.root,seed=False,monitor=False)
        self.manager=recovered
        self.assertEqual('running', recovered.states[sid]['status'], recovered.states[sid])
        self.assertEqual(first, recovered.instances[sid]['root'])
        recovered.action(sid,'restart')
        wait_for(lambda: not recovered.operations, 25)
        self.assertEqual('running',recovered.states[sid]['status'],recovered.states[sid])
        self.assertFalse(proc.verified(first))
        recovered.action(sid,'stop')
        wait_for(lambda: not recovered.operations,25)
        self.assertEqual('stopped', recovered.states[sid]['status'], recovered.states[sid])
        self.assertTrue(Path(recovered.configs[sid]['directory']).is_dir())
        recovered.remove(sid)
        self.assertTrue((self.root/'service 中文 空格/server.py').exists())

    def test_wrong_identity_cannot_kill_or_recover(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            record=proc.identity(child.pid); wrong=copy.deepcopy(record); wrong['created']+=100
            self.assertFalse(proc.verified(wrong))
            proc.force_stop([wrong])
            self.assertIsNone(child.poll())
            wrong=copy.deepcopy(record); wrong['command_hash']='mismatch'
            self.assertFalse(proc.verified(wrong))
        finally:
            child.kill(); child.wait()

    def test_conflicting_port_and_timeout_no_automatic_force(self):
        manager=self.make_manager(); port=free_port()
        with socket.socket() as blocker:
            blocker.bind(('127.0.0.1',port)); blocker.listen()
            sid=manager.save_config(self.http_config(port))
            manager.action(sid,'start'); wait_for(lambda:not manager.operations)
            self.assertIn('已被占用',manager.states[sid]['error'])
            self.assertNotIn(sid,manager.instances)
        config=self.http_config(command=[sys.executable,'-c','import time;time.sleep(40)'],timeout=1)
        sid=manager.save_config(config); manager.action(sid,'start'); wait_for(lambda:not manager.operations)
        self.assertIn('启动超时',manager.states[sid]['error'])
        self.assertTrue(any(proc.verified(r) for r in manager.instances[sid]['members']))
        manager.action(sid,'stop',True); wait_for(lambda:not manager.operations)
        self.assertEqual('stopped',manager.states[sid]['status'])

    def test_external_readonly_and_dynamic_actual_url(self):
        manager=self.make_manager(); config=self.http_config(url='',discover_url=True)
        sid=manager.save_config(config); manager.action(sid,'start'); wait_for(lambda:not manager.operations)
        self.assertEqual('running', manager.states[sid]['status'], manager.states[sid])
        self.assertTrue(manager.instances[sid]['actual_url'].startswith('http://127.0.0.1:'))
        manager.action(sid,'stop'); wait_for(lambda:not manager.operations,25)
        config=self.http_config(); external=proc.launch(config['command'],config['directory'])
        try:
            wait_for(lambda:bool(proc.listening_ports([proc.identity(external.pid)])))
            sid2=manager.save_config(config); manager.refresh()
            self.assertEqual('external', manager.states[sid2]['status'],manager.states[sid2])
            with self.assertRaises(ValueError): manager.action(sid2,'stop',True)
            manager.remove(sid2)
            self.assertIsNone(external.poll())
        finally:
            external.kill(); external.wait()

    def test_process_only_does_not_treat_worker_as_ready(self):
        manager=self.make_manager()
        config=self.http_config(command=[sys.executable,'-c','raise RuntimeError("expected-start-failure")'],health_mode='process',url='')
        sid=manager.save_config(config); manager.action(sid,'start'); wait_for(lambda:not manager.operations)
        self.assertEqual('error',manager.states[sid]['status'],manager.states[sid])

    def test_slow_stop_script_is_cleaned_before_a_later_instance(self):
        manager=self.make_manager()
        marker=self.root/'LATE_STOP_MARKER'
        stop=[sys.executable,'-c',f'import time;from pathlib import Path;time.sleep(16);Path({str(marker)!r}).write_text("late")']
        sid=manager.save_config(self.http_config(stop_command=stop))
        manager.action(sid,'start'); wait_for(lambda:not manager.operations)
        self.assertEqual('running',manager.states[sid]['status'])
        manager.action(sid,'stop'); wait_for(lambda:not manager.operations,23)
        self.assertEqual('error',manager.states[sid]['status'])
        self.assertIn('辅助进程',manager.states[sid]['error'])
        self.assertFalse(any(proc.verified(r) for r in manager.instances[sid].get('stop_members',[])))
        time.sleep(2)
        self.assertFalse(marker.exists(),'超时停止脚本不得继续执行')
        manager.action(sid,'stop',True); wait_for(lambda:not manager.operations)
        manager.save_config({'stop_command':[]},sid)
        manager.action(sid,'start'); wait_for(lambda:not manager.operations)
        self.assertEqual('running',manager.states[sid]['status'])
        manager.action(sid,'stop'); wait_for(lambda:not manager.operations,25)

class ApiTests(Fixture):
    def setUp(self):
        super().setUp()
        self.server=AppServer(self.root/'api',0,seed=False)
        self.manager=self.server.manager
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.origin=self.server.origin
        self.token=self.server.token

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()
        super().tearDown()

    def request(self,path,method='GET',data=None,token=True,origin=None,headers=None):
        h={}
        if token: h['X-Session-Token']=self.token
        if method!='GET': h.update({'Content-Type':'application/json','Origin':origin or self.origin})
        h.update(headers or {})
        req=urllib.request.Request(self.origin+path,data=json.dumps(data or {}).encode() if method!='GET' else None,headers=h,method=method)
        try:
            with HTTP.open(req,timeout=3) as response: return response.status,response.read()
        except urllib.error.HTTPError as exc:
            with exc: return exc.code,exc.read()

    def test_session_origin_host_and_static_navigation(self):
        self.assertEqual(200,self.request('/api/bootstrap',token=False)[0])
        self.assertEqual(403,self.request('/api/services',token=False)[0])
        self.assertEqual(403,self.request('/api/services','POST',{},origin='https://evil.test')[0])
        self.assertEqual(403,self.request('/api/bootstrap',headers={'Sec-Fetch-Site':'cross-site'})[0])
        self.assertEqual(200,self.request('/',token=False,headers={'Sec-Fetch-Site':'cross-site'})[0])
        self.assertEqual(403,self.request('/api/bootstrap',headers={'Host':'evil.test'})[0])
        self.assertEqual(404,self.request('/api/services/../../logs')[0])

    def test_crud_validation_and_scan_api(self):
        code,body=self.request('/api/services','POST',self.http_config())
        self.assertEqual(201,code,body); sid=json.loads(body)['id']
        code,body=self.request('/api/services/'+sid,'PATCH',{'env':{'API_KEY':'FAKE'}})
        self.assertEqual(400,code)
        code,_=self.request('/api/services/'+sid,'PATCH',{'name':'改名','env':{'APP_MODE':'local'}})
        self.assertEqual(200,code)
        self.assertEqual(200,self.request('/api/services/'+sid,'DELETE',{})[0])
        self.assertEqual(202,self.request('/api/scan','POST',{'roots':[str(self.root)]})[0])
        self.assertEqual(200,self.request('/api/scan/cancel','POST',{})[0])

class BackendProcessTests(Fixture):
    def test_actual_backend_exit_preserves_service_and_new_session_recovers(self):
        root=self.root/'backend-process'; root.mkdir()
        port=free_port(); origin=f'http://127.0.0.1:{port}'
        backends=[]
        service_record=None
        def backend():
            options=dict(cwd=str(Path(__file__).resolve().parent.parent),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if os.name=='nt': options['creationflags']=subprocess.CREATE_NO_WINDOW
            child=subprocess.Popen([sys.executable,'-m','lsm.server','--root',str(root),'--port',str(port),'--no-seed'],**options)
            backends.append(child)
            wait_for(lambda: child.poll() is not None or reachable(origin+'/api/bootstrap'))
            if child.poll() is not None: raise AssertionError('隔离后台启动失败')
            return child
        def request(path,token=None,data=None):
            headers={}
            if token: headers['X-Session-Token']=token
            if data is not None: headers.update({'Origin':origin,'Content-Type':'application/json'})
            req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
            with HTTP.open(req,timeout=4) as response: return json.load(response)
        try:
            first=backend(); oldtoken=request('/api/bootstrap')['token']
            sid=request('/api/services',oldtoken,self.http_config())['id']
            request(f'/api/services/{sid}/start',oldtoken,{})
            def row(): return next(s for s in request('/api/services',oldtoken)['services'] if s['id']==sid)
            wait_for(lambda:row()['status']=='running',15)
            service=row(); service_record=json.loads((root/'runtime/instances.json').read_text(encoding='utf-8'))[sid]['root']
            request('/api/shutdown',oldtoken,{})
            first.wait(timeout=8)
            self.assertTrue(proc.verified(service_record))
            with HTTP.open(service['actual_url'],timeout=2) as response: self.assertEqual(200,response.status)
            second=backend(); newtoken=request('/api/bootstrap')['token']
            self.assertNotEqual(oldtoken,newtoken)
            restored=next(s for s in request('/api/services',newtoken)['services'] if s['id']==sid)
            self.assertEqual('running',restored['status'],restored)
            self.assertTrue(restored['owned'])
            self.assertEqual(service['pid'],restored['pid'])
            request(f'/api/services/{sid}/stop',newtoken,{})
            wait_for(lambda: next(s for s in request('/api/services',newtoken)['services'] if s['id']==sid)['status']=='stopped',25)
            self.assertFalse(proc.verified(service_record))
            request('/api/shutdown',newtoken,{})
            second.wait(timeout=8)
        finally:
            for child in backends:
                if child.poll() is None: child.kill(); child.wait()
            if service_record: proc.force_stop(proc.expand_owned([service_record]))
            instances=root/'runtime/instances.json'
            if instances.exists():
                for instance in json.loads(instances.read_text(encoding='utf-8')).values():
                    proc.force_stop(instance.get('members',[]))

def reachable(url):
    try:
        with HTTP.open(url,timeout=.3): return True
    except OSError: return False

if __name__ == '__main__': unittest.main(verbosity=2)
