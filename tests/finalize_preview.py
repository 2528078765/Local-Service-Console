"""Refresh only management records after discovery-rule QA; never starts business tools."""
from pathlib import Path
import json
import sys
import time
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from lsm.discovery import canonical, inspect_directory
from lsm.manager import Manager, HTTP, atomic_json
from launcher import checked_backend, URL

ROOT=Path(__file__).resolve().parent.parent
if checked_backend():
    with HTTP.open(URL+'/api/bootstrap',timeout=4) as response: token=json.load(response)['token']
    request=urllib.request.Request(URL+'/api/shutdown',data=b'{}',headers={'Origin':URL,'Content-Type':'application/json','X-Session-Token':token},method='POST')
    with HTTP.open(request,timeout=4): pass
    deadline=time.monotonic()+10
    while checked_backend() and time.monotonic()<deadline: time.sleep(.2)
    if checked_backend(): raise RuntimeError('预览后台未退出，不会竞争修改配置')
manager=Manager(ROOT,seed=True,monitor=False)
removed=[]
for sid,config in list(manager.configs.items()):
    directory=Path(config['directory'])
    if config.get('source')!='scan' or config.get('manual') or manager.states.get(sid,{}).get('owned'):
        continue
    try:
        is_self=canonical(directory)==canonical(ROOT) or canonical(directory).startswith(canonical(ROOT)+__import__('os').sep)
        candidate=None if is_self else inspect_directory(directory,{p.name for p in directory.iterdir()})
        if candidate is None:
            manager.remove(sid); removed.append({'name':config['name'],'directory':str(directory)})
    except (OSError,ValueError,SyntaxError):
        pass  # Keep ambiguous/moved records rather than silently erase them.
manager.scanner.start([str(ROOT.parent)])
while manager.scanner.snapshot()['running']: time.sleep(.2)
manager.refresh()
result={'removed_nonservice_scan_candidates':removed,'scan':manager.scanner.snapshot(),
        'service_count':len(manager.configs),'known_tools':[{'name':s['name'],'version':s['version'],'directory':s['directory'],'status':s['status']}
                 for s in manager.list_services() if s.get('source')=='preset']}
atomic_json(ROOT/'test-artifacts'/'final-scan-result.json',result)
manager.close()
print(json.dumps(result,ensure_ascii=False,indent=2))
