"""Explicit real local UI startup checks only. No transcription/generation/cloud calls."""
from pathlib import Path
import json
import socket
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from lsm.discovery import inspect_directory
from lsm.manager import Manager, HTTP, atomic_json
from lsm import processes as proc

ROOT=Path(__file__).resolve().parent.parent
REPORT=ROOT/'test-artifacts'/'real-tools-result.json'

def wait(manager, sid, seconds=90):
    deadline=time.monotonic()+seconds
    while manager.operations.get(sid) and time.monotonic()<deadline:
        time.sleep(.2)
    if manager.operations.get(sid): raise RuntimeError('操作等待超时')
    return dict(manager.states[sid])

def main():
    report={'started_at':time.time(),'scope':'启动首页与健康检查，不运行任何业务任务','cases':[]}
    manager=Manager(ROOT/'test-artifacts'/'real-tools-manager',seed=False,monitor=False)
    created=[]
    try:
        for name in ('video-to-note-1.4.6','shortvideo-agent'):
            directory=ROOT.parent/name
            config=inspect_directory(directory,{p.name for p in directory.iterdir()})
            external=proc.project_processes(directory,config['command'])
            report['cases'].append({'check':'preflight','name':name,'external_pids':[r['pid'] for r in external],
                                    'version':config['version'],'version_source':config['version_source']})
            if external:
                raise RuntimeError(f'{name}已有外部实例，停止测试且不触碰它')
            sid=config['id']; manager.merge(config)
            # This test may be rerun; never adopt stale PID state blindly.
            manager.instances.pop(sid,None)
            manager.action(sid,'start'); created.append(sid)
            state=wait(manager,sid)
            actual=manager.instances.get(sid,{}).get('actual_url')
            report['cases'].append({'check':'start','name':name,'status':state['status'],'error':state.get('error'),
                                    'actual_url':actual,'pids':[r['pid'] for r in manager.instances.get(sid,{}).get('members',[])]})
            if state['status']!='running': raise RuntimeError(f'{name}启动失败：'+state.get('error',''))
            with HTTP.open(actual,timeout=4) as response:
                report['cases'].append({'check':'homepage','name':name,'http_status':response.status,'html_bytes_sampled':len(response.read(4096))})
            manager.close()
            manager=Manager(manager.root,seed=False,monitor=False)
            if manager.states[sid]['status']!='running': raise RuntimeError(f'{name}恢复失败')
            report['cases'].append({'check':'manager-recovery','name':name,'status':manager.states[sid]['status']})
            manager.action(sid,'restart'); state=wait(manager,sid)
            report['cases'].append({'check':'restart','name':name,'status':state['status'],'error':state.get('error')})
            if state['status']!='running': raise RuntimeError(f'{name}重启失败：'+state.get('error',''))
            manager.action(sid,'stop'); state=wait(manager,sid)
            report['cases'].append({'check':'graceful-stop','name':name,'status':state['status'],'error':state.get('error')})
            if state['status']!='stopped': raise RuntimeError(f'{name}正常停止失败：'+state.get('error',''))
            if name=='shortvideo-agent':
                with socket.socket() as blocker:
                    blocker.bind(('127.0.0.1',8899)); blocker.listen()
                    manager.action(sid,'start'); state=wait(manager,sid)
                    actual=manager.instances.get(sid,{}).get('actual_url','')
                    report['cases'].append({'check':'port-fallback','status':state['status'],'actual_url':actual,'blocker_still_listening':blocker.fileno()>=0})
                    if state['status']!='running' or ':8899/' in actual: raise RuntimeError('AutoVid端口回退验证失败')
                    manager.action(sid,'stop'); state=wait(manager,sid)
                    if state['status']!='stopped': raise RuntimeError('AutoVid回退端口实例正常停止失败')
                    with socket.socket() as probe:
                        report['cases'].append({'check':'blocker-survives-stop','port':8899,'connect_result':probe.connect_ex(('127.0.0.1',8899))})
        report['passed']=True
    except Exception as exc:
        report.update(passed=False,error=str(exc))
        raise
    finally:
        for sid in created:
            instance=manager.instances.get(sid,{})
            owned=proc.expand_owned(instance.get('members',[]))
            if owned:
                # Isolated smoke's own instances only; explicit test cleanup, never external.
                report['cases'].append({'check':'test-cleanup-force','id':sid,'pids':[r['pid'] for r in owned]})
                proc.force_stop(owned)
                instance.update(members=[],stopped=True,actual_url='')
        manager.close()
        report['finished_at']=time.time()
        atomic_json(REPORT,report)
        print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
