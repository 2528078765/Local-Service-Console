"""Remove only still-verified processes recorded by our isolated backend-process tests."""
from pathlib import Path
import json
import sys
import psutil
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from lsm import processes as proc
root=Path(__file__).resolve().parent.parent/'test-artifacts'
for record in root.glob('case-*/backend-process/runtime/instances.json'):
    for instance in json.loads(record.read_text(encoding='utf-8')).values():
        records=instance.get('members',[])
        active=[r['pid'] for r in records if proc.verified(r)]
        if active:
            print('cleaning isolated test instance',active)
            proc.force_stop(records)
# If a failing TemporaryDirectory teardown removed its JSON before Windows released cwd,
# identify only this application's durable workers whose cwd and spec both lie in case-*.
worker=(Path(__file__).resolve().parent.parent/'lsm/worker.py').resolve()
for process in psutil.process_iter(['pid']):
    try:
        args=process.cmdline()
        cwd=Path(process.cwd()).resolve()
        if not cwd.is_relative_to(root.resolve()) or not any(part.startswith('case-') for part in cwd.relative_to(root.resolve()).parts):
            continue
        if len(args)<4 or Path(args[2]).resolve()!=worker:
            continue
        spec=Path(args[3]).resolve()
        if not spec.is_relative_to(root.resolve()):
            continue
        if spec.exists():
            continue  # A current run still owns its spec; do not interfere with it.
        record=proc.identity(process.pid)
        print('cleaning verified orphan test worker',[record['pid']])
        proc.force_stop([record])
    except (OSError,ValueError,psutil.Error,RuntimeError):
        pass
