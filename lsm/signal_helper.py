"""Short-lived helper: attach only the dedicated console of a verified managed root."""
import ctypes
import sys
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lsm.processes import verified

record = json.loads(sys.argv[2])
if not verified(record):
    raise SystemExit(4)

kernel = ctypes.windll.kernel32
kernel.FreeConsole()
if not kernel.AttachConsole(int(sys.argv[1])):
    print('AttachConsole error', kernel.GetLastError())
    raise SystemExit(2)
if not verified(record):
    kernel.FreeConsole()
    raise SystemExit(4)
# A NULL handler only ignores Ctrl+C; Ctrl+Break needs a real handler.
handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
handler = handler_type(lambda event: True)
kernel.SetConsoleCtrlHandler(handler, True)
ok = kernel.GenerateConsoleCtrlEvent(1, 0)  # CTRL_BREAK_EVENT, dedicated console only
time.sleep(.1)
kernel.FreeConsole()
raise SystemExit(0 if ok else 3)
