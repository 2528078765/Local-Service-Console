"""Windowless Windows entrypoint for the service desk desktop shortcut."""
from pathlib import Path
import ctypes
import io
import os
import sys


def show_error(message):
    if os.name == 'nt':
        ctypes.windll.user32.MessageBoxW(None, message, '本地服务台', 0x10)


def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)
    # pythonw has no console streams; existing launcher diagnostics remain usable.
    sys.stdout = sys.stdout or io.StringIO()
    sys.stderr = sys.stderr or io.StringIO()
    try:
        from launcher import main as launch
        launch()
        return 0
    except Exception as exc:
        message = f'无法打开本地服务台：{exc}'
        try:
            from lsm.logging_utils import append_log
            append_log(root / 'runtime' / 'desktop-launcher.log', message + '\n')
        except Exception:
            pass
        show_error(message + '\n\n请确认 Python 和项目文件仍在原位置。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
