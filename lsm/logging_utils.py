import re
from pathlib import Path

def redact(text):
    text = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*', r'\1[已隐藏]', text)
    text = re.sub(r'https?://[^\s<>\x22\x27]+\?[^\s<>\x22\x27]*(?:sig|token|signature|key|x-amz-signature|credential)=[^\s<>\x22\x27]+', '[已隐藏带凭据链接]', text, flags=re.I)
    text = re.sub(r'(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret|authorization|signature|credential|x-amz-signature)\s*[\x22\x27]?\s*[:=]\s*[\x22\x27]?)[^\s\x22\x27&,;<>]+', r'\1[已隐藏]', text)
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{12,}', '[已隐藏密钥]', text)
    return text

def append_log(path, text, limit=10 * 1024 * 1024):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size >= limit:
        oldest = path.with_suffix('.log.4')
        oldest.unlink(missing_ok=True)
        for index in range(3, 0, -1):
            source = path.with_suffix(f'.log.{index}')
            if source.exists():
                source.replace(path.with_suffix(f'.log.{index+1}'))
        path.replace(path.with_suffix('.log.1'))
    with path.open('a', encoding='utf-8') as handle:
        handle.write(redact(text))

def tail_log(path, size=128 * 1024):
    try:
        with Path(path).open('rb') as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - size))
            return redact(handle.read().decode('utf-8', errors='replace'))
    except OSError:
        return ''
