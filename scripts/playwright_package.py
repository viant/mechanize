"""Hash a self-contained local Playwright runtime using the broker's wire format."""
import hashlib
import json
import os
from pathlib import Path
import stat


def file_digest(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('Physical absolute Playwright file required')
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or
            info.st_uid not in (0, os.getuid()) or info.st_size > 256 * 1024 * 1024):
        raise ValueError('Owned bounded Playwright file required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_digest(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise ValueError('Physical absolute Playwright runtime required')
    files = []
    for current, directories, names in os.walk(root, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in directories)]:
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in (0, os.getuid()):
                raise ValueError('Owned Playwright directories without symlinks required')
        files.extend(Path(current) / name for name in names)
        if len(files) > 10000:
            raise ValueError('Playwright runtime file limit exceeded')
    digest = hashlib.sha256()
    for path in sorted(files):
        value = json.dumps([str(path.relative_to(root)), file_digest(path)], ensure_ascii=False, separators=(',', ':'))
        for raw, escaped in [('<', '\\u003c'), ('>', '\\u003e'), ('&', '\\u0026'), ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
            value = value.replace(raw, escaped)
        digest.update(value.encode('utf-8') + b'\n')
    return digest.hexdigest()


def configuration(node, runtime):
    for name in ('sidecar.mjs', 'engine.mjs', 'relay.mjs', 'fingerprint.cjs', 'target.cjs', 'package-lock.json', 'node_modules/playwright-core/package.json'):
        file_digest(Path(runtime) / name)
    return {'nodePath': str(node), 'nodeSHA256': file_digest(node),
            'runtimeRoot': str(runtime), 'runtimeSHA256': runtime_digest(runtime)}
