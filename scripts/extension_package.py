"""Exact, bounded Chrome runtime resources; no browser or installation actions."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

FILES = ('browser.js', 'content.js', 'dom.js', 'fingerprint.js', 'manifest.json', 'options.html',
         'options.js', 'protocol.js', 'recorder.js', 'retirement.js', 'worker.js')
# Exact historical snapshots accepted only for upgrade backup and rollback.
OLDEST_LEGACY_FILES = ('browser.js', 'content.js', 'dom.js', 'manifest.json', 'options.html',
                       'options.js', 'protocol.js', 'recorder.js', 'worker.js')
INTERMEDIATE_LEGACY_FILES = ('browser.js', 'content.js', 'dom.js', 'fingerprint.js', 'manifest.json',
                             'options.html', 'options.js', 'protocol.js', 'recorder.js', 'worker.js')
LEGACY_FILE_SETS = (OLDEST_LEGACY_FILES, INTERMEDIATE_LEGACY_FILES)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def safe(path):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError('canonical extension path required')
    if any(part.is_symlink() for part in [path, *path.parents]):
        raise ValueError('extension symlink rejected')
    return path


def owned_directory(path):
    path = safe(path)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('owned non-shared-writable extension directory required')
    return path


def read_resource(path):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as resource:
        info = os.fstat(resource.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                info.st_mode & 0o022 or info.st_size > MAX_FILE_BYTES):
            raise ValueError('bounded owned regular extension resource required')
        result = resource.read(MAX_FILE_BYTES + 1)
    if len(result) > MAX_FILE_BYTES:
        raise ValueError('extension resource exceeds byte bound')
    return result


def inventory_hash(files, allow_legacy=False):
    accepted = {frozenset(FILES)}
    if allow_legacy:
        accepted.update(frozenset(names) for names in LEGACY_FILE_SETS)
    if not isinstance(files, dict) or frozenset(files) not in accepted or any(
            not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value) for value in files.values()):
        raise ValueError('exact Chrome runtime hash inventory required')
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def inventory(path, exact=True, allow_legacy=False):
    path = owned_directory(path)
    actual_names = {entry.name for entry in path.iterdir()}
    if exact:
        if actual_names == set(FILES):
            names = FILES
        elif allow_legacy and any(actual_names == set(legacy) for legacy in LEGACY_FILE_SETS):
            names = next(legacy for legacy in LEGACY_FILE_SETS if actual_names == set(legacy))
        else:
            raise ValueError('exact Chrome runtime resource set required')
    else:
        names = FILES
    identity(path)
    result, total = {}, 0
    for name in names:
        data = read_resource(path / name)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('Chrome runtime package exceeds byte bound')
        result[name] = hashlib.sha256(data).hexdigest()
    return {'files': result, 'sha256': inventory_hash(result, allow_legacy=allow_legacy)}


def identity(path):
    try:
        manifest = json.loads(read_resource(Path(path) / 'manifest.json'))
    except (ValueError, UnicodeError):
        raise ValueError('valid bounded Chrome runtime manifest required') from None
    if (not isinstance(manifest, dict) or manifest.get('manifest_version') != 3 or
            manifest.get('background') != {'service_worker': 'worker.js', 'type': 'module'} or
            manifest.get('options_page') != 'options.html' or
            'key' in manifest and (not isinstance(manifest['key'], str) or not manifest['key'])):
        raise ValueError('exact MV3 runtime entry points required')
    return manifest.get('key')


def verify(path, files, digest, allow_legacy=False):
    if not isinstance(digest, str) or inventory_hash(files, allow_legacy=allow_legacy) != digest:
        raise ValueError('Chrome runtime inventory digest mismatch')
    actual = inventory(path, allow_legacy=allow_legacy)
    if actual != {'files': files, 'sha256': digest}:
        raise ValueError('Chrome runtime resource hashes disagree')
    return actual


def copy(source, target, expected, source_exact=True, allow_legacy=False):
    if source_exact:
        verify(source, expected['files'], expected['sha256'], allow_legacy=allow_legacy)
    elif inventory(source, exact=False) != expected:
        raise ValueError('Chrome source changed before packaging')
    target = safe(target)
    if target.exists():
        raise ValueError('fresh Chrome package destination required')
    owned_directory(target.parent)
    target.mkdir(mode=0o700)
    try:
        for name in sorted(expected["files"]):
            data = read_resource(Path(source) / name)
            fd = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        verify(target, expected['files'], expected['sha256'], allow_legacy=allow_legacy)
    except Exception:
        shutil.rmtree(target)
        raise


def replace(source, target, expected, allow_legacy=False):
    # Caller must first inhibit the enrolled Chrome and native host. Keeping the
    # absolute target unchanged preserves Chrome's unpacked extension identity.
    target = safe(target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(target.parent)
    if target.exists():
        inventory(target, allow_legacy=allow_legacy)
    staged = Path(tempfile.mkdtemp(prefix='.extension-stage-', dir=target.parent))
    staged.rmdir()
    previous = target.parent / ('.extension-previous-' + uuid.uuid4().hex)
    try:
        copy(source, staged, expected, allow_legacy=allow_legacy)
        if target.exists():
            os.replace(target, previous)
        try:
            os.replace(staged, target)
            verify(target, expected['files'], expected['sha256'], allow_legacy=allow_legacy)
        except Exception:
            if target.exists():
                shutil.rmtree(target)
            if previous.exists():
                os.replace(previous, target)
            raise
        if previous.exists():
            shutil.rmtree(previous)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def build(source, destination):
    expected = inventory(source, exact=False)
    destination = safe(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(destination.parent)
    staged = Path(tempfile.mkdtemp(prefix='.extension-build-', dir=destination.parent))
    staged.rmdir()
    try:
        copy(source, staged, expected, source_exact=False)
        replace(staged, destination, expected)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    return expected
