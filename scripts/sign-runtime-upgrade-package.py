#!/usr/bin/env python3
"""Sign reviewed upgrade metadata locally; never install or authorize an upgrade.

The Ed25519 private key and signed output must be outside the source repository.
The public review key must already be enrolled in the signed approval console.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

DOMAIN = b'viant.mechanize.runtime-upgrade-package.v1\0'
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def canonical(path):
    path = Path(path)
    if not path.is_absolute() or Path(os.path.normpath(path)) != path or path.resolve() != path:
        raise ValueError('Canonical absolute file path required')
    return path


def outside_sources(path):
    path = canonical(path)
    if path == SOURCE_ROOT or SOURCE_ROOT in path.parents or any((p / '.git').exists() for p in path.parents):
        raise ValueError('Private signing files must be outside Git sources')
    return path


def read_private(path, limit):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= limit:
            raise ValueError('Private bounded owned regular file required')
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
        entry = path.lstat()
        if len(data) != before.st_size or (before.st_dev, before.st_ino) != (entry.st_dev, entry.st_ino) or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Signing input changed during read')
    return data


def sign(payload_path, private_key_path, output_path, openssl='openssl'):
    key = read_private(outside_sources(private_key_path), 16384)
    payload = read_private(payload_path, 2_000_000)
    # Structural validation belongs to the console and installer. This tool
    # signs the exact reviewed bytes; it cannot create consent or key-custody claims.
    if not isinstance(json.loads(payload), dict):
        raise ValueError('Reviewed JSON object required')
    output = outside_sources(output_path)
    parent = output.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError('Private owned output directory required')
    with tempfile.TemporaryDirectory(prefix='mechanize-package-sign-') as temp:
        root = Path(temp)
        for name, data in [('review-key.pem', key), ('message', DOMAIN + payload)]:
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f: f.write(data)
        completed = subprocess.run([openssl, 'pkeyutl', '-sign', '-rawin', '-inkey', str(root / 'review-key.pem'), '-in', str(root / 'message'), '-out', str(root / 'signature')], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        if completed.returncode:
            raise ValueError('Local signing failed; diagnostic output withheld')
        signature = (root / 'signature').read_bytes()
        if len(signature) != 64:
            raise ValueError('Ed25519 review key required')
    envelope = json.dumps({'version': 1, 'payloadBase64': base64.b64encode(payload).decode(), 'signatureBase64': base64.b64encode(signature).decode()}, separators=(',', ':')).encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(envelope); f.flush(); os.fsync(f.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--private-key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    sign(args.payload, args.private_key, args.output, args.openssl)
    print(json.dumps({'signedPackageWritten': True, 'installationPerformed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Upgrade package signing failed; private diagnostic output withheld') from None
