#!/usr/bin/env python3
"""Stage a signed console-only update; --apply requires an operator-verified idle broker.

Preflight: --source SOURCE_ROOT --installation INSTALL_ROOT
Apply: add --apply --broker-pid PID --idle-verified (normal Keychain UI optional).
Rollback: --installation INSTALL_ROOT --rollback BACKUP --broker-pid PID --idle-verified
Never rebuilds/replaces broker/helper, database, credentials or permanent grants.
"""
import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid


def safe(path):
    p = Path(path).absolute()
    if any(x.is_symlink() for x in [p, *p.parents]):
        raise ValueError('symlink path rejected')
    return p


def private(path):
    p = safe(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_size > 1048576:
            raise ValueError('private bounded owned file required')
        return f.read()


def run(*args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError(Path(args[0]).name + ' failed (output withheld)')
    return result


def atomic(path, data):
    fd, temp = tempfile.mkstemp(prefix='.console-update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def requirement(app):
    run('codesign', '--verify', '--strict', str(app))
    info = run('codesign', '--display', '--verbose=4', str(app)).stderr.decode()
    match = re.search(r'^CDHash=([0-9a-f]{40})$', info, re.M)
    if not match:
        raise ValueError('exact console hash unavailable')
    req = 'identifier "com.viant.mechanize.consent" and cdhash H"' + match[1] + '"'
    run('codesign', '--verify', '--strict', '--test-requirement', '=' + req, str(app))
    return req


def process_identity(pid, executable):
    lib = ctypes.CDLL('/usr/lib/libproc.dylib')
    buf = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid, buf, len(buf)) <= 0 or Path(os.fsdecode(buf.value)) != executable:
        raise ValueError('PID executable identity mismatch')
    result = run('ps', '-p', str(pid), '-o', 'uid=', '-o', 'lstart=').stdout.decode().strip()
    if not result or int(result.split()[0]) != os.getuid():
        raise ValueError('PID ownership mismatch')
    return result


def stop(pid, executable):
    identity = process_identity(pid, executable)
    if process_identity(pid, executable) != identity:
        raise ValueError('PID generation changed')
    os.kill(pid, signal.SIGTERM)
    for _ in range(150):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(.1)
    raise RuntimeError('graceful shutdown unconfirmed; no forced kill')


def stop_consoles(app):
    executable = app / 'Contents/MacOS/MechanizeConsent'
    for line in run('ps', '-axo', 'pid=,uid=,comm=').stdout.decode().splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[1] == str(os.getuid()) and fields[2] == str(executable):
            stop(int(fields[0]), executable)


def start(root, listen):
    logs = root / 'logs'
    logs.mkdir(mode=0o700, exist_ok=True)
    with (logs / 'broker.stdout.log').open('ab') as out, (logs / 'broker.stderr.log').open('ab') as err:
        p = subprocess.Popen([str(root / 'mechanize'), 'serve', '-config', str(root / 'config.json'), '-listen', listen],
                             cwd=root, stdout=out, stderr=err, start_new_session=True)
    time.sleep(.5)
    process_identity(p.pid, root / 'mechanize')
    return p.pid


def enroll(app, req, config, interactive):
    # Run as the verified console itself: macOS's creator signing partition must
    # match the reader, not a separate ad-hoc enrollment helper.
    run('codesign', '--verify', '--strict', '--test-requirement', '=' + req, str(app))
    key = base64.b64decode(private(config['keys']['HMAC']['URL']), validate=True)
    policy = config['identityPolicy']
    if policy['algorithms'] != ['HS256'] or 'development-console' not in policy['clients'] or len(config['users']) != 1:
        raise ValueError('unsupported development identity configuration')
    b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b'=')
    now = int(time.time())
    claims = {'iss': policy['issuer'], 'aud': policy['audience'], 'sub': config['users'][0]['subject'],
              'client_id': 'development-console', 'scope': 'desktop:observe consent:admin', 'iat': now, 'nbf': now - 30, 'exp': now + 86400}
    payload = b64(b'{"alg":"HS256","typ":"JWT"}') + b'.' + b64(json.dumps(claims, separators=(',', ':')).encode())
    token = payload + b'.' + b64(hmac.new(key, payload, hashlib.sha256).digest())
    args = [str(app / 'Contents/MacOS/MechanizeConsent'), '--enroll-credential'] + (['--interactive'] if interactive else [])
    result = json.loads(run(*args, input=token, timeout=120 if interactive else 20).stdout)
    if result != {'enrolled': True, 'code': 'enrollmentAdded'}:
        raise RuntimeError('console enrollment response rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source'); parser.add_argument('--installation', required=True)
    parser.add_argument('--apply', action='store_true'); parser.add_argument('--rollback')
    parser.add_argument('--broker-pid', type=int); parser.add_argument('--idle-verified', action='store_true')
    parser.add_argument('--interactive-enrollment', action='store_true')
    parser.add_argument('--listen', default='127.0.0.1:4987')
    args = parser.parse_args()
    if os.uname().sysname != 'Darwin' or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', args.listen):
        raise ValueError('macOS and explicit IPv4 loopback listener required')
    os.umask(0o077)
    root = safe(args.installation)
    if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError('private owned installation required')
    app = root / 'Mechanize Permissions.app'; config_path = root / 'config.json'
    config_bytes = private(config_path); config = json.loads(config_bytes)
    old_req = requirement(app)
    if old_req != config['nativeConsole']['designatedRequirement']:
        raise ValueError('installed console and broker pin disagree')
    hashes = {name: hashlib.sha256(safe(root / name).read_bytes()).hexdigest() for name in ('mechanize', 'mechanize-native')}
    if args.apply or args.rollback:
        if not args.broker_pid or not args.idle_verified:
            raise ValueError('operator must verify idle through MCP and provide owned broker PID')
        process_identity(args.broker_pid, root / 'mechanize')
    if args.rollback:
        backup = safe(args.rollback)
        saved_config = private(backup / 'config.json')
        expected = json.loads(config_bytes); restored = json.loads(saved_config)
        expected['nativeConsole']['designatedRequirement'] = restored['nativeConsole']['designatedRequirement']
        if expected != restored:
            raise ValueError('rollback would change configuration outside console pin')
        saved_req = requirement(backup / app.name)
        if json.loads(saved_config)['nativeConsole']['designatedRequirement'] != saved_req:
            raise ValueError('rollback pin mismatch')
        stop_consoles(app); stop(args.broker_pid, root / 'mechanize')
        shutil.rmtree(app); shutil.copytree(backup / app.name, app)
        atomic(config_path, saved_config)
        pid = start(root, args.listen)
        run('open', str(app)); print(json.dumps({'rolledBack': True, 'brokerPID': pid})); return
    if not args.source:
        raise ValueError('--source required for preflight/apply')
    source = safe(args.source)
    stage = Path(tempfile.mkdtemp(prefix='mechanize-console-', dir='/private/tmp'))
    console = stage / 'console'
    shutil.copytree(source / 'native/console', console, ignore=shutil.ignore_patterns('.build', 'dist', '.DS_Store'))
    plist = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    for name, key in [('mechanize', 'MechanizeBrokerRequirement'), ('mechanize-native', 'MechanizeHelperRequirement')]:
        run('codesign', '--verify', '--strict', '--test-requirement', '=' + plist[key], str(root / name))
    env = os.environ.copy(); env['MECHANIZE_BROKER_REQUIREMENT'] = plist['MechanizeBrokerRequirement']
    run('swift', 'test', '--package-path', str(console), timeout=180)
    run('sh', str(console / 'build-app.sh'), env=env, timeout=180)
    staged = console / 'dist' / app.name
    account = 'com.viant.mechanize.consent:' + str(os.getuid()) + ':' + uuid.uuid4().hex
    plist['MechanizeEnrollmentAccount'] = account
    (staged / 'Contents/Info.plist').write_bytes(plistlib.dumps(plist))
    run('codesign', '--force', '--sign', '-', '--identifier', 'com.viant.mechanize.consent', str(staged))
    req = requirement(staged)
    if not args.apply:
        print(json.dumps({'preflightPassed': True, 'stage': str(stage), 'consoleRequirement': req, 'installedFilesChanged': False})); return
    if private(config_path) != config_bytes or requirement(app) != old_req:
        raise ValueError('installation changed during build')
    backup = root / ('console-backup-' + str(int(time.time())) + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(mode=0o700); shutil.copytree(app, backup / app.name)
    atomic(backup / 'config.json', config_bytes)
    print(json.dumps({'backup': str(backup), 'stage': str(stage)}), flush=True)
    stop_consoles(app)
    shutil.rmtree(app); shutil.copytree(staged, app)
    try:
        enroll(app, req, config, args.interactive_enrollment)
    except Exception:
        shutil.rmtree(app); shutil.copytree(backup / app.name, app)
        run('open', str(app))
        raise RuntimeError('enrollment failed; original console restored; broker/config unchanged') from None
    # Identity checked again immediately before signaling; no PID-only termination.
    try:
        stop(args.broker_pid, root / 'mechanize')
    except Exception:
        shutil.rmtree(app); shutil.copytree(backup / app.name, app)
        run('open', str(app))
        raise RuntimeError('broker shutdown unconfirmed; original console/config preserved') from None
    config['nativeConsole']['designatedRequirement'] = req
    atomic(config_path, json.dumps(config, indent=2).encode() + b'\n')
    pid = start(root, args.listen)
    print(json.dumps({'brokerPID': pid, 'backup': str(backup), 'verificationPending': True}), flush=True)
    report = json.loads(run(str(app / 'Contents/MacOS/MechanizeConsent'), '--check-connection', timeout=40).stdout)
    if report.get('stage') != 'complete' or not all(report.get(x) for x in ('brokerVerified', 'credentialAvailable', 'authenticated')):
        raise RuntimeError('connection verification failed; use explicit rollback with reported backup')
    if hashes != {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in hashes}:
        raise RuntimeError('broker/helper changed unexpectedly')
    atomic(backup / 'upgrade-report.json', json.dumps({'backup': str(backup), 'brokerPID': pid, 'consoleRequirement': req, 'consoleEnrollmentAccount': account, 'connection': report, 'brokerHelperUnchanged': True}).encode())
    run('open', str(app))
    print(json.dumps({'upgraded': True, 'backup': str(backup), 'brokerPID': pid, 'connection': report}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('console upgrade failed: ' + str(error) if isinstance(error, (ValueError, RuntimeError)) else 'console upgrade failed: ' + type(error).__name__)
