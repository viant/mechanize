#!/usr/bin/env python3
"""Update only a frozen native helper, preserving broker/console/key identities.

Requires an operator-verified idle broker for --apply. A failed restart leaves
the backup and verification pending; it never forces termination or rolls back
an uncertain live operation. No credentials are provisioned or read.
"""
import argparse
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import time
import uuid


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = load_module('helper_console_upgrade', 'upgrade-console.py')


def installed_helper(root, config):
    """Use the exact enrolled helper, including a private staged installation."""
    raw = config.get('nativeHelper') if isinstance(config, dict) else None
    if not isinstance(raw, str) or not Path(raw).is_absolute():
        raise ValueError('absolute enrolled helper required')
    helper = shared.safe(raw)
    if helper.name != 'mechanize-native' or helper.resolve(strict=True) != helper or not helper.is_file():
        raise ValueError('canonical enrolled helper required')
    try:
        helper.relative_to(root)
    except ValueError:
        raise ValueError('enrolled helper must remain inside installation') from None
    return helper


def helper_config(config, requirement):
    if not isinstance(requirement, str) or not re.fullmatch(r'identifier "com\.viant\.mechanize\.native" and cdhash H"[a-f0-9]{40}"', requirement):
        raise ValueError('exact native helper requirement required')
    if not isinstance(config, dict) or not isinstance(config.get('nativeLaunch'), dict) or not config.get('nativeHelper'):
        raise ValueError('existing native helper enrollment required')
    result = copy.deepcopy(config)
    result['nativeLaunch']['helperRequirement'] = requirement
    return result


def helper_pin(helper):
    shared.run('codesign', '--force', '--sign', '-', '--identifier', 'com.viant.mechanize.native', str(helper))
    output = shared.run('codesign', '--display', '--verbose=4', str(helper)).stderr.decode()
    match = re.search(r'^CDHash=([a-f0-9]{40})$', output, re.M)
    if not match:
        raise ValueError('signed helper hash unavailable')
    requirement = 'identifier "com.viant.mechanize.native" and cdhash H"' + match[1] + '"'
    shared.run('codesign', '--verify', '--strict', '--test-requirement', '=' + requirement, str(helper))
    return requirement


def verify_source(source, expected):
    inventory = json.loads(shared.private(source / '.mechanize-source-inventory.json'))
    if not isinstance(inventory, list) or not 0 < len(inventory) <= 10000:
        raise ValueError('bounded frozen source inventory required')
    names = []
    digest = hashlib.sha256()
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256'}:
            raise ValueError('closed frozen source inventory required')
        name, checksum = entry['path'], entry['sha256']
        if not isinstance(name, str) or Path(name).is_absolute() or '\\' in name or not name or any(
                part in ('', '.', '..', '.build', '.git') for part in name.split('/')) or name == '.mechanize-source-inventory.json':
            raise ValueError('canonical frozen source path required')
        path = shared.safe(source / name)
        if not isinstance(checksum, str) or not re.fullmatch('[a-f0-9]{64}', checksum) or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            raise ValueError('frozen source checksum mismatch')
        names.append(name)
        digest.update(name.encode() + b'\0' + bytes.fromhex(checksum))
    if names != sorted(set(names)) or digest.hexdigest() != expected:
        raise ValueError('frozen source digest mismatch')
    paths = [path for path in source.rglob('*') if '.build' not in path.relative_to(source).parts]
    if any(path.is_symlink() for path in paths):
        raise ValueError('frozen source symlink rejected')
    actual = sorted(path.relative_to(source).as_posix() for path in paths
                    if path.is_file() and '.build' not in path.relative_to(source).parts
                    and path.relative_to(source).as_posix() != '.mechanize-source-inventory.json')
    if actual != names:
        raise ValueError('unbound frozen source files present')


def verify_candidate(candidate, expected):
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
        raise ValueError('built helper checksum mismatch')


def validate_launchd_job(job, root, label):
    arguments = [str(root / 'mechanize'), 'serve', '-config', str(root / 'config.json'), '-listen', '127.0.0.1:4987']
    if not re.fullmatch(r'com\.viant\.mechanize\.[A-Za-z0-9._-]{1,128}', label) or job.get('Label') != label or job.get('ProgramArguments') != arguments:
        raise ValueError('exact owned launchd job required')
    triggers = {'StartInterval', 'StartCalendarInterval', 'WatchPaths', 'QueueDirectories', 'Sockets', 'MachServices', 'LaunchEvents'}
    if job.get('KeepAlive') is not False or set(job) & triggers:
        raise ValueError('automatic launchd restart must be disabled')


def launchd_pid(root, label):
    output = shared.run('launchctl', 'print', 'gui/' + str(os.getuid()) + '/' + label).stdout.decode()
    if '\tprogram = ' + str(root / 'mechanize') + '\n' not in output or '\tpath = ' + str(root / 'runtime/broker.plist') + '\n' not in output:
        raise ValueError('loaded launchd job identity mismatch')
    if re.search(r'^\s*properties = .*keepalive', output, re.M | re.I):
        raise ValueError('loaded launchd job may restart automatically')
    match = re.search(r'^\s*pid = (\d+)$', output, re.M)
    return int(match[1]) if match else None


def start_launchd(root, label):
    shared.run('launchctl', 'kickstart', 'gui/' + str(os.getuid()) + '/' + label)
    for _ in range(100):
        pid = launchd_pid(root, label)
        if pid:
            try:
                shared.process_identity(pid, root / 'mechanize')
                return pid
            except ValueError:
                pass
        time.sleep(.1)
    raise RuntimeError('managed broker start unconfirmed; verification pending')


def verify_stopped_job(root, label, job_before):
    if launchd_pid(root, label) is not None or shared.private(root / 'runtime/broker.plist') != job_before:
        raise RuntimeError('launchd restarted or changed; no artifact replacement attempted')


def wait_helper_exit(helper):
    for _ in range(150):
        rows = shared.run('ps', '-axo', 'uid=,comm=').stdout.decode().splitlines()
        if not any(row.strip().split(None, 1) == [str(os.getuid()), str(helper)] for row in rows):
            return
        time.sleep(.1)
    raise RuntimeError('helper shutdown unconfirmed; no forced termination attempted')


def main():
    with contextlib.ExitStack() as cleanup:
        return perform(cleanup)


def perform(cleanup):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-report', required=True)
    parser.add_argument('--installation', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--broker-pid', type=int)
    parser.add_argument('--idle-verified', action='store_true')
    parser.add_argument('--launchd-label', help='existing idle development job with automatic restart disabled')
    args = parser.parse_args()
    os.umask(0o077)
    root = shared.safe(args.installation)
    if args.apply:
        cleanup.enter_context(shared.runtime_lock(root))
    before = shared.private(root / 'config.json')
    config = json.loads(before)
    report = json.loads(shared.private(Path(args.source_report)))
    if set(report) != {'sourceRoot', 'sourceDigest', 'brokerSHA256', 'helperSHA256'} or not all(
            isinstance(report.get(key), str) and re.fullmatch('[a-f0-9]{64}', report[key])
            for key in ['sourceDigest', 'brokerSHA256', 'helperSHA256']):
        raise ValueError('bounded frozen helper source report required')
    source = shared.safe(report['sourceRoot'])
    verify_source(source, report['sourceDigest'])
    broker, helper = root / 'mechanize', installed_helper(root, config)
    console = root / 'Mechanize Permissions.app/Contents/MacOS/MechanizeConsent'
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    if digest(broker) != report['brokerSHA256']:
        raise ValueError('broker changed since helper source freeze')
    console_digest = digest(console)
    runtime_upgrade = load_module('helper_runtime_upgrade', 'upgrade-runtime.py')
    runtime_upgrade.owned_directory(root)
    for artifact in [broker, helper, console]:
        runtime_upgrade.regular_tree(artifact)
    reverse_pin = runtime_upgrade.helper_metadata(helper).get('MechanizeBrokerRequirement')
    if not reverse_pin:
        raise ValueError('installed helper reverse pin unavailable')
    shared.run('codesign', '--verify', '--strict', '--test-requirement', '=' + reverse_pin, str(broker))
    binary_root = shared.run('swift', 'build', '--package-path', 'native/macos', '-c', 'release', '--show-bin-path', cwd=source).stdout.decode().strip()
    candidate = shared.safe(Path(binary_root) / 'mechanize-native')
    runtime_upgrade.regular_tree(candidate)
    verify_candidate(candidate, report['helperSHA256'])
    if runtime_upgrade.helper_metadata(candidate).get('MechanizeBrokerRequirement') != reverse_pin:
        raise ValueError('candidate helper must retain the installed broker reverse pin')
    stage = root / ('.helper-stage-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    staged = stage / 'mechanize-native'
    shutil.copyfile(candidate, staged)
    staged.chmod(0o700)
    verify_candidate(staged, report['helperSHA256'])
    requirement = helper_pin(staged)
    updated = helper_config(config, requirement)
    if not args.apply:
        print(json.dumps({'preflightPassed': True, 'stage': str(stage), 'installedFilesChanged': False}))
        return
    if not args.broker_pid or not args.idle_verified or not args.launchd_label:
        raise ValueError('exact idle broker confirmation required')
    job_before = shared.private(root / 'runtime/broker.plist')
    validate_launchd_job(plistlib.loads(job_before), root, args.launchd_label)
    if launchd_pid(root, args.launchd_label) != args.broker_pid:
        raise ValueError('launchd broker generation changed')
    shared.process_identity(args.broker_pid, broker)
    backup = root / ('helper-backup-' + str(int(time.time())) + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(mode=0o700)
    (backup / 'config.json').write_bytes(before)
    (backup / 'patch-source.json').write_text(json.dumps(report))
    shared.stop(args.broker_pid, broker)
    wait_helper_exit(helper)
    verify_stopped_job(root, args.launchd_label, job_before)
    if shared.private(root / 'config.json') != before or digest(broker) != report['brokerSHA256'] or digest(console) != console_digest:
        raise RuntimeError('installation changed during shutdown; no artifact replacement attempted')
    os.rename(helper, backup / 'mechanize-native')
    os.rename(staged, helper)
    shared.atomic(root / 'config.json', (json.dumps(updated, indent=2) + '\n').encode())
    record = {'backup': str(backup), 'helperPath': str(helper), 'helperRequirement': requirement, 'helperSHA256': digest(helper),
              'brokerSHA256': digest(broker), 'consoleSHA256': digest(console), 'sourceRoot': str(source),
              'sourceDigest': report['sourceDigest'], 'verificationPending': True}
    (backup / 'upgrade-report.json').write_text(json.dumps(record, indent=2))
    pid = start_launchd(root, args.launchd_label)
    shared.process_identity(pid, broker)
    if digest(broker) != report['brokerSHA256'] or digest(console) != console_digest:
        raise RuntimeError('broker or console changed; verification pending')
    print(json.dumps({'helperUpdated': True, 'brokerConsoleUnchanged': True, 'brokerPID': pid,
                      'backup': str(backup), 'verificationPending': True}))


if __name__ == '__main__':
    main()
