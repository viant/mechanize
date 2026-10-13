#!/usr/bin/env python3
"""Refresh only an existing Chrome image pin after an independently signed update.

Dry-run by default. Apply requires the owned broker/native host to be stopped;
Chrome remains running. Never reads credential resources, Vault or browser data,
changes grants, starts/stops processes, or rebuilds binaries.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
review = module('chrome_update_review', 'prepare-runtime-upgrade-review.py')
package = review.package
enrollment = module('chrome_update_enrollment', 'enroll-chrome.py')
locks = module('chrome_update_lock', 'upgrade-console.py')


def verify(path, requirement, work):
    result = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures',
                             '--test-requirement', '=' + requirement, str(path)],
                            cwd=work, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError('Signed executable proof failed')


def no_runtime(executables):
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,comm='], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=5)
    if result.returncode or len(result.stdout) > 2_000_000:
        raise ValueError('Bounded runtime process inventory unavailable')
    for line in result.stdout.decode('utf-8', 'strict').splitlines():
        row = line.strip().split(None, 1)
        if len(row) == 2 and row[1] in executables:
            raise ValueError('Broker/native host must be stopped before pin replacement')


def prepare(config_path, host_path, chrome, work, inspect=review.inspect_process,
            verifier=verify, pin=review.pin_from_signature):
    config_path, host_path = package.physical(config_path), package.physical(host_path)
    if config_path == host_path:
        raise ValueError('Distinct existing configurations required')
    originals = [package.read_file(config_path, 1_048_576, private=True),
                 package.read_file(host_path, 16384, private=True)]
    config, host = [package.decode(raw) for raw in originals]
    c = config.get('chrome'); trust = c.get('processTrust') if isinstance(c, dict) else None
    if not isinstance(trust, dict) or c.get('fixtureEnrollment', False) is not False or host.get('fixtureEnrollment', False) is not False:
        raise ValueError('Existing production enrollment required')
    if host.get('processTrust') != trust or trust.get('expectedUID') != os.getuid() or host.get('socketPath') != c.get('socketPath'):
        raise ValueError('Existing native/broker trust mismatch')
    grants = [g for g in c.get('grants', []) if all(g.get(k) == host.get(k) for k in ('profileChannel', 'browserInstance', 'extensionOrigin', 'credentialResource'))]
    if len(grants) != 1:
        raise ValueError('One unchanged matching enrollment required')
    broker_pin = host.get('brokerRequirement')
    if broker_pin != config.get('nativeVault', {}).get('brokerRequirement'):
        raise ValueError('Existing reverse broker pin mismatch')
    package.requirement(broker_pin, 'broker')
    package.requirement(trust.get('nativeHostRequirement'), 'chrome.nativehost')
    native_host = package.physical(trust['nativeHostExecutable'])
    broker = native_host.parent / 'mechanize'
    verifier(broker, broker_pin, work)
    verifier(native_host, trust['nativeHostRequirement'], work)
    verifier(trust['chromeExecutable'], review.GOOGLE_SIGNER, work)
    fresh = pin(trust['chromeExecutable'], 'google-chrome', work)
    package.chrome_requirement(fresh)
    observed = review.check_process(chrome, trust['chromeExecutable'], fresh, work, inspect, verifier, chrome=True, google=True)
    updated = [copy.deepcopy(config), copy.deepcopy(host)]
    updated[0]['chrome']['processTrust']['chromeRequirement'] = fresh
    updated[1]['processTrust']['chromeRequirement'] = fresh
    candidates = [enrollment.encoded(value) for value in updated]
    if fresh == trust['chromeRequirement']:
        candidates = originals[:]
    return {'paths': [config_path, host_path], 'originals': originals, 'candidates': candidates,
            'chrome': chrome, 'observed': observed, 'executable': trust['chromeExecutable'],
            'requirement': fresh, 'runtime': {str(broker), str(native_host)}}


def apply(plan, backup, work, inspect=review.inspect_process, verifier=verify,
          stopped=no_runtime, atomic=enrollment.atomic):
    backup = package.external(backup)
    if backup.exists():
        raise ValueError('Fresh private backup directory required')
    def check(expected):
        stopped(plan['runtime'])
        for path, raw in zip(plan['paths'], expected):
            if package.read_file(path, 1_048_576, private=True) != raw:
                raise ValueError('Configuration changed after review')
        current = review.check_process(plan['chrome'], plan['executable'], plan['requirement'], work,
                                       inspect, verifier, chrome=True, google=True)
        if current != plan['observed']:
            raise ValueError('Chrome changed after review')
    check(plan['originals'])
    backup.mkdir(mode=0o700)
    for name, raw in zip(('broker.original.json', 'native-host.original.json'), plan['originals']):
        atomic(backup / name, raw, None)
    expected = plan['originals'][:]
    try:
        for i, path in enumerate(plan['paths']):
            check(expected)
            if expected[i] != plan['candidates'][i]:
                atomic(path, plan['candidates'][i], expected[i])
                expected[i] = plan['candidates'][i]
        check(plan['candidates'])
    except Exception:
        # No blind rollback over another writer or a newly started runtime.
        # A partially written pair remains fail-closed; private originals remain.
        raise ValueError('Pin repair incomplete; private backups retained') from None
    return plan['originals'] != plan['candidates']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--native-host-config', default=str(Path.home() / 'Library/Application Support/Mechanize/native-host.json'))
    parser.add_argument('--chrome-pid', type=int, required=True)
    parser.add_argument('--chrome-start', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS required')
    if args.apply != bool(args.backup_dir):
        raise ValueError('Apply requires an explicit fresh backup directory')
    if shutil.which('codesign') != '/usr/bin/codesign' or shutil.which('lipo') != '/usr/bin/lipo':
        raise ValueError('Fixed Apple signing tools required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='mechanize-chrome-pin-review-') as folder:
        work = Path(folder).resolve()
        chrome = {'pid': args.chrome_pid, 'start': args.chrome_start}
        if args.apply:
            with locks.runtime_lock(Path(args.config).parent):
                plan = prepare(args.config, args.native_host_config, chrome, work)
                changed = apply(plan, args.backup_dir, work)
        else:
            plan = prepare(args.config, args.native_host_config, chrome, work)
            changed = plan['originals'] != plan['candidates']
        print(json.dumps({'verifiedGoogleChrome': True, 'currentProcessVerified': True,
                          'pinChangeRequired': changed, 'applied': bool(args.apply and changed),
                          'grantsChanged': False, 'credentialsChanged': False,
                          'binariesChanged': False, 'processesRestarted': False}))

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Chrome pin recovery refused; private details withheld', file=sys.stderr)
        sys.exit(1)
