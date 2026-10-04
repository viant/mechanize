#!/usr/bin/env python3
"""Preserve an installed development runtime while replacing its signed build.

Preflight: --source FROZEN_ROOT --manifest MANIFEST --installation INSTALL_ROOT
Apply adds: --apply --broker-pid PID --idle-verified
Rollback: --rollback BACKUP --installation INSTALL_ROOT --broker-pid PID --idle-verified
No build, database provisioning, grant changes, socket deletion, or default UI prompts.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import stat
import struct
import sys
import tempfile
import time
import uuid

SCRIPTS = Path(__file__).absolute().parent
extension_spec = importlib.util.spec_from_file_location('extension_package', SCRIPTS / 'extension_package.py')
extension_package = importlib.util.module_from_spec(extension_spec)
extension_spec.loader.exec_module(extension_package)
spec = importlib.util.spec_from_file_location('console_upgrade', SCRIPTS / 'upgrade-console.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
safe, private, run, atomic = shared.safe, shared.private, shared.run, shared.atomic
ARTIFACTS = {'broker': ('mechanize', 'broker'), 'helper': ('mechanize-native', 'native'),
             'console': ('Mechanize Permissions.app', 'consent'),
             'nativeHost': ('mechanize-native-host', 'chrome.nativehost')}


def owned_directory(path):
    p = safe(path)
    info = p.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private owned directory required')
    return p


def regular_tree(path):
    safe(path)
    for entry in ([path, *path.rglob('*')] if path.is_dir() else [path]):
        safe(entry)
        info = entry.stat()
        if info.st_uid != os.getuid() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('owned regular artifact tree required')


def verify(path, requirement, identifier, digest=None):
    regular_tree(path)
    pattern = r'identifier "com\.viant\.mechanize\.' + re.escape(identifier) + r'" and cdhash H"[a-f0-9]{40}"'
    if not isinstance(requirement, str) or not re.fullmatch(pattern, requirement):
        raise ValueError('exact manifest code requirement required')
    if digest is not None:
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('manifest SHA256 mismatch')
    run('codesign', '--verify', '--strict', '--test-requirement', '=' + requirement, str(path))


def helper_metadata(path):
    # Signed __TEXT,__info_plist is authoritative; never infer the reverse pin
    # from a loose companion plist in the staging directory.
    data = path.read_bytes()
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('thin little-endian Mach-O helper required')
    count = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > len(data):
            raise ValueError('invalid Mach-O load command')
        if command == 0x19:
            sections = struct.unpack_from('<I', data, offset + 64)[0]
            for index in range(sections):
                start = offset + 72 + index * 80
                if start + 80 > offset + size:
                    raise ValueError('invalid Mach-O section')
                section, segment = struct.unpack_from('<16s16s', data, start)
                if section.rstrip(b'\0') == b'__info_plist' and segment.rstrip(b'\0') == b'__TEXT':
                    length = struct.unpack_from('<Q', data, start + 40)[0]
                    position = struct.unpack_from('<I', data, start + 48)[0]
                    return plistlib.loads(data[position:position + length].rstrip(b'\0'))
        offset += size
    raise ValueError('signed helper reverse pin absent')


def verify_manifest(source, manifest, artifacts):
    if manifest.get('schemaVersion') != 1 or manifest.get('mode') != 'development' or manifest.get('productionQualified') is not False or manifest.get('sourceRoot') != str(source):
        raise ValueError('incompatible frozen development manifest')
    if manifest.get('extension') != str(source / 'dist/development/extension/chrome'):
        raise ValueError('fixed packaged Chrome extension path required')
    extension_package.verify(artifacts / 'extension/chrome', manifest.get('extensionFiles'), manifest.get('extensionSHA256'))
    for name, (filename, identifier) in ARTIFACTS.items():
        if manifest.get(name) != str(source / 'dist/development' / filename):
            raise ValueError('unexpected manifest artifact path')
        digest = manifest.get(name + 'SHA256') if name != 'console' else None
        if name != 'console' and digest is None:
            raise ValueError('manifest binary digest required')
        verify(artifacts / filename, manifest[name + 'Requirement'], identifier, digest)
    broker = manifest['brokerRequirement']
    plist = plistlib.loads((artifacts / ARTIFACTS['console'][0] / 'Contents/Info.plist').read_bytes())
    if plist.get('MechanizeBrokerRequirement') != broker or plist.get('MechanizeHelperRequirement') != manifest['helperRequirement']:
        raise ValueError('console reverse pins disagree')
    account = manifest.get('consoleEnrollmentAccount', '')
    if not re.fullmatch('com.viant.mechanize.consent:' + str(os.getuid()) + ':[0-9a-f]{32}', account) or plist.get('MechanizeEnrollmentAccount') != account:
        raise ValueError('signed per-build console enrollment account required')
    if helper_metadata(artifacts / 'mechanize-native').get('MechanizeBrokerRequirement') != broker:
        raise ValueError('helper reverse pin disagrees')
    host = (artifacts / 'mechanize-native-host').read_bytes()
    embedded = set(re.findall(rb'identifier "com\.viant\.mechanize\.broker" and cdhash H"[a-f0-9]{40}"', host))
    if embedded != {broker.encode()} or manifest.get('nativeHostBrokerRequirement') != broker:
        raise ValueError('native host signed reverse pin disagrees')
    return plist


def updated_config(config, root, source, manifest):
    result = copy.deepcopy(config)
    result['sourceRoot'] = str(source)
    result['nativeHelper'] = str(root / 'mechanize-native')
    if result.get('nativeLaunch') is not None:
        result['nativeLaunch']['helperRequirement'] = manifest['helperRequirement']
    if not result.get('nativeConsole'):
        raise ValueError('existing console enrollment required')
    result['nativeConsole']['designatedRequirement'] = manifest['consoleRequirement']
    chrome = result.get('chrome')
    if chrome and chrome.get('processTrust'):
        trust = chrome['processTrust']
        if trust.get('nativeHostExecutable') != str(root / 'mechanize-native-host'):
            raise ValueError('external enrolled Chrome host requires separate operator upgrade')
        trust['nativeHostRequirement'] = manifest['nativeHostRequirement']
    return result


def encode(value):
    return json.dumps(value, indent=2).encode() + b'\n'


def chrome_native_host_path():
    return safe(Path.home() / 'Library/Application Support/Mechanize/native-host.json')


def validate_chrome_native_host(config, external, root, broker_requirement):
    chrome = config.get('chrome')
    fields = {'socketPath', 'fixtureEnrollment', 'processTrust', 'profileChannel', 'browserInstance',
              'extensionOrigin', 'credentialResource', 'brokerRequirement', 'profileDirectory'}
    if isinstance(external, dict) and 'trustScope' in external:
        fields.add('trustScope')
    if (not isinstance(chrome, dict) or chrome.get('fixtureEnrollment') is not False or
            not isinstance(external, dict) or set(external) != fields or external.get('fixtureEnrollment') is not False):
        raise ValueError('exact enrolled Chrome native-host configuration required')
    trust = chrome.get('processTrust')
    grants = chrome.get('grants')
    if (not isinstance(trust, dict) or trust.get('nativeHostExecutable') != str(root / 'mechanize-native-host') or
            external['processTrust'] != trust or external['brokerRequirement'] != broker_requirement or
            not isinstance(grants, list) or len(grants) != 1 or not isinstance(grants[0], dict)):
        raise ValueError('enrolled Chrome native-host trust disagrees with installed broker')
    grant = grants[0]
    if (not isinstance(chrome.get('socketPath'), str) or not chrome['socketPath'] or
            external['socketPath'] != chrome['socketPath'] or
            any(not isinstance(grant.get(field), str) or not grant[field] or external[field] != grant[field]
                for field in ('profileChannel', 'browserInstance', 'extensionOrigin'))):
        raise ValueError('enrolled Chrome native-host profile or transport disagrees')
    scope, external_scope = grant.get('trustScope', ''), external.get('trustScope', '')
    if scope not in ('', 'profile', 'desktop') or external_scope not in ('', 'profile', 'desktop'):
        raise ValueError('closed Chrome trust scope required')
    scope, external_scope = scope or 'profile', external_scope or 'profile'
    if external_scope != scope:
        raise ValueError('enrolled Chrome trust scope disagrees')
    directory = grant.get('profileDirectory', '')
    if external['profileDirectory'] != directory or (scope == 'profile' and (not isinstance(directory, str) or not directory)) or (scope == 'desktop' and directory != ''):
        raise ValueError('enrolled Chrome profile evidence scope disagrees')
    if scope == 'desktop':
        require_desktop_browser_user(config, grant)
    resource = grant.get('credentialResource')
    if (not isinstance(resource, dict) or not isinstance(resource.get('URL'), str) or not Path(resource['URL']).is_absolute() or
            not isinstance(resource.get('Key', ''), str) or
            resource.get('Data') or resource.get('Fallback') or external['credentialResource'] != resource):
        raise ValueError('enrolled Chrome native-host credential references disagree')


def require_desktop_browser_user(config, grant):
    principal = grant.get('principal', {})
    subject = principal.get('subject')
    users = [user for user in config.get('users', []) if user.get('subject') == subject and
             user.get('tenant', '') == principal.get('tenant', '')]
    if (not isinstance(subject, str) or not subject or len(users) != 1 or
            users[0].get('desktopAccess') is not True or
            principal.get('issuer') != config.get('identityPolicy', {}).get('issuer')):
        raise ValueError('desktop browser scope requires the existing explicit desktop-wide user')


def enable_desktop_browser_scope(updated, snapshot):
    # An explicit operator switch, never a fallback after profile proof failure.
    if snapshot is None or updated.get('chrome', {}).get('fixtureEnrollment') is not False:
        raise ValueError('existing production Chrome enrollment required for desktop scope')
    grants = updated['chrome'].get('grants', [])
    if len(grants) != 1:
        raise ValueError('one exact Chrome enrollment required for desktop scope')
    require_desktop_browser_user(updated, grants[0])
    external = json.loads(snapshot['after'])
    grants[0]['trustScope'] = 'desktop'
    grants[0]['profileDirectory'] = ''
    external['trustScope'] = 'desktop'
    external['profileDirectory'] = ''
    snapshot['after'] = encode(external)


def preflight_chrome_native_host(config, root, broker_requirement, manifest):
    # An unrelated external file is never consulted when Chrome is not enrolled.
    if config.get('chrome') is None:
        return None
    path = chrome_native_host_path()
    before = private(path)
    external = json.loads(before)
    validate_chrome_native_host(config, external, root, broker_requirement)
    verify(root / 'mechanize', broker_requirement, 'broker')
    verify(root / 'mechanize-native-host', external['processTrust']['nativeHostRequirement'], 'chrome.nativehost')
    updated = copy.deepcopy(external)
    updated['brokerRequirement'] = manifest['brokerRequirement']
    updated['processTrust']['nativeHostRequirement'] = manifest['nativeHostRequirement']
    return {'path': path, 'before': before, 'after': encode(updated)}


def check_chrome_snapshot(snapshot):
    if snapshot is not None and private(snapshot['path']) != snapshot['before']:
        raise ValueError('enrolled Chrome native-host configuration changed; review retained backup')


def backup_chrome_snapshot(snapshot, backup):
    if snapshot is None:
        return None
    check_chrome_snapshot(snapshot)
    atomic(backup / 'chrome-native-host.json', snapshot['before'])
    return {'path': str(snapshot['path']), 'originalSHA256': hashlib.sha256(snapshot['before']).hexdigest(),
            'updatedSHA256': hashlib.sha256(snapshot['after']).hexdigest()}


def rollback_chrome_snapshot(config, saved_config, record, backup, root):
    entry = record.get('chromeNativeHost')
    if entry is None:
        if config.get('chrome') is not None or saved_config.get('chrome') is not None:
            raise ValueError('Chrome rollback requires its original external native-host snapshot')
        return None
    if saved_config.get('chrome') is None or not isinstance(entry, dict) or set(entry) != {'path', 'originalSHA256', 'updatedSHA256'}:
        raise ValueError('unexpected Chrome rollback snapshot')
    path = chrome_native_host_path()
    if entry['path'] != str(path) or any(not isinstance(entry[field], str) or not re.fullmatch(r'[a-f0-9]{64}', entry[field])
                                         for field in ('originalSHA256', 'updatedSHA256')):
        raise ValueError('exact Chrome rollback snapshot identity required')
    saved = private(backup / 'chrome-native-host.json')
    if hashlib.sha256(saved).hexdigest() != entry['originalSHA256']:
        raise ValueError('Chrome rollback snapshot digest mismatch')
    broker = record.get('artifacts', {}).get('broker', {}).get('requirement')
    native_host = record.get('artifacts', {}).get('nativeHost', {}).get('requirement')
    external = json.loads(saved)
    validate_chrome_native_host(saved_config, external, root, broker)
    if not broker or not native_host or external['processTrust'].get('nativeHostRequirement') != native_host:
        raise ValueError('Chrome rollback snapshot artifact pins disagree')
    current = private(path)
    if hashlib.sha256(current).hexdigest() not in (entry['originalSHA256'], entry['updatedSHA256']):
        raise ValueError('Chrome native-host configuration changed since upgrade; review backup manually')
    return {'path': path, 'before': current, 'after': saved}


def require_helpers_stopped(root):
    for line in run('ps', '-ww', '-axo', 'pid=,uid=,comm=').stdout.decode().splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[1] == str(os.getuid()) and fields[2] in (str(root / 'mechanize-native'), str(root / 'mechanize-native-host')):
            raise RuntimeError('helper or Chrome native host still running after graceful broker shutdown; no binaries replaced; review retained backup')


def require_chrome_stopped(config, root):
    chrome = config.get('chrome')
    if chrome is None:
        return
    executable = chrome.get('processTrust', {}).get('chromeExecutable')
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise ValueError('enrolled Chrome executable is required for extension replacement')
    for line in run('ps', '-ww', '-axo', 'pid=,uid=,comm=').stdout.decode().splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[1] == str(os.getuid()) and fields[2] in (executable, str(root / 'mechanize-native-host')):
            raise ValueError('enrolled Chrome and native host must be stopped before extension replacement')


def preflight_extension(root, manifest, artifacts):
    expected = {'files': manifest.get('extensionFiles'), 'sha256': manifest.get('extensionSHA256')}
    extension_package.verify(artifacts / 'extension/chrome', expected['files'], expected['sha256'])
    target = safe(root / 'extension/chrome')
    original = extension_package.inventory(target, allow_legacy=True) if target.exists() else None
    if original is not None and extension_package.identity(target) != extension_package.identity(artifacts / 'extension/chrome'):
        raise ValueError('Chrome extension identity key cannot change during upgrade')
    return {'path': target, 'original': original, 'updated': expected}


def check_extension_snapshot(snapshot):
    target = snapshot['path']
    current = extension_package.inventory(target, allow_legacy=True) if target.exists() else None
    if current != snapshot['original']:
        raise ValueError('installed Chrome extension changed after preflight; review backup')


def backup_extension_snapshot(snapshot, backup):
    check_extension_snapshot(snapshot)
    if snapshot['original'] is not None:
        (backup / 'extension').mkdir(mode=0o700)
        extension_package.copy(snapshot['path'], backup / 'extension/chrome', snapshot['original'], allow_legacy=True)
    return {'path': str(snapshot['path']), 'original': snapshot['original'], 'updated': snapshot['updated']}


def rollback_extension_snapshot(config, saved_config, record, backup, root):
    target = safe(root / 'extension/chrome')
    entry = record.get('chromeExtension')
    if entry is None:
        if config.get('chrome') is not None or saved_config.get('chrome') is not None or target.exists() or (backup / 'extension').exists():
            raise ValueError('legacy rollback lacks an exact Chrome extension snapshot')
        return None
    if not isinstance(entry, dict) or set(entry) != {'path', 'original', 'updated'} or entry['path'] != str(target):
        raise ValueError('exact Chrome extension rollback identity required')
    for expected in (entry['original'], entry['updated']):
        if expected is not None and (not isinstance(expected, dict) or set(expected) != {'files', 'sha256'} or
                                     extension_package.inventory_hash(expected['files'], allow_legacy=True) != expected['sha256']):
            raise ValueError('valid Chrome extension rollback inventory required')
    if entry['updated'] is None:
        raise ValueError('updated Chrome extension inventory required')
    if entry['original'] is not None:
        extension_package.verify(backup / 'extension/chrome', entry['original']['files'], entry['original']['sha256'], allow_legacy=True)
    elif (backup / 'extension').exists():
        raise ValueError('unexpected Chrome extension backup')
    current = extension_package.inventory(target, allow_legacy=True) if target.exists() else None
    if current is not None and current not in (entry['original'], entry['updated']):
        raise ValueError('Chrome extension changed since upgrade; review backup manually')
    return {'path': target, 'original': current, 'updated': entry['original']}


def restore_extension(snapshot, backup):
    if snapshot is None:
        return
    check_extension_snapshot(snapshot)
    if snapshot['updated'] is None:
        if snapshot['path'].exists():
            shutil.rmtree(snapshot['path'])
    else:
        extension_package.replace(backup / 'extension/chrome', snapshot['path'], snapshot['updated'], allow_legacy=True)


def replace_artifacts(source, root):
    for filename, _ in ARTIFACTS.values():
        original = source / filename
        target = root / filename
        if not original.exists():
            # A legacy installation may not contain a native host yet.
            if target.exists():
                target.unlink()
            continue
        if original.is_dir():
            temporary = root / ('.runtime-app-' + uuid.uuid4().hex)
            shutil.copytree(original, temporary)
            if target.exists():
                shutil.rmtree(target)
            os.replace(temporary, target)
        else:
            atomic(target, original.read_bytes())
            target.chmod(0o700)


def report_health(root, listen, endly_runner):
    result = {'connectionVerified': False, 'mcpVerified': False, 'verificationPending': True}
    # Process creation precedes HTTP readiness while the host loads its services.
    # This waits only for a listener; authenticated checks below establish health.
    host, port = listen.rsplit(':', 1)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    try:
        report = json.loads(run(str(root / 'Mechanize Permissions.app/Contents/MacOS/MechanizeConsent'), '--check-connection', timeout=40).stdout)
        result['connectionVerified'] = report.get('stage') == 'complete' and all(report.get(k) for k in ('brokerVerified', 'credentialAvailable', 'authenticated'))
    except Exception:
        pass
    try:
        config = json.loads(private(root / 'config.json'))
        workflow_dir = safe(Path(config['sourceRoot']) / 'examples/endly')
        workflow = safe(workflow_dir / 'smoke.yaml')
        # Predetermined five-assertion discovery/validation workflow; an empty or
        # altered successful workflow must never manufacture MCP readiness.
        if hashlib.sha256(workflow.read_bytes()).hexdigest() != '5e89bb4daaf932df98e1416a6ddfed728b22257082397719783bf682b390b587':
            raise ValueError('Endly smoke workflow changed; verification pending')
        resource = config['stdioCredential']
        if not resource.get('URL') or resource.get('Fallback') or resource.get('Data'):
            raise ValueError('explicit Scy credential reference required')
        reference = resource['URL'] + ('|' + resource['Key'] if resource.get('Key') else '')
        run(str(safe(endly_runner)), '-r=smoke', 'endpoint=http://' + listen + '/mcp',
            'bearerTokenSecret=' + reference, cwd=workflow_dir, timeout=90)
        result['mcpVerified'] = True
    except Exception:
        pass
    result['verificationPending'] = not (result['connectionVerified'] and result['mcpVerified'])
    return result


def enable_window_frame_click(config):
    profile = config.get('nativeLaunch')
    if not isinstance(profile, dict) or profile.get('mode') != 'semantic':
        raise ValueError('window frame click requires the semantic native profile')
    profile['windowFrameClick'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source'); parser.add_argument('--manifest')
    parser.add_argument('--installation', required=True)
    parser.add_argument('--apply', action='store_true'); parser.add_argument('--rollback')
    parser.add_argument('--broker-pid', type=int); parser.add_argument('--idle-verified', action='store_true')
    parser.add_argument('--broker-stopped-verified', action='store_true', help='rollback only: operator confirmed no broker/helper process remains')
    parser.add_argument('--interactive-enrollment', action='store_true')
    parser.add_argument('--listen', default='127.0.0.1:4987')
    parser.add_argument('--static-text-user', help='exact existing subject for the optional bounded static-text reader')
    parser.add_argument('--static-text-bundle', action='append', default=[], help='enable noneditable static text reads within an already enrolled application')
    parser.add_argument('--background-console', action='store_true', help='reopen the console without taking focus from the active application')
    parser.add_argument('--chrome-trust-scope', choices=['desktop'], help='explicitly select desktop-wide Chrome trust for an already desktop-wide user; never claims profile isolation')
    parser.add_argument('--enable-targeted-keyboard', action='store_true', help='enroll focus-bound keyboard alongside semantic AX actions; never enables raw pointer/text')
    parser.add_argument('--enable-session-keyboard', action='store_true', help='explicitly enroll login-session keyboard delivery alongside semantic AX actions; never a targeted-keyboard fallback')
    parser.add_argument('--enable-window-frame-click', action='store_true', help='enable single-use capture-bound window clicks for the semantic native profile')
    parser.add_argument('--native-effect-reconciliation', action='append', default=[], choices=['plan.effect.reconcile', 'plan.postcondition.reconcile', 'native.chrome.openExtensions.v1', 'native.focus.v1'], help='enroll a compiled read-only effect reconciliation contract')
    parser.add_argument('--endly-runner', default=str(Path.home() / '.local/bin/endly-mcp-runner'))
    args = parser.parse_args()
    if sys.platform != 'darwin' or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', args.listen) or not 0 < int(args.listen.split(':')[1]) < 65536:
        raise ValueError('macOS and IPv4 loopback listener required')
    if args.apply and args.rollback:
        raise ValueError('apply and rollback are mutually exclusive')
    if args.rollback and args.chrome_trust_scope:
        raise ValueError('rollback restores its recorded scope; scope changes require a separate upgrade')
    if args.rollback and args.enable_window_frame_click:
        raise ValueError('rollback restores its recorded window input enrollment')
    os.umask(0o077)
    root = owned_directory(args.installation)
    config_path = root / 'config.json'
    original_bytes = private(config_path)
    config = json.loads(original_bytes)
    app = root / 'Mechanize Permissions.app'
    old_requirement = None
    if not args.rollback:
        old_requirement = shared.requirement(app)
        if old_requirement != config['nativeConsole']['designatedRequirement']:
            raise ValueError('installed console pin disagrees')
    if args.broker_stopped_verified and (not args.rollback or args.broker_pid):
        raise ValueError('stopped verification is rollback-only and cannot accompany a PID')
    if (args.apply or args.rollback) and not args.broker_stopped_verified:
        if not args.broker_pid or not args.idle_verified:
            raise ValueError('operator-verified idle MCP and exact owned broker PID required')
        shared.process_identity(args.broker_pid, root / 'mechanize')
    if args.rollback:
        backup = owned_directory(args.rollback)
        saved = private(backup / 'config.json')
        record = json.loads(private(backup / 'rollback.json'))
        if record['installation'] != str(root) or hashlib.sha256(original_bytes).hexdigest() not in (record['originalConfigSHA256'], record['updatedConfigSHA256']):
            raise ValueError('rollback installation/configuration changed; review backup manually')
        for name, (filename, identifier) in ARTIFACTS.items():
            entry = record['artifacts'].get(name)
            if entry:
                verify(backup / filename, entry['requirement'], identifier, entry.get('sha256'))
            elif (backup / filename).exists():
                raise ValueError('unexpected backup artifact')
        if shared.requirement(backup / app.name) != json.loads(saved)['nativeConsole']['designatedRequirement']:
            raise ValueError('backup console pin disagrees')
        chrome_snapshot = rollback_chrome_snapshot(config, json.loads(saved), record, backup, root)
        extension_snapshot = rollback_extension_snapshot(config, json.loads(saved), record, backup, root)
        require_chrome_stopped(config, root)
        require_chrome_stopped(json.loads(saved), root)
        shared.stop_consoles(app)
        if args.broker_stopped_verified:
            for line in run('ps', '-axo', 'pid=,uid=,comm=').stdout.decode().splitlines():
                fields = line.strip().split(None, 2)
                if len(fields) == 3 and fields[1] == str(os.getuid()) and fields[2] in (str(root / 'mechanize'), str(root / 'mechanize-native'), str(root / 'mechanize-native-host')):
                    raise ValueError('installed broker/helper still running')
        else:
            shared.stop(args.broker_pid, root / 'mechanize')
        if private(config_path) != original_bytes:
            raise ValueError('rollback configuration changed during shutdown; review retained backup')
        require_helpers_stopped(root)
        require_chrome_stopped(config, root)
        require_chrome_stopped(json.loads(saved), root)
        check_chrome_snapshot(chrome_snapshot)
        if extension_snapshot is not None:
            check_extension_snapshot(extension_snapshot)
        replace_artifacts(backup, root)
        restore_extension(extension_snapshot, backup)
        if chrome_snapshot is not None:
            atomic(chrome_snapshot['path'], chrome_snapshot['after'])
        atomic(config_path, saved)
        pid = shared.start(root, args.listen)
        print(json.dumps({'rolledBack': True, 'brokerPID': pid, 'backup': str(backup), **report_health(root, args.listen, args.endly_runner)}))
        return
    if not args.source or not args.manifest:
        raise ValueError('frozen --source and --manifest required')
    source = safe(args.source)
    if source == SCRIPTS.parent or not source.is_dir():
        raise ValueError('separate frozen source snapshot required')
    manifest_path = safe(args.manifest)
    manifest_bytes = private(manifest_path)
    manifest = json.loads(manifest_bytes)
    if manifest_path != source / 'dist/development/manifest.json':
        raise ValueError('manifest must belong to frozen source build')
    artifacts = source / 'dist/development'
    verify_manifest(source, manifest, artifacts)
    extension_snapshot = preflight_extension(root, manifest, artifacts)
    if plistlib.loads((app / 'Contents/Info.plist').read_bytes()).get('MechanizeEnrollmentAccount') == manifest['consoleEnrollmentAccount']:
        raise ValueError('new per-build console account required')
    updated = updated_config(config, root, source, manifest)
    installed_plist = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    chrome_snapshot = preflight_chrome_native_host(config, root, installed_plist.get('MechanizeBrokerRequirement'), manifest)
    if args.chrome_trust_scope == 'desktop':
        enable_desktop_browser_scope(updated, chrome_snapshot)
    if args.enable_targeted_keyboard:
        if updated.get('nativeLaunch', {}).get('mode') != 'semantic':
            raise ValueError('targeted keyboard requires existing semantic enrollment')
        updated['nativeLaunch']['targetedKeyboard'] = True
    if args.enable_session_keyboard:
        if updated.get('nativeLaunch', {}).get('mode') != 'semantic':
            raise ValueError('session keyboard requires the semantic native profile')
        updated['nativeLaunch']['sessionKeyboard'] = True
    if args.enable_window_frame_click:
        enable_window_frame_click(updated)
    if args.native_effect_reconciliation:
        enrolled = updated.get('nativeEffectReconciliation', [])
        if not isinstance(enrolled, list) or any(value not in ['plan.effect.reconcile', 'plan.postcondition.reconcile', 'native.chrome.openExtensions.v1', 'native.focus.v1'] for value in enrolled):
            raise ValueError('unknown existing effect reconciliation enrollment')
        updated['nativeEffectReconciliation'] = list(dict.fromkeys(enrolled + args.native_effect_reconciliation))
    if args.static_text_bundle:
        users = [user for user in updated.get('users', []) if user.get('subject') == args.static_text_user]
        if len(users) != 1:
            raise ValueError('static text enrollment requires one exact existing subject')
        user = users[0]
        bundles = set(user.get('staticTextBundles', []))
        for bundle in args.static_text_bundle:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+', bundle):
                raise ValueError('exact static text application identifier required')
            if not user.get('desktopAccess') and bundle not in user.get('nativeBundles', []):
                raise ValueError('static text reader cannot expand enrolled application scope')
            bundles.add(bundle)
        if len(bundles) > 64:
            raise ValueError('static text application limit exceeded')
        user['staticTextBundles'] = sorted(bundles)
    elif args.static_text_user:
        raise ValueError('static text subject requires an explicit application')
    stage = Path(tempfile.mkdtemp(prefix='mechanize-runtime-', dir='/private/tmp'))
    for filename, _ in ARTIFACTS.values():
        path = artifacts / filename
        if path.is_dir():
            shutil.copytree(path, stage / filename)
        else:
            shutil.copyfile(path, stage / filename); (stage / filename).chmod(0o700)
    (stage / 'extension').mkdir(mode=0o700)
    extension_package.copy(artifacts / 'extension/chrome', stage / 'extension/chrome', extension_snapshot['updated'])
    atomic(stage / 'manifest.json', manifest_bytes)
    verify_manifest(source, manifest, stage)
    if not args.apply:
        print(json.dumps({'preflightPassed': True, 'stage': str(stage), 'sourceRoot': str(source), 'installedFilesChanged': False}))
        return
    if private(config_path) != original_bytes or shared.requirement(app) != old_requirement:
        raise ValueError('installation changed during preflight')
    check_chrome_snapshot(chrome_snapshot)
    check_extension_snapshot(extension_snapshot)
    require_chrome_stopped(config, root)
    backup = root / ('runtime-backup-' + str(int(time.time())) + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(mode=0o700)
    backup_artifacts = {}
    old_plist = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    for name, (filename, identifier) in ARTIFACTS.items():
        path = root / filename
        if path.exists():
            info = run('codesign', '--display', '--verbose=4', str(path)).stderr.decode()
            match = re.search(r'^CDHash=([0-9a-f]{40})$', info, re.M)
            if not match:
                raise ValueError('installed artifact hash unavailable')
            req = 'identifier "com.viant.mechanize.' + identifier + '" and cdhash H"' + match[1] + '"'
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if name != 'console' else None
            verify(path, req, identifier, digest)
            if name in ('broker', 'helper') and old_plist.get({'broker': 'MechanizeBrokerRequirement', 'helper': 'MechanizeHelperRequirement'}[name]) != req:
                raise ValueError('installed reverse pins disagree')
            backup_artifacts[name] = {'requirement': req, 'sha256': digest}
            regular_tree(path)
            if path.is_dir():
                shutil.copytree(path, backup / filename)
            else:
                shutil.copyfile(path, backup / filename); (backup / filename).chmod(0o700)
    atomic(backup / 'config.json', original_bytes)
    rollback_record = {'installation': str(root), 'artifacts': backup_artifacts, 'originalConfigSHA256': hashlib.sha256(original_bytes).hexdigest(), 'updatedConfigSHA256': hashlib.sha256(encode(updated)).hexdigest()}
    chrome_record = backup_chrome_snapshot(chrome_snapshot, backup)
    if chrome_record is not None:
        rollback_record['chromeNativeHost'] = chrome_record
    rollback_record['chromeExtension'] = backup_extension_snapshot(extension_snapshot, backup)
    atomic(backup / 'rollback.json', encode(rollback_record))
    print(json.dumps({'backup': str(backup), 'stage': str(stage), 'rollbackScript': str(Path(__file__).absolute()), 'rollbackRequires': '--rollback BACKUP --installation INSTALL_ROOT --broker-pid CURRENT_PID --idle-verified', 'rollbackWhenStopped': '--rollback BACKUP --installation INSTALL_ROOT --broker-stopped-verified'}), flush=True)
    # Enrollment must run from the final installed path: the Keychain ACL stores
    # that executable's identity. The new account preserves old credentials.
    if private(config_path) != original_bytes or shared.requirement(app) != old_requirement:
        raise ValueError('installation changed during backup')
    check_chrome_snapshot(chrome_snapshot)
    check_extension_snapshot(extension_snapshot)
    require_chrome_stopped(config, root)
    shared.stop_consoles(app)
    shared.stop(args.broker_pid, root / 'mechanize')
    if private(config_path) != original_bytes:
        raise RuntimeError('configuration changed during shutdown; retained backup requires operator review')
    check_chrome_snapshot(chrome_snapshot)
    require_helpers_stopped(root)
    require_chrome_stopped(config, root)
    check_extension_snapshot(extension_snapshot)
    try:
        replace_artifacts(stage, root)
        extension_package.replace(stage / 'extension/chrome', extension_snapshot['path'], extension_snapshot['updated'], allow_legacy=True)
        verify_manifest(source, manifest, root)
        shared.enroll(app, manifest['consoleRequirement'], config, args.interactive_enrollment)
        check_chrome_snapshot(chrome_snapshot)
        if chrome_snapshot is not None:
            atomic(chrome_snapshot['path'], chrome_snapshot['after'])
        atomic(config_path, encode(updated))
        pid = shared.start(root, args.listen)
    except Exception:
        raise RuntimeError('runtime replacement/start failed; retained backup requires explicit rollback (use --broker-stopped-verified when no broker/helper is running)') from None
    health = report_health(root, args.listen, args.endly_runner)
    report = {'upgraded': True, 'backup': str(backup), 'brokerPID': pid, 'sourceRoot': str(source), **health}
    atomic(backup / 'upgrade-report.json', encode(report))
    if health['connectionVerified']:
        run('open', *(['-g'] if args.background_console else []), str(app))
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('runtime upgrade failed: ' + str(error) if isinstance(error, (ValueError, RuntimeError)) else 'runtime upgrade failed: ' + type(error).__name__)
