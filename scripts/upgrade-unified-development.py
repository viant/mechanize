#!/usr/bin/env python3
"""Update an existing certificate-signed unified developer app.

Preflight is the default. Apply requires an exact idle broker PID. Existing
credentials, grants, stores, extension bytes and scope remain unchanged.
Keychain custody or a managed broker requires the separately reviewed migration
route. Existing local Scy Vault routing is preserved without accessing key bytes.
"""
import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

SCRIPTS = Path(__file__).resolve().parent
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
runtime = load('unified_update_runtime', 'upgrade-runtime.py')
shared = runtime.shared
package = load('unified_update_package', 'package-runtime-upgrade.py')
ROLES = {'broker': ('mechanize', 'broker'), 'helper': ('mechanize-native', 'native'), 'nativeHost': ('mechanize-native-host', 'chrome.nativehost')}

def validate_preserved_custody(config, app):
    if config.get('keychain'):
        raise ValueError('Keychain custody requires the reviewed migration route')
    vault = config.get('nativeVault')
    if vault is None:
        return
    fields = {'keyProvider', 'windowProtection', 'root', 'recordRoot', 'keyVersion', 'keyAlias', 'brokerRequirement'}
    if not isinstance(vault, dict) or set(vault) - fields or vault.get('keyProvider') != 'scy-local-v1' or vault.get('windowProtection') != 'helper-v1':
        raise ValueError('Only existing helper-protected local Scy custody can be preserved')
    if vault.get('root') != str(Path.home()/'.secret/vault') or vault.get('recordRoot') not in (None, '', str(Path.home()/'.secret/vault-records')):
        raise ValueError('Existing native Vault routing changed')
    for name in ('keyAlias', 'keyVersion'):
        value = vault.get(name)
        if not isinstance(value, str) or not runtime.re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value):
            raise ValueError('Bounded existing local key reference required')
    info = plistlib.loads(package.read_file(app/'Contents/Info.plist'))
    if vault.get('brokerRequirement') != info.get('MechanizeBrokerRequirement') or not vault.get('brokerRequirement'):
        raise ValueError('Existing Vault broker pin disagrees with installed app')

def candidate_config(original, app, source, manifest):
    validate_preserved_custody(original, app)
    helpers = app / 'Contents/Helpers'
    if original.get('nativeHelper') != str(helpers / 'mechanize-native') or original.get('nativeLaunch', {}).get('transport') != 'console-v1':
        raise ValueError('Existing same-path console-owned unified runtime required')
    if not original.get('nativeConsole'):
        raise ValueError('Existing native console enrollment required')
    result = copy.deepcopy(original)
    result['sourceRoot'] = str(source)
    result['nativeLaunch']['helperRequirement'] = manifest['runtime']['helper']['requirement']
    result['nativeConsole']['designatedRequirement'] = manifest['consoleRequirement']
    if result.get('nativeVault'):
        result['nativeVault']['brokerRequirement'] = manifest['runtime']['broker']['requirement']
    if result.get('chromeRetirement'):
        result['chromeRetirement']['brokerRequirement'] = manifest['runtime']['broker']['requirement']
    if result.get('chrome'):
        trust = result['chrome'].get('processTrust') or {}
        if trust.get('nativeHostExecutable') != str(helpers / 'mechanize-native-host'):
            raise ValueError('Unexpected native-host executable')
        trust['nativeHostRequirement'] = manifest['runtime']['nativeHost']['requirement']
    return result

def verify_bundle(app, manifest, verify=package.verify_artifact):
    if manifest.get('layout') != 'unified-app-v1' or manifest.get('installationPerformed') is not False or manifest.get('bundleIdentifier') != 'com.viant.mechanize.consent':
        raise ValueError('Staged unified development manifest required')
    if package.inventory(app) != manifest['inventory']:
        raise ValueError('Candidate inventory changed')
    verify(app, manifest['consoleRequirement'], app.parent)
    info = plistlib.loads(package.read_file(app / 'Contents/Info.plist'))
    if info.get('CFBundleIdentifier') != manifest['bundleIdentifier'] or info.get('MechanizeHelperLaunchTransport') != 'console-v1':
        raise ValueError('Candidate app identity changed')
    if set(manifest['runtime']) != set(ROLES):
        raise ValueError('Closed helper role set required')
    for role, (filename, suffix) in ROLES.items():
        item = manifest['runtime'][role]
        if item['relativePath'] != 'Contents/Helpers/' + filename:
            raise ValueError('Unexpected nested helper path')
        path = app / item['relativePath']
        package.requirement(item['requirement'], suffix)
        if package.sha(package.read_file(path, 512*1024*1024)) != item['sha256']:
            raise ValueError('Nested helper bytes changed')
        verify(path, item['requirement'], app.parent)
    if info.get('MechanizeBrokerRequirement') != manifest['runtime']['broker']['requirement'] or info.get('MechanizeHelperRequirement') != manifest['runtime']['helper']['requirement']:
        raise ValueError('Candidate reverse pins changed')
    return info

def certificate(path):
    with tempfile.TemporaryDirectory(prefix='mechanize-update-cert-') as d:
        prefix = str(Path(d)/'cert')
        shared.run('codesign', '--display', '--extract-certificates='+prefix, str(path))
        leaf = Path(prefix+'0')
        if not leaf.is_file(): raise ValueError('Certificate-signed update required; ad-hoc is not supported')
        return hashlib.sha1(leaf.read_bytes()).hexdigest()

def start_console(app, root):
    config=package.decode(shared.private(root/'config.json'))
    endpoint=Path(config['nativeConsole']['socketPath']+'.helper')
    executable=app/'Contents/MacOS/MechanizeConsent'
    shared.run('open','-g',str(app))
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        for line in shared.run('ps','-axo','pid=,uid=,comm=').stdout.decode().splitlines():
            fields=line.strip().split(None,2)
            if len(fields)==3 and fields[1]==str(os.getuid()) and fields[2]==str(executable):
                shared.process_identity(int(fields[0]),executable)
                try:info=endpoint.lstat()
                except FileNotFoundError:continue
                if stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077:
                    return
        time.sleep(.1)
    raise RuntimeError('Console helper listener did not become ready')

def start(app, root, listen):
    # console-v1 broker initialization needs the signed app's helper launcher.
    # Starting the broker first strands it before its HTTP listener exists.
    start_console(app,root)
    broker = app/'Contents/Helpers/mechanize'
    logs = root/'logs';logs.mkdir(mode=0o700,exist_ok=True)
    with (logs/'broker.stdout.log').open('ab') as out, (logs/'broker.stderr.log').open('ab') as err:
        child = subprocess.Popen([str(broker),'serve','-config',str(root/'config.json'),'-listen',listen],cwd=root,stdout=out,stderr=err,start_new_session=True)
    time.sleep(.5)
    shared.process_identity(child.pid,broker)
    return child.pid

def exchange(left, right):
    # Both directories are on the same volume. Keep the old app at right;
    # never leave the installed path missing between two separate renames.
    libc=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    rename=libc.renamex_np;rename.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
    if rename(os.fsencode(left),os.fsencode(right),2)!=0:
        raise OSError(ctypes.get_errno(),'Atomic application exchange failed')

def require_broker_stopped(helpers):
    for line in shared.run('ps','-axo','pid=,uid=,comm=').stdout.decode().splitlines():
        fields=line.strip().split(None,2)
        if len(fields)==3 and fields[1]==str(os.getuid()) and fields[2]==str(helpers/'mechanize'):
            raise ValueError('Broker is still running')

def rollback(root, backup, broker_pid, stopped, listen):
    backup=runtime.owned_directory(backup)
    if backup.parent!=root or not backup.name.startswith('unified-backup-'):raise ValueError('Owned update backup required')
    record=package.decode(shared.private(backup/'update.json'))
    app=package.physical(Path.home()/'Applications/Mechanize.app')
    retained=package.physical(record['retainedApp'])
    if record['installedApp']!=str(app) or retained.parent!=app.parent or not retained.name.startswith('.mechanize-update-'):raise ValueError('Backup application scope changed')
    before=shared.private(backup/'config.json');original=package.decode(before)
    current=shared.private(root/'config.json')
    if package.sha(before)!=record['originalConfigSHA256'] or package.sha(current) not in (record['originalConfigSHA256'],record['candidateConfigSHA256']):raise ValueError('Backup/config revision changed')
    if package.inventory(app)!=record['candidateAppInventory'] or package.inventory(retained)!=record['originalAppInventory']:raise ValueError('Application revision changed')
    if shared.requirement(retained)!=original['nativeConsole']['designatedRequirement']:raise ValueError('Original console pin changed')
    validate_preserved_custody(original, retained)
    helpers=app/'Contents/Helpers'
    chrome=record.get('chrome')
    if chrome:
        chrome_path=package.physical(chrome['path']);current_chrome=shared.private(chrome_path)
        if package.sha(current_chrome) not in (chrome['beforeSHA256'],chrome['afterSHA256']):raise ValueError('Browser config changed')
        saved_chrome=shared.private(backup/'chrome-native-host.json')
        if package.sha(saved_chrome)!=chrome['beforeSHA256']:raise ValueError('Browser backup changed')
    with shared.runtime_lock(root):
        shared.stop_consoles(app)
        if broker_pid:shared.stop(broker_pid,helpers/'mechanize')
        elif not stopped:raise ValueError('Exact idle broker PID or verified stopped state required')
        require_broker_stopped(helpers)
        runtime.require_helpers_stopped(helpers)
        if shared.private(root/'config.json')!=current or package.inventory(app)!=record['candidateAppInventory'] or package.inventory(retained)!=record['originalAppInventory']:raise ValueError('Rollback inputs changed')
        if chrome and shared.private(chrome_path)!=current_chrome:raise ValueError('Browser config changed during shutdown')
        exchange(app,retained)
        if chrome:
            shared.atomic(chrome_path,saved_chrome)
        shared.atomic(root/'config.json',before)
        pid=start(app,root,listen)
        report=shared.verify_console_connection(app,pid,helpers/'mechanize')
        record.update(state='rolled-back',brokerPID=pid,connection=report);shared.atomic(backup/'update.json',runtime.encode(record))
        print(json.dumps({'rolledBack':True,'brokerPID':pid,'backup':str(backup)}))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation',required=True,type=Path)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--rollback',type=Path)
    parser.add_argument('--broker-stopped-verified',action='store_true')
    parser.add_argument('--broker-pid',type=int)
    parser.add_argument('--idle-verified',action='store_true')
    parser.add_argument('--listen',default='127.0.0.1:4987')
    args=parser.parse_args()
    if os.uname().sysname!='Darwin' or not runtime.re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',args.listen) or not 0<int(args.listen.split(':')[1])<65536:
        raise ValueError('macOS and a bounded loopback listener required')
    os.umask(0o077)
    root=runtime.owned_directory(args.installation)
    if args.rollback:
        if args.apply or args.manifest or args.source or args.broker_pid and not args.idle_verified:raise ValueError('Rollback requires only its backup and verified process state')
        rollback(root,args.rollback,args.broker_pid,args.broker_stopped_verified,args.listen);return
    if not args.manifest or not args.source or args.broker_stopped_verified:raise ValueError('Source and manifest are required for preflight/apply')
    app=package.physical(Path.home()/'Applications/Mechanize.app')
    source=package.physical(args.source)
    if source==SCRIPTS.parent or not (source/'go.mod').is_file():
        raise ValueError('Separate frozen source snapshot required')
    if (root/'runtime/broker.plist').exists():
        raise ValueError('Managed installations require the reviewed service updater')
    manifest_raw=package.read_file(args.manifest,8*1024*1024,private=True);manifest=package.decode(manifest_raw)
    build_raw=package.read_file(source/'dist/development/manifest.json',8*1024*1024,private=True)
    build=package.decode(build_raw)
    if package.sha(build_raw)!=manifest.get('sourceManifestSHA256') or build.get('sourceRoot')!=str(source):
        raise ValueError('Candidate must bind the exact frozen source build')
    for role in ROLES:
        if build.get(role+'Requirement')!=manifest['runtime'][role]['requirement'] or build.get(role+'SHA256')!=manifest['runtime'][role]['sha256']:
            raise ValueError('Candidate differs from frozen source build')
    candidate=package.physical(manifest['app'])
    if package.overlap(candidate,app):raise ValueError('Separate candidate app required')
    new_info=verify_bundle(candidate,manifest)
    old_pin=shared.requirement(app);old_inventory=package.inventory(app)
    old_info=plistlib.loads(package.read_file(app/'Contents/Info.plist'))
    if certificate(app)!=certificate(candidate):raise ValueError('Update must preserve the existing signing certificate')
    config_path=root/'config.json';before=shared.private(config_path);original=package.decode(before)
    if original['nativeConsole']['designatedRequirement']!=old_pin:raise ValueError('Installed console pin disagrees')
    if old_info.get('MechanizeRuntimeLayoutVersion')!=1 or old_info.get('MechanizeEnrollmentAccount')==new_info.get('MechanizeEnrollmentAccount'):
        raise ValueError('Existing unified app and fresh console account required')
    helpers=app/'Contents/Helpers'
    runtime.verify(helpers/'mechanize',old_info['MechanizeBrokerRequirement'],'broker')
    runtime.verify(helpers/'mechanize-native',old_info['MechanizeHelperRequirement'],'native')
    updated=candidate_config(original,app,source,manifest)
    flat={role+'Requirement':manifest['runtime'][role]['requirement'] for role in ROLES}
    chrome=runtime.preflight_chrome_native_host(original,helpers,old_info['MechanizeBrokerRequirement'],flat)
    if not args.apply:
        print(json.dumps({'preflightPassed':True,'installedFilesChanged':False,'custodyMigrationRequired':False,'preserves':['credential resources','grants','stores','extension','scope'],'candidate':str(candidate)}));return
    if not args.idle_verified or not args.broker_pid:raise ValueError('Exact owned idle broker PID required')
    with shared.runtime_lock(root):
        shared.process_identity(args.broker_pid,helpers/'mechanize')
        if shared.private(config_path)!=before or package.inventory(app)!=old_inventory or package.read_file(args.manifest,8*1024*1024,private=True)!=manifest_raw:
            raise ValueError('Installation or candidate changed after preflight')
        runtime.check_chrome_snapshot(chrome)
        backup=root/('unified-backup-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
        shared.atomic(backup/'config.json',before)
        if chrome:shared.atomic(backup/'chrome-native-host.json',chrome['before'])
        stage=app.parent/('.mechanize-update-'+uuid.uuid4().hex+'.app')
        shutil.copytree(candidate,stage);verify_bundle(stage,manifest)
        record={'state':'prepared','installedApp':str(app),'retainedApp':str(stage),'originalConfigSHA256':package.sha(before),'candidateConfigSHA256':package.sha(runtime.encode(updated)),'originalAppInventory':old_inventory,'candidateAppInventory':manifest['inventory']}
        if chrome:record['chrome']={'path':str(chrome['path']),'beforeSHA256':package.sha(chrome['before']),'afterSHA256':package.sha(chrome['after'])}
        shared.atomic(backup/'update.json',runtime.encode(record))
        print(json.dumps({'preparedBackup':str(backup),'retainedAppPath':str(stage)}),flush=True)
        shared.stop_consoles(app)
        shared.stop(args.broker_pid,helpers/'mechanize')
        require_broker_stopped(helpers)
        # Retire only owned helper/bridge processes. Chrome and its tabs stay open.
        for line in shared.run('ps','-axo','pid=,uid=,comm=').stdout.decode().splitlines():
            fields=line.strip().split(None,2)
            if len(fields)==3 and fields[1]==str(os.getuid()) and fields[2] in [str(helpers/'mechanize-native'),str(helpers/'mechanize-native-host')]:shared.stop(int(fields[0]),Path(fields[2]))
        runtime.require_helpers_stopped(helpers)
        if shared.private(config_path)!=before or package.inventory(app)!=old_inventory:raise RuntimeError('Stopped installation changed; no exchange performed')
        runtime.check_chrome_snapshot(chrome);verify_bundle(stage,manifest)
        exchange(app,stage)
        record['state']='app-exchanged';shared.atomic(backup/'update.json',runtime.encode(record))
        # Never repeat uncertain enrollment or automatically roll back it.
        shared.enroll(app,manifest['consoleRequirement'],original,False)
        record['state']='console-enrolled';shared.atomic(backup/'update.json',runtime.encode(record))
        if chrome:shared.atomic(chrome['path'],chrome['after'])
        shared.atomic(config_path,runtime.encode(updated))
        record['state']='configured';shared.atomic(backup/'update.json',runtime.encode(record))
        pid=start(app,root,args.listen)
        report=shared.verify_console_connection(app,pid,helpers/'mechanize')
        record.update(state='verified',brokerPID=pid,connection=report)
        shared.atomic(backup/'update.json',runtime.encode(record))
        print(json.dumps({'upgraded':True,'backup':str(backup),'retainedOriginalApp':str(stage),'brokerPID':pid,'connectionVerified':True}))

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit(type(e).__name__+': update stopped; inspect retained private evidence. No automatic retry or rollback.') from None
