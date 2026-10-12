#!/usr/bin/env python3
"""Stage one visible signed Mechanize.app; never install or change custody."""
import argparse
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import playwright_package

spec=importlib.util.spec_from_file_location('runtime_package',Path(__file__).with_name('package-runtime-upgrade.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
signing_spec=importlib.util.spec_from_file_location('mechanize_development_signing',Path(__file__).with_name('development_signing.py'))
development_signing=importlib.util.module_from_spec(signing_spec);signing_spec.loader.exec_module(development_signing)
LAYOUT={'broker':'Contents/Helpers/mechanize','helper':'Contents/Helpers/mechanize-native','nativeHost':'Contents/Helpers/mechanize-native-host'}

def sign(app,identity,work):
    if identity!='-' and not re.fullmatch('[A-Fa-f0-9]{40}',identity):raise ValueError('Exact signing certificate fingerprint required')
    p.child(['codesign',*development_signing.signing_arguments(identity,'com.viant.mechanize.consent'),str(app)],work)
    result=subprocess.run(['codesign','--display','--verbose=4',str(app)],cwd=work,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    match=re.search(rb'^CDHash=([a-fA-F0-9]{40})$',result.stderr,re.M)
    if result.returncode or not match:raise ValueError('Signed console identity unavailable')
    requirement='identifier "com.viant.mechanize.consent" and cdhash H"'+match[1].decode().lower()+'"'
    p.verify_artifact(app,requirement,work)
    if identity!='-':
        development_signing.verify_certificate(app,identity)
    return requirement

def build(manifest_path,output,identity=None,verify=p.verify_artifact,signer=sign,installed_app=None):
    output=p.external(output)
    if output.exists():raise ValueError('New staging directory required')
    manifest_raw=p.read_file(manifest_path);manifest=p.decode(manifest_raw)
    if manifest.get('schemaVersion')!=1 or manifest.get('installationPerformed') is not False:raise ValueError('Uninstalled development manifest required')
    if identity is None:
        identity=manifest.get('signingCertificateSHA1') if manifest.get('signingMode')=='certificate' else '-'
        if not isinstance(identity,str):raise ValueError('Existing staged signing identity required')
    if identity!='-':identity=development_signing.select_identity(identity)
    output.mkdir(mode=0o700)
    console=p.physical(manifest['console']);old_inventory=p.inventory(console)
    p.requirement(manifest['consoleRequirement'],'consent');verify(console,manifest['consoleRequirement'],output)
    sources={}
    for role,suffix in [('broker','broker'),('helper','native'),('nativeHost','chrome.nativehost')]:
        source=p.physical(manifest[role]);req=p.requirement(manifest[role+'Requirement'],suffix)
        if p.sha(p.read_file(source,512*1024*1024))!=p.digest(manifest[role+'SHA256']):raise ValueError('Staged runtime digest mismatch')
        verify(source,req,output);sources[role]=source
    if manifest['nativeHostBrokerRequirement']!=manifest['brokerRequirement']:raise ValueError('Native host reverse pin mismatch')
    info=plistlib.loads(p.read_file(console/'Contents/Info.plist'))
    if info.get('CFBundleIdentifier')!='com.viant.mechanize.consent' or info.get('CFBundleExecutable')!='MechanizeConsent' or info.get('MechanizeBrokerRequirement')!=manifest['brokerRequirement'] or info.get('MechanizeHelperRequirement')!=manifest['helperRequirement']:raise ValueError('Signed console trust metadata mismatch')
    if (console/'Contents/Helpers').exists():raise ValueError('Input already contains runtime helpers')
    app=output/'Mechanize.app';shutil.copytree(console,app)
    helpers=app/'Contents/Helpers';helpers.mkdir(mode=0o700)
    for role,relative in LAYOUT.items():
        shutil.copyfile(sources[role],app/relative);(app/relative).chmod(0o700)
        verify(app/relative,manifest[role+'Requirement'],output)
        if p.sha(p.read_file(app/relative,512*1024*1024))!=manifest[role+'SHA256']:raise ValueError('Nested image changed')
    if installed_app is not None:
        existing=p.physical(installed_app)
        if existing!=Path.home()/'Applications/Mechanize.app':raise ValueError('Exact installed unified app metadata required')
        old=plistlib.loads(p.read_file(existing/'Contents/Info.plist'))
        account=old.get('MechanizeEnrollmentAccount')
        if old.get('CFBundleIdentifier')!='com.viant.mechanize.consent' or not isinstance(account,str) or not account.startswith('com.viant.mechanize.consent:') or len(account)>1024 or any(ord(c)<32 for c in account):raise ValueError('Existing opaque console enrollment account required')
        if info.get('MechanizeEnrollmentAccount')==account:raise ValueError('New console requires a fresh enrollment account')
        review=('MechanizeUpgradeReviewPublicKey','MechanizeUpgradePackagePath')
        if any(key in old for key in review):
            if not all(isinstance(old.get(key),str) and old[key] for key in review):raise ValueError('Complete public upgrade enrollment required')
            encoded=old[review[0]];raw=base64.b64decode(encoded,validate=True)
            if len(raw)!=32 or base64.b64encode(raw).decode()!=encoded or p.overlap(p.path(old[review[1]]),existing):raise ValueError('Exact external public review enrollment required')
            for key in review:info[key]=old[key]
    info.update({'CFBundleName':'Mechanize','CFBundleDisplayName':'Mechanize','MechanizeRuntimeLayoutVersion':1,'MechanizeHelperLaunchTransport':'console-v1',
        'MechanizeBrokerRelativePath':LAYOUT['broker'],'MechanizeHelperRelativePath':LAYOUT['helper'],'MechanizeNativeHostRelativePath':LAYOUT['nativeHost']})
    with (app/'Contents/Info.plist').open('wb') as target:plistlib.dump(info,target)
    requirement=signer(app,identity,output)
    for role,relative in LAYOUT.items():verify(app/relative,manifest[role+'Requirement'],output)
    verify(app,requirement,output)
    if p.inventory(console)!=old_inventory or p.read_file(manifest_path)!=manifest_raw:raise ValueError('Source changed while staging')
    result={'schemaVersion':1,'layout':'unified-app-v1','app':str(app),'bundleIdentifier':'com.viant.mechanize.consent','consoleRequirement':requirement,
        'runtime':{role:{'relativePath':relative,'requirement':manifest[role+'Requirement'],'sha256':manifest[role+'SHA256']} for role,relative in LAYOUT.items()},
        'inventory':p.inventory(app),'sourceManifestSHA256':p.sha(manifest_raw),'migrationRequired':True,'installationPerformed':False,'credentialsProvisioned':False,'systemPermissionsGranted':False,'singleTCCEntryQualified':False}
    if manifest.get('playwright') is not None:
        source_runtime=console/'Contents/Resources/Playwright'
        expected=playwright_package.configuration(Path(manifest['playwright']['nodePath']),source_runtime)
        if expected!=manifest['playwright']:raise ValueError('Reviewed Playwright runtime changed')
        result['playwright']=playwright_package.configuration(Path(expected['nodePath']),app/'Contents/Resources/Playwright')
        if result['playwright']['runtimeSHA256']!=expected['runtimeSHA256']:raise ValueError('Nested Playwright runtime changed')
    p.write_private(output/'unified-manifest.json',p.wire(result))
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',required=True);parser.add_argument('--output-directory',required=True);parser.add_argument('--signing-identity',help='Defaults to the staged development manifest signing identity');parser.add_argument('--installed-app',type=Path,help='Preserve public review enrollment only; retain the new candidate console account');args=parser.parse_args()
    try:build(args.manifest,args.output_directory,args.signing_identity,installed_app=args.installed_app)
    except Exception:raise SystemExit('Unified staging failed; private diagnostics withheld')
    print(json.dumps({'staged':True,'installed':False,'migrationRequired':True,'singleTCCEntryQualified':False},separators=(',',':')))
if __name__=='__main__':main()
