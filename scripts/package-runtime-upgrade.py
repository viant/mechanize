#!/usr/bin/env python3
"""Assemble and sign reviewed staged upgrade artifacts; never launch or install them."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import plistlib
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PLAN_KEYS = ('version','oldBrokerSHA256','brokerCandidate','configCandidate','backup','stageJournalRoot','artifactJournalRoot','newSourceRoot','runtime','readiness')
RUNTIME_KEYS = ('BrokerPath','OldBrokerRequirement','NewBrokerRequirement','ActiveHelperPath','ActiveHelperRequirement','ActiveHelperSHA256','ChromeExecutable','ExtensionID','OldConsoleBirth','Artifacts','Mode','PreservedExtension','ChromeRequirement')
ARTIFACT_KEYS = ('role','target','candidate','Old','New','OldDigest','NewDigest','OldRequirement','NewRequirement')
ENROLLMENT_KEYS = ('version','session','config','resources','consoleRequirement','expectedUID','namespace','clientID','canonicalExecutable','oldRequirement','newRequirement','alias','service','account','journalRoot')
ENTRY_KEYS = ('kind','mode','size','sha256')
ROLES = {'helper':('helper','helperRequirement','helperSHA256','native'), 'native-host':('nativeHost','nativeHostRequirement','nativeHostSHA256','chrome.nativehost'), 'console':('console','consoleRequirement',None,'consent')}

def closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys): raise ValueError('Closed reviewed metadata required')
    return {k:value[k] for k in keys}

def text(value):
    if not isinstance(value,str) or not value or len(value.encode())>4096 or any(ord(c)<32 for c in value): raise ValueError('Bounded metadata text required')
    return value

def digest(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value): raise ValueError('SHA256 required')
    return value

def path(value):
    text(str(value)); p=Path(value)
    if not p.is_absolute() or os.path.normpath(str(p))!=str(p): raise ValueError('Canonical absolute path required')
    return p

def physical(value):
    p=path(value)
    if p.resolve()!=p or any(q.is_symlink() for q in [p,*p.parents]): raise ValueError('Symlink path rejected')
    return p

def external(value):
    p=physical(value)
    if p==ROOT or ROOT in p.parents or any((q/'.git').exists() for q in [p,*p.parents]): raise ValueError('Packaging output must be outside Git')
    return p

def ref(value):
    value=closed(value,('path','sha256'));path(value['path']);digest(value['sha256']);return value

def sha(raw): return hashlib.sha256(raw).hexdigest()

def wire(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e').replace('\u2028','\\u2028').replace('\u2029','\\u2029').encode()

def decode(raw):
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result: raise ValueError('Duplicate JSON field')
            result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))

def read_file(value, limit=2_000_000, private=False):
    p=physical(value);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno())
        if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1 or a.st_mode&0o7022 or not 0<=a.st_size<=limit or private and stat.S_IMODE(a.st_mode)!=0o600: raise ValueError('Unsafe bounded metadata/artifact file')
        raw=f.read(limit+1);b=os.fstat(f.fileno());entry=p.lstat()
        if len(raw)!=a.st_size or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) or (a.st_dev,a.st_ino)!=(entry.st_dev,entry.st_ino): raise ValueError('Artifact changed')
    return raw

def inventory(value):
    result={};total=0;p=physical(value)
    def visit(current,name):
        nonlocal total
        info=current.lstat();mode=stat.S_IMODE(info.st_mode)
        if info.st_uid!=os.getuid() or mode&0o7022 or len(result)>=4096: raise ValueError('Unsafe staged artifact tree')
        if stat.S_ISDIR(info.st_mode):
            if mode not in (0o700,0o755): raise ValueError('Directory mode rejected')
            result[name]={'kind':'directory','mode':mode,'size':0,'sha256':''}
            names=sorted(os.listdir(current))
            for member in names: visit(current/member,member if name=='.' else name+'/'+member)
            after=current.lstat()
            if names!=sorted(os.listdir(current)) or (info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns): raise ValueError('Artifact tree changed')
        else:
            raw=read_file(current,512*1024*1024);total+=len(raw)
            if total>512*1024*1024 or mode not in (0o600,0o644,0o700,0o755): raise ValueError('Artifact exceeds bound')
            result[name]={'kind':'file','mode':mode,'size':len(raw),'sha256':sha(raw)}
    visit(p,'.');return ordered_inventory(result)

def runtime_resources_inventory(value):
    import extension_package
    p=physical(value);before=p.lstat();mode=stat.S_IMODE(before.st_mode)
    if not stat.S_ISDIR(before.st_mode) or before.st_uid!=os.getuid() or mode not in (0o700,0o755):raise ValueError('Owned runtime directory required')
    result={'.':{'kind':'directory','mode':mode,'size':0,'sha256':''}}
    total=0
    for name in extension_package.FILES:
        info=(p/name).lstat();raw=read_file(p/name,4*1024*1024);total+=len(raw)
        mode=stat.S_IMODE(info.st_mode)
        if mode not in (0o600,0o644,0o700,0o755) or total>16*1024*1024:raise ValueError('Runtime resource bound exceeded')
        result[name]={'kind':'file','mode':mode,'size':len(raw),'sha256':sha(raw)}
    after=p.lstat()
    if (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('Runtime directory changed')
    return ordered_inventory(result)

def ordered_inventory(value):
    if not isinstance(value,dict) or not value or len(value)>4096 or '.' not in value: raise ValueError('Bounded inventory required')
    result={};total=0
    for name in sorted(value):
        if name!='.' and (name.startswith('/') or any(x in ('','..','.') for x in name.split('/'))): raise ValueError('Relative inventory name required')
        entry=closed(value[name],ENTRY_KEYS);kind=entry['kind'];mode=entry['mode'];size=entry['size']
        if type(mode)!=int or type(size)!=int or size<0 or size>512*1024*1024: raise ValueError('Inventory integer required')
        if kind=='directory':
            if mode not in (0o700,0o755) or size!=0 or entry['sha256']!='': raise ValueError('Directory inventory invalid')
        elif kind=='file':
            if mode not in (0o600,0o644,0o700,0o755): raise ValueError('File mode invalid')
            digest(entry['sha256']);total+=size
        else: raise ValueError('File/directory inventory only')
        result[name]=entry
    if total>512*1024*1024: raise ValueError('Inventory byte bound')
    return result

GOOGLE_CHROME_REQUIREMENT = 'identifier "com.google.Chrome" and anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV"'

def chrome_requirement(value):
    if value == GOOGLE_CHROME_REQUIREMENT: return value
    atom=r'cdhash H"[a-f0-9]{40}"'
    if not isinstance(value,str) or not re.fullmatch(r'identifier "com\.google\.Chrome" and (?:'+atom+r'|\('+atom+r'(?: or '+atom+r'){1,3}\))',value):raise ValueError('Exact bounded Chrome architecture pins required')
    hashes=re.findall(r'H"([a-f0-9]{40})"',value)
    if len(set(hashes))!=len(hashes):raise ValueError('Duplicate Chrome architecture pin')
    return value

def requirement(value, role):
    if not isinstance(value,str) or not re.fullmatch(r'identifier "com\.viant\.mechanize\.'+re.escape(role)+r'" and cdhash H"[a-f0-9]{40}"',value): raise ValueError('Exact role signature pin required')
    return value

def child(args,cwd):
    directory=external(cwd); info=directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Private child working directory required')
    result=subprocess.run(args,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
    if result.returncode: raise ValueError('Packaging child failed; diagnostics withheld')

def verify_artifact(p,req,cwd): child(['codesign','--verify','--strict','--test-requirement','='+req,str(physical(p))],cwd)

def overlap(a,b):
    a,b=path(a),path(b);return a==b or a in b.parents or b in a.parents

def unified_manifest(reference, manifest, verify, cwd):
    reference=ref(reference);raw=read_file(reference['path'],private=True)
    if sha(raw)!=reference['sha256']:raise ValueError('Unified manifest reference changed')
    u=decode(raw)
    closed(u,('schemaVersion','layout','app','bundleIdentifier','consoleRequirement','runtime','inventory','sourceManifestSHA256','migrationRequired','installationPerformed','credentialsProvisioned','systemPermissionsGranted','singleTCCEntryQualified'))
    if u['schemaVersion']!=1 or u['layout']!='unified-app-v1' or u['bundleIdentifier']!='com.viant.mechanize.consent' or u['installationPerformed'] is not False:raise ValueError('Reviewed unified stage required')
    app=physical(u['app']);expected=ordered_inventory(u['inventory'])
    if inventory(app)!=expected:raise ValueError('Unified app inventory changed')
    verify(app,requirement(u['consoleRequirement'],'consent'),cwd)
    updated=copy.deepcopy(manifest);updated['console']=str(app);updated['consoleRequirement']=u['consoleRequirement']
    closed(u['runtime'],('broker','helper','nativeHost'))
    for role,name in [('broker','mechanize'),('helper','mechanize-native'),('nativeHost','mechanize-native-host')]:
        item=closed(u['runtime'][role],('relativePath','requirement','sha256'));relative='Contents/Helpers/'+name
        if item['relativePath']!=relative or item['requirement']!=manifest[role+'Requirement'] or item['sha256']!=manifest[role+'SHA256'] or expected[relative]['sha256']!=item['sha256']:raise ValueError('Nested runtime binding mismatch')
        updated[role]=str(app/relative)
    return u,updated

def assemble_plan(review,manifest,verify,cwd):
    if 'unifiedManifest' not in review:return assemble_legacy_plan(review,manifest,verify,cwd)
    base=copy.deepcopy(review);reference=base.pop('unifiedManifest')
    update=base.pop('samePathUnifiedUpdate',False)
    if update is not False and update is not True:raise ValueError('Explicit same-path update required')
    approval_present='preinstalledApprovalConsole' in base
    approval=base.pop('preinstalledApprovalConsole',False)
    if approval_present and approval is not True:raise ValueError('Explicit approving console review required')
    preinstalled_present='preinstalledUnifiedApp' in base
    preinstalled=base.pop('preinstalledUnifiedApp',False)
    if preinstalled_present and preinstalled is not True:raise ValueError('Explicit preinstalled bundle review required')
    u,updated=unified_manifest(reference,manifest,verify,cwd)
    if u['sourceManifestSHA256']!=review['stagedManifest']['sha256']:raise ValueError('Unified source build mismatch')
    plan,enrollment,observer=assemble_legacy_plan(base,updated,verify,cwd,unified_update=update)
    target=Path.home()/'Applications/Mechanize.app'
    if update:
        if preinstalled or approval or path(enrollment['canonicalExecutable'])!=target/'Contents/Helpers/mechanize':raise ValueError('Exact existing unified update required')
        old_console=next(a for a in plan['runtime']['Artifacts'] if a['role']=='console')
        if inventory(target)!=old_console['Old']:raise ValueError('Old unified bundle changed')
        verify(target,old_console['OldRequirement'],cwd)
    elif preinstalled:
        if inventory(target)!=ordered_inventory(u['inventory']):raise ValueError('Preinstalled bundle differs from reviewed candidate')
        verify(target,u['consoleRequirement'],cwd);verify(target/'Contents/Helpers/mechanize',manifest['brokerRequirement'],cwd)
        if inventory(target)!=ordered_inventory(u['inventory']):raise ValueError('Preinstalled bundle changed during verification')
    elif target.exists() or target.is_symlink():raise ValueError('Initial unified destination must be absent')
    app={'role':'unified-app','target':str(target),'candidate':u['app'],'Old':{},'New':ordered_inventory(u['inventory']),'OldDigest':'','NewDigest':sha(wire(ordered_inventory(u['inventory']))),'OldRequirement':'','NewRequirement':u['consoleRequirement']}
    runtime=plan['runtime'];legacy=runtime['Artifacts'];runtime['Artifacts']= [app];runtime['Mode']='unified-app-update-v3' if update else 'unified-app-v2';runtime['LegacyArtifacts']=legacy
    if update:
        app.update(Old=copy.deepcopy(old_console['Old']),OldDigest=old_console['OldDigest'],OldRequirement=old_console['OldRequirement'])
        runtime['ConfigPath']=enrollment['config']['path']
    else:runtime['NewBrokerPath']=str(target/'Contents/Helpers/mechanize')
    if preinstalled:runtime['preinstalledUnifiedApp']=True
    if approval:
        if not preinstalled or enrollment['consoleRequirement']!=u['consoleRequirement']:raise ValueError('Approving console must be exact preinstalled app')
        original=next(a for a in legacy if a['role']=='console')
        snapshot={'path':original['target'],'requirement':original['OldRequirement'],'inventory':original['Old'],'inventorySHA256':original['OldDigest']}
        approving={'installedPath':str(target),'requirement':u['consoleRequirement'],'birth':runtime['OldConsoleBirth']}
        original.update(target=u['app'],Old=copy.deepcopy(original['New']),OldDigest=original['NewDigest'],OldRequirement=original['NewRequirement'])
        runtime['preinstalledApprovalConsole']=True;runtime['ApprovalConsole']=approving;runtime['OriginalConsoleArtifact']=snapshot
        enrollment['approvalConsole']=copy.deepcopy(approving);enrollment['originalConsoleRequirement']=snapshot['requirement']
    plan['version']=3 if update else 2;enrollment['version']=plan['version']
    if not update:enrollment['newCanonicalExecutable']=runtime['NewBrokerPath']
    order=(*RUNTIME_KEYS[:8],'ExtensionStorageSHA256',*RUNTIME_KEYS[8:],'ChromeRecovery','NativeRecordRoot','NewBrokerPath','LegacyArtifacts','preinstalledUnifiedApp','preinstalledApprovalConsole','ApprovalConsole','OriginalConsoleArtifact','ConfigPath')
    plan['runtime']={key:runtime[key] for key in order if key in runtime}
    return plan,enrollment,observer

def assemble_legacy_plan(review, manifest, verify, cwd, unified_update=False):
    review=closed(review,('version','title','stagedManifest','enrollment','installPlan','observer'))
    if type(review['version'])!=int or review['version']!=1: raise ValueError('Review version required')
    text(review['title'])
    if len(review['title'].encode())>120: raise ValueError('Title too long')
    enrollment=closed(copy.deepcopy(review['enrollment']),ENROLLMENT_KEYS)
    if enrollment['version']!=1 or type(enrollment['expectedUID'])!=int or enrollment['expectedUID']!=os.getuid(): raise ValueError('Current owner required')
    for k in ('session','namespace'):digest(enrollment[k])
    ref(enrollment['config'])
    if not isinstance(enrollment['resources'],list) or not 1<=len(enrollment['resources'])<=16: raise ValueError('Bounded resource references required')
    for resource in enrollment['resources']:ref(resource)
    if len({r['path'] for r in enrollment['resources']})!=len(enrollment['resources']):raise ValueError('Duplicate resource reference')
    for k in ('consoleRequirement','clientID','alias','service','account'):text(enrollment[k])
    requirement(enrollment['consoleRequirement'],'consent')
    for k in ('canonicalExecutable','journalRoot'):path(enrollment[k])
    requirement(enrollment['oldRequirement'],'broker');requirement(enrollment['newRequirement'],'broker')
    if enrollment['oldRequirement']==enrollment['newRequirement']:raise ValueError('Distinct reviewed broker versions required')
    plan=closed(copy.deepcopy(review['installPlan']),tuple(k for k in PLAN_KEYS if k!='brokerCandidate'))
    for value,name in [(enrollment['journalRoot'],'mechanize-custody-migration'),(plan['stageJournalRoot'],'mechanize-runtime-staging'),(plan['artifactJournalRoot'],'mechanize-runtime-artifacts')]:
        journal=path(value)
        if journal.name!=name or journal.parent.name!='.secret':raise ValueError('Exact private journal layout required')
    if type(plan['version'])!=int or plan['version']!=1:raise ValueError('Plan version required')
    optional=tuple(k for k in ('ChromeRecovery','NativeRecordRoot') if k in plan['runtime'])
    runtime=closed(plan['runtime'],tuple(k for k in RUNTIME_KEYS if k!='NewBrokerRequirement')+optional)
    if runtime['Mode']!='preserve-extension-v1': raise ValueError('Only explicit preserved-extension assembly supported')
    preserved=runtime['PreservedExtension'];closed(preserved,('path','extensionID','inventory','inventorySHA256',*(['runtimeResourcesOnly'] if 'runtimeResourcesOnly' in preserved else [])))
    if 'runtimeResourcesOnly' in preserved and preserved['runtimeResourcesOnly'] is not True:raise ValueError('Explicit runtime-only preservation required')
    path(preserved['path']);preserved['inventory']=ordered_inventory(preserved['inventory'])
    if digest(preserved['inventorySHA256'])!=sha(wire(preserved['inventory'])) or preserved['extensionID']!=runtime['ExtensionID'] or not re.fullmatch('[a-p]{32}',runtime['ExtensionID']): raise ValueError('Preserved extension metadata mismatch')
    import extension_package
    names=set(preserved['inventory'])- {'.'}
    if preserved.get('runtimeResourcesOnly') and names!=set(extension_package.FILES):raise ValueError('Complete current runtime resources required')
    if names not in [set(x) for x in (*extension_package.LEGACY_FILE_SETS,extension_package.FILES)] or any(e['kind']!='file' or e['size']>4*1024*1024 for n,e in preserved['inventory'].items() if n!='.') or sum(e['size'] for e in preserved['inventory'].values())>16*1024*1024:raise ValueError('Exact public extension inventory required')
    if 'ChromeRecovery' in runtime:
        recovery=closed(runtime['ChromeRecovery'],('originalConfig','originalChromeSHA256'));ref(recovery['originalConfig']);digest(recovery['originalChromeSHA256'])
        chrome_requirement(runtime['ChromeRequirement'])
    if 'NativeRecordRoot' in runtime and runtime['NativeRecordRoot']!=str(Path.home()/'.secret/vault-records'):raise ValueError('Exact new record-store routing required')
    preserved={k:preserved[k] for k in ('path','extensionID','inventory','inventorySHA256',*(['runtimeResourcesOnly'] if 'runtimeResourcesOnly' in preserved else []))}
    runtime['PreservedExtension']=preserved
    for k in ('ActiveHelperSHA256',):digest(runtime[k])
    requirement(runtime['ActiveHelperRequirement'],'native')
    for k in ('ChromeExecutable','ActiveHelperPath','BrokerPath'):path(runtime[k])
    text(runtime['ChromeRequirement']);text(runtime['OldConsoleBirth']);digest(plan['oldBrokerSHA256'])
    if runtime['BrokerPath']!=enrollment['canonicalExecutable'] or runtime['OldBrokerRequirement']!=enrollment['oldRequirement']: raise ValueError('Original broker binding mismatch')
    if (not unified_update and path(enrollment['config']['path'])!=path(runtime['BrokerPath']).parent/'config.json') or (unified_update and (path(runtime['BrokerPath'])!=Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize' or path(enrollment['config']['path']).name!='config.json' or overlap(path(enrollment['config']['path']).parent,Path.home()/'Applications/Mechanize.app'))): raise ValueError('Canonical config reference required')
    broker=physical(manifest['broker']);broker_req=requirement(manifest['brokerRequirement'],'broker')
    if broker_req!=enrollment['newRequirement'] or sha(read_file(broker,512*1024*1024))!=digest(manifest['brokerSHA256']): raise ValueError('Staged broker mismatch')
    verify(broker,broker_req,cwd)
    plan['brokerCandidate']={'path':str(broker),'sha256':manifest['brokerSHA256']};runtime['NewBrokerRequirement']=broker_req
    if manifest['nativeHostBrokerRequirement']!=broker_req: raise ValueError('Native-host reverse pin mismatch')
    artifacts=runtime['Artifacts']
    if not isinstance(artifacts,list) or len(artifacts)!=3 or {a.get('role') for a in artifacts}!={'helper','native-host','console'}: raise ValueError('Exact non-extension artifact set required')
    for index,a in enumerate(artifacts):
        a=closed(a,('role','target','Old','OldDigest','OldRequirement'));role=a['role'];key,pin,hashkey,identifier=ROLES[role]
        path(a['target']);a['Old']=ordered_inventory(a['Old'])
        if digest(a['OldDigest'])!=sha(wire(a['Old'])): raise ValueError('Reviewed old inventory digest mismatch')
        requirement(a['OldRequirement'],identifier);new_req=requirement(manifest[pin],identifier);candidate=physical(manifest[key])
        before=inventory(candidate);verify(candidate,new_req,cwd)
        if inventory(candidate)!=before: raise ValueError('Signed artifact changed')
        if hashkey and before.get('.',{}).get('sha256')!=digest(manifest[hashkey]): raise ValueError('Staged executable digest mismatch')
        expected_target=Path.home()/'Applications/Mechanize.app' if unified_update and role=='console' else path(runtime['BrokerPath']).parent/{'helper':'mechanize-native','native-host':'mechanize-native-host','console':'Mechanize Permissions.app'}[role]
        expected_kind='directory' if role=='console' else 'file'
        if path(a['target'])!=expected_target or candidate==path(a['target']) or a['Old']['.']['kind']!=expected_kind or before['.']['kind']!=expected_kind:raise ValueError('Canonical artifact target/kind required')
        a.update(candidate=str(candidate),New=before,NewDigest=sha(wire(before)),NewRequirement=new_req)
        artifacts[index]={k:a[k] for k in ARTIFACT_KEYS}
    console=next(a for a in artifacts if a['role']=='console')
    if path(console['target'])!=(Path.home()/'Applications/Mechanize.app' if unified_update else path(runtime['BrokerPath']).parent/'Mechanize Permissions.app'): raise ValueError('Canonical console target required')
    plist=plistlib.loads(read_file(Path(console['candidate'])/'Contents/Info.plist'))
    if plist.get('MechanizeBrokerRequirement')!=broker_req:raise ValueError('Candidate console reverse broker pin mismatch')
    if 'Contents/MacOS/MechanizeConsent' not in console['New']:raise ValueError('Candidate console main executable missing')
    readiness=closed(plan['readiness'],('launchd','listen'));ref(readiness['launchd']);text(readiness['listen'])
    readiness.update(consoleCandidate=console['candidate'],consoleRequirement=console['NewRequirement'],consoleInventory=console['New'])
    root=path(enrollment['config']['path']).parent if unified_update else path(runtime['BrokerPath']).parent
    for target in [plan[k] for k in ('backup','stageJournalRoot','artifactJournalRoot')]+[enrollment['journalRoot'],enrollment['config']['path'],runtime['BrokerPath']]+[a['target'] for a in artifacts]:
        if (root not in path(target).parents and not (unified_update and (path(target)==Path.home()/'Applications/Mechanize.app' or Path.home()/'Applications/Mechanize.app' in path(target).parents))) or overlap(target,preserved['path']): raise ValueError('Runtime write set overlaps preserved extension or escapes root')
    for candidate in [plan['configCandidate']['path'],str(broker)]+[a['candidate'] for a in artifacts]:
        if overlap(candidate,preserved['path']): raise ValueError('Candidate overlaps preserved extension')
    ref(plan['configCandidate']);path(plan['newSourceRoot'])
    plan['runtime']={k:runtime[k] for k in (*RUNTIME_KEYS,*optional)};plan['readiness']=readiness
    plan={k:plan[k] for k in PLAN_KEYS}
    observer=closed(copy.deepcopy(review['observer']),('port','brokerPID','brokerStart','brokerRequirement','credentialURL','credentialSHA256','windowTitle','chromePID','chromeStart','consentBinding'))
    for k in ('brokerPID','chromePID'):
        if type(observer[k])!=int or not 0<observer[k]<=2**31-1: raise ValueError('Reviewed process ID required')
    if type(observer['port'])!=int or not 0<observer['port']<=65535 or observer['brokerRequirement']!=enrollment['oldRequirement']: raise ValueError('Observer broker binding mismatch')
    for k in ('brokerStart','chromeStart'):
        if not re.fullmatch(r'[1-9][0-9]*:(?:0|[1-9][0-9]{0,5})',observer[k]): raise ValueError('Canonical process birth required')
    binding=observer['consentBinding'];closed(binding,('sessionID','purpose',*(['grantID'] if isinstance(binding,dict) and 'grantID' in binding else [])))
    for value in binding.values():
        text(value)
        if len(value.encode())>1024:raise ValueError('Observer consent binding too long')
    path(observer['credentialURL']);digest(observer['credentialSHA256']);text(observer['windowTitle'])
    return plan,enrollment,observer

def write_private(p,raw):
    external(p);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def worker(enrollment,destination,identity):
    spec=importlib.util.spec_from_file_location('custody_build',ROOT/'scripts/build-custody-migration.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    expected_enrollment=sha(base64.b64decode(module.encode_enrollment(enrollment)))
    payload=destination.parent/(destination.name+'-enrollment.json');write_private(payload,wire(enrollment))
    args=[sys.executable,str(ROOT/'scripts/build-custody-migration.py'),'--enrollment',str(payload),'--output-directory',str(destination)]
    if identity:args+=['--signing-identity',identity]
    child(args,destination.parent)
    m=decode(read_file(destination/'manifest.json',private=True))
    expected={'schemaVersion','executable','requirement','sha256','enrollmentSHA256','installationPerformed','migrationPerformed'}
    closed(m,expected)
    if m['schemaVersion']!=1 or m['installationPerformed'] is not False or m['migrationPerformed'] is not False: raise ValueError('Worker build receipt invalid')
    # Existing builder owns Go enrollment ordering and escaping.
    if m['enrollmentSHA256']!=expected_enrollment or sha(read_file(m['executable'],512*1024*1024))!=digest(m['sha256']): raise ValueError('Worker build binding mismatch')
    if physical(m['executable'])!=destination/'mechanize-custody-migration':raise ValueError('Unexpected worker destination')
    requirement(m['requirement'],'custody-migration');verify_artifact(m['executable'],m['requirement'],destination.parent)
    return {k:m[k] for k in ('executable','requirement','sha256')}

def package(review_path,output,private_key,identity=None):
    output=external(output);parent=output.parent.stat()
    if parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700: raise ValueError('Private external parent required')
    output.mkdir(mode=0o700)
    review=decode(read_file(review_path,private=True));reference=ref(review.get('stagedManifest'))
    raw=read_file(reference['path'],private=True)
    if sha(raw)!=reference['sha256']:raise ValueError('Reviewed build manifest digest mismatch')
    manifest=decode(raw)
    plan,enrollment,observer=assemble_plan(review,manifest,verify_artifact,output)
    plan_raw=wire(plan)
    if len(plan_raw)>1_048_576:raise ValueError('Plan size bound')
    plan_path=output/'install-plan.json';write_private(plan_path,plan_raw)
    installer_enrollment=copy.deepcopy(enrollment);installer_enrollment['installPlan']={'path':str(plan_path),'sha256':sha(plan_raw)}
    installer=worker(installer_enrollment,output/'installer',identity)
    preparation_enrollment=copy.deepcopy(enrollment);preparation_enrollment['preparation']={'mutationExecutable':installer['executable'],'mutationRequirement':installer['requirement'],'mutationSHA256':installer['sha256'],'runtimeManifestSHA256':sha(plan_raw)}
    preparation=worker(preparation_enrollment,output/'preparation',identity)
    bootstrap={k:enrollment[k] for k in ('session','canonicalExecutable','oldRequirement','newRequirement','alias','service','account')}
    if 'newCanonicalExecutable' in enrollment:bootstrap['newCanonicalExecutable']=enrollment['newCanonicalExecutable']
    bootstrap['configSHA256']=enrollment['config']['sha256'];bootstrap['workerRequirement']=installer['requirement']
    payload={'version':1,'title':review['title'],'preparationWorker':preparation,'installerWorker':installer,'bootstrap':bootstrap,'installPlanBase64':base64.b64encode(plan_raw).decode(),'installPlanSHA256':sha(plan_raw),'observer':observer}
    raw=wire(payload)
    if len(raw)>2_000_000:raise ValueError('Package size bound')
    payload_path=output/'reviewed-package.json';write_private(payload_path,raw)
    # Final source artifacts must still match the reviewed output before signing.
    again,_,_=assemble_plan(review,manifest,verify_artifact,output)
    if wire(again)!=plan_raw:raise ValueError('Staged artifacts changed during worker builds')
    child([sys.executable,str(ROOT/'scripts/sign-runtime-upgrade-package.py'),'--payload',str(payload_path),'--private-key',str(external(private_key)),'--output',str(output/'signed-package.json')],output)
    envelope=closed(decode(read_file(output/'signed-package.json',private=True)),('version','payloadBase64','signatureBase64'))
    if type(envelope['version'])!=int or envelope['version']!=1 or base64.b64decode(envelope['payloadBase64'],validate=True)!=raw or len(base64.b64decode(envelope['signatureBase64'],validate=True))!=64:raise ValueError('Signed envelope output mismatch')
    return {'packageAssembled':True,'packageSHA256':sha(raw),'installationPerformed':False,'approvalGranted':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--review',required=True,type=Path);parser.add_argument('--output-directory',required=True,type=Path);parser.add_argument('--private-key',required=True,type=Path);parser.add_argument('--signing-identity')
    args=parser.parse_args();print(json.dumps(package(args.review,args.output_directory,args.private_key,args.signing_identity)))

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Runtime package assembly failed; private diagnostics withheld') from None
