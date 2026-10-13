#!/usr/bin/env python3
"""Generate a private reviewed upgrade proposal from unchanged local metadata.

Never installs, signs a package, loads Keychain/Vault entries, or prints resource
contents. Verifier files are streamed only into SHA256, never decoded as keys.
"""
import argparse
import copy
import ctypes
import hashlib
import grp
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_package',ROOT/'scripts/package-runtime-upgrade.py')
package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
GOOGLE_SIGNER=package.GOOGLE_CHROME_REQUIREMENT
INPUT_KEYS=('version','title','installationRoot','stagedManifest','approvalConsole','processes','extension','observerCredential','consentBinding','keychain','identity','launchdPath')
CONFIG_KEYS={'sourceRoot','storageRoot','nativeHelper','keys','identityPolicy','stdioCredential','users','chrome','maxUsers','nativeConsole','nativeLaunch','nativeVault','keychain','artifacts','chromeRetirement','nativeEffectReconciliation'}
RESOURCE_KEYS={'name','url','key','maxretry','timeoutms','fallback','data'}

def ci(value,name,default=None):
    if not isinstance(value,dict):raise ValueError('Typed configuration metadata required')
    keys=[key for key in value if key.lower()==name.lower()]
    if len(keys)>1:raise ValueError('Ambiguous configuration key')
    return value[keys[0]] if keys else default

def owned_directory(value):
    p=package.physical(value);s=p.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('Private owned directory required')
    return p

def hash_private(value):
    p=package.physical(value);owned_directory(p.parent)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);buffer=bytearray(65536);digest=hashlib.sha256()
    try:
        with os.fdopen(fd,'rb',buffering=0) as f:
            before=os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=1_048_576:raise ValueError('Bounded private resource required')
            total=0
            while True:
                n=f.readinto(buffer)
                if not n:break
                total+=n
                if total>1_048_576:raise ValueError('Resource bound exceeded')
                digest.update(memoryview(buffer)[:n]);buffer[:n]=bytes(n)
            after=os.fstat(f.fileno());entry=p.lstat()
            if total!=before.st_size or identity(before)!=identity(after) or (before.st_dev,before.st_ino)!=(entry.st_dev,entry.st_ino):raise ValueError('Resource changed during fingerprint')
    finally:buffer[:]=bytes(len(buffer))
    return {'path':str(p),'sha256':digest.hexdigest()}

def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def resource_metadata(value,verifier=False):
    if not isinstance(value,dict) or set(k.lower() for k in value)-RESOURCE_KEYS:raise ValueError('Closed resource reference required')
    for key in value:ci(value,key)
    if ci(value,'Data') not in (None,'') or ci(value,'Fallback') is not None:raise ValueError('Inline/fallback resources are not metadata')
    url=package.text(ci(value,'URL'));key=ci(value,'Key','')
    if not isinstance(key,str) or verifier and key:raise ValueError('Encrypted verifier resource unsupported')
    if key and not re.match(r'^[a-z][a-z0-9+.-]*://',key):raise ValueError('Inline encryption key unsupported')
    if verifier:package.path(url)
    return url

def verifier_resources(config):
    keys=config.get('keys');allowed={'hmac','rsa','rules','certurl'}
    if not isinstance(keys,dict) or set(k.lower() for k in keys)-allowed or ci(keys,'CertURL',''):raise ValueError('Local verifier configuration required')
    resources=[]
    def collect(rule):
        if not isinstance(rule,dict):raise ValueError('Verifier rule required')
        rsa=ci(rule,'RSA',[]) or []
        if not isinstance(rsa,list):raise ValueError('Verifier RSA list required')
        resources.extend(rsa)
        hmac=ci(rule,'HMAC')
        if hmac is not None:resources.append(hmac)
    collect(keys);rules=ci(keys,'Rules',[]) or []
    if not isinstance(rules,list):raise ValueError('Verifier rules list required')
    for rule in rules:
        if not isinstance(rule,dict) or set(k.lower() for k in rule)-{'resource','algorithm','rsa','hmac'}:raise ValueError('Closed verifier rule required')
        collect(rule)
    paths=sorted(set(resource_metadata(r,True) for r in resources))
    if not 1<=len(paths)<=16:raise ValueError('One to sixteen exact verifier resources required')
    return [hash_private(path) for path in paths]

def validate_config_metadata(config):
    if not isinstance(config,dict) or set(config)-CONFIG_KEYS:raise ValueError('Closed host configuration required')
    if config.get('stdioCredential') is not None:resource_metadata(config['stdioCredential'])
    artifacts=config.get('artifacts',{}).get('keyResources',{})
    if not isinstance(artifacts,dict):raise ValueError('Artifact key references required')
    for resource in artifacts.values():resource_metadata(resource)
    chrome=config.get('chrome')
    if not isinstance(chrome,dict) or chrome.get('fixtureEnrollment') is True or not isinstance(chrome.get('grants'),list):raise ValueError('Production Chrome enrollment required')
    for grant in chrome['grants']:resource_metadata(grant.get('credentialResource'))
    for key in ('nativeVault','nativeLaunch','nativeConsole','identityPolicy','keychain'):
        if not isinstance(config.get(key),dict):raise ValueError('Required original configuration missing')
    def fields(value,allowed):
        if not isinstance(value,dict) or set(value)-set(allowed):raise ValueError('Unknown typed configuration field')
    fields(config['identityPolicy'],('clients','issuer','audience','algorithms','requiredScopes','tenantClaim'))
    fields(config['nativeLaunch'],('windowFrameClick','sessionKeyboard','sessionText','targetedKeyboard','mode','lockPath','helperRequirement','expectedUID','transport'))
    if config['nativeLaunch'].get('transport','') not in ('','console-v1'):raise ValueError('Unsupported native helper transport')
    fields(chrome,('socketPath','fixtureEnrollment','grants','processTrust'))
    fields(chrome.get('processTrust'),('expectedUID','nativeHostExecutable','nativeHostRequirement','chromeExecutable','chromeRequirement','maximumAncestors'))
    for grant in chrome['grants']:
        fields(grant,('allWebsites','trustScope','principal','profileChannel','browserInstance','extensionOrigin','origins','credentialResource','profileDirectory'))
        if 'principal' in grant:fields(grant['principal'],('issuer','subject','tenant','scopes','namespace','clientId','clientName'))
    for user in config.get('users',[]):fields(user,('desktopAccess','recordingAllowed','subject','tenant','nativeBundles','webOrigins','valueIdentifiers','staticTextBundles'))
    if set(k.lower() for k in config['keychain'])!={'items'}:raise ValueError('Closed Keychain metadata required')
    for item in ci(config['keychain'],'Items',{}).values():
        if not isinstance(item,dict) or set(k.lower() for k in item)!={'service','account'}:raise ValueError('Closed master item metadata required')
    if 'artifacts' in config:fields(config['artifacts'],('sourceKeyReference','keyResources','maxBytes','namespaceQuotaBytes'))
    if 'chromeRetirement' in config:fields(config['chromeRetirement'],('brokerRequirement',))
    # These closed routing records cannot carry an inline credential payload.
    for key,allowed in {'nativeVault':{'root','recordRoot','keyVersion','keyAlias','brokerRequirement','windowProtection'},'nativeConsole':{'socketPath','designatedRequirement','expectedUID'}}.items():
        if set(config[key])-allowed:raise ValueError('Unknown protected routing field')
    if config['nativeVault'].get('windowProtection','') not in ('','helper-v1'):raise ValueError('Unsupported native window protection')

def derived_identity(config,selected):
    selected=package.closed(selected,('subject','tenant','clientID'));policy=config['identityPolicy']
    for key in selected:
        if key!='tenant' or selected[key]:package.text(selected[key])
    if selected['clientID'] not in policy.get('clients',{}):raise ValueError('Client is not enrolled')
    matches=[u for u in config.get('users',[]) if u.get('subject')==selected['subject'] and u.get('tenant','')==selected['tenant']]
    if len(matches)!=1:raise ValueError('Exact configured user required')
    issuer=package.text(policy.get('issuer'));package.text(policy.get('audience'))
    if not policy.get('algorithms') or 'none' in policy['algorithms']:raise ValueError('Existing signed identity policy required')
    return package.sha(package.wire(['mechanize.identity.v1',issuer.strip(),selected['tenant'].strip(),selected['subject'].strip()]))

class BSDInfo(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint32) for name in ('flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved')]+[('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(name,ctypes.c_uint32) for name in ('nfiles','pgid','jobc','tdev','tpgid')]+[('nice',ctypes.c_int32),('seconds',ctypes.c_uint64),('microseconds',ctypes.c_uint64)]

def inspect_process(pid):
    if sys.platform!='darwin' or type(pid)!=int or not 0<pid<2**31:raise ValueError('macOS process reference required')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib');info=BSDInfo();path=ctypes.create_string_buffer(4096)
    if lib.proc_pidinfo(pid,3,ctypes.c_uint64(0),ctypes.byref(info),ctypes.sizeof(info))!=ctypes.sizeof(info) or lib.proc_pidpath(pid,path,len(path))<=0 or info.pid!=pid or info.status==5:raise ValueError('Process identity unavailable')
    return {'pid':pid,'uid':int(info.uid),'start':str(info.seconds)+':'+str(info.microseconds),'executable':os.fsdecode(path.value)}

def check_process(reference,canonical,requirement,work,inspect,verify,chrome=False,google=False):
    reference=package.closed(reference,('pid','start'))
    if type(reference['pid'])!=int or not 0<reference['pid']<2**31 or not re.fullmatch(r'[1-9][0-9]*:(?:0|[1-9][0-9]{0,5})',reference['start']):raise ValueError('Canonical PID/birth reference required')
    before=inspect(reference['pid']);actual=package.physical(before['executable']);canonical=package.physical(canonical)
    if before['uid']!=os.getuid() or before['start']!=reference['start']:raise ValueError('Process reference changed')
    a,b=canonical.lstat(),actual.lstat()
    if chrome:
        if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino) or a.st_uid not in (0,os.getuid()) or not stat.S_ISREG(a.st_mode) or a.st_mode&0o7002 or not a.st_mode&0o111:raise ValueError('Chrome main image physical identity mismatch')
    elif actual!=canonical or a.st_nlink!=1:raise ValueError('Canonical runtime executable required')
    if chrome and a.st_mode&0o020:
        if sys.platform!='darwin' or a.st_gid!=grp.getgrnam('admin').gr_gid:raise ValueError('Chrome writable group is not privileged admin')
    if chrome and (google or a.st_mode&0o020):verify(canonical,GOOGLE_SIGNER,work)
    verify(canonical,requirement,work)
    if inspect(reference['pid'])!=before or identity(a)!=identity(canonical.lstat()) or identity(b)!=identity(actual.lstat()):raise ValueError('Process/image changed during review')
    return before

def pin_from_signature(value,role,work):
    import subprocess
    path=package.physical(value)
    architectures=[None]
    if role=='google-chrome':
        result=subprocess.run(['lipo','-archs',str(path)],cwd=work,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
        architectures=result.stdout.decode('ascii').split()
        if result.returncode or not 1<=len(architectures)<=4 or len(set(architectures))!=len(architectures) or any(a not in ('arm64','arm64e','x86_64') for a in architectures):raise ValueError('Complete signed Chrome architecture inventory unavailable')
    hashes=[]
    for architecture in architectures:
        command=['codesign','--display','--verbose=4']+(['--arch',architecture] if architecture else [])+[str(path)]
        result=subprocess.run(command,cwd=work,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
        match=re.search(rb'^CDHash=([a-fA-F0-9]{40})$',result.stderr,re.M)
        if result.returncode or not match:raise ValueError('Signed architecture identity unavailable')
        hashes.append(match[1].decode().lower())
    hashes=sorted(set(hashes));clauses=['cdhash H"'+value+'"' for value in hashes]
    identifier='com.google.Chrome' if role=='google-chrome' else 'com.viant.mechanize.'+role
    pin='identifier "'+identifier+'" and '+(clauses[0] if len(clauses)==1 else '('+' or '.join(clauses)+')')
    if role=='google-chrome':package.chrome_requirement(pin)
    package.verify_artifact(path,pin,work);return pin

def launchd_metadata(path,broker,config):
    owned_directory(package.physical(path).parent)
    raw=package.read_file(path,1_048_576,private=True)
    if not raw.lstrip().startswith(b'<?xml'):raise ValueError('Frozen XML launchd definition required')
    value=plistlib.loads(raw);args=value.get('ProgramArguments',[])
    if not re.fullmatch(r'com\.viant\.mechanize\.[a-z0-9.-]+',value.get('Label','')) or 'Program' in value or value.get('KeepAlive',False) is not False or len(args)!=6 or args[:5]!=[str(broker),'serve','-config',str(config),'-listen']:raise ValueError('Exact original launchd definition required')
    listen=package.text(args[5])
    if not re.fullmatch(r'(?:127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}',listen) or int(listen.rsplit(':',1)[1])>65535:raise ValueError('Local listener required')
    return {'path':str(package.physical(path)),'sha256':package.sha(raw)},listen

def candidate_config(original,manifest,source_root,root):
    result=copy.deepcopy(original);result['sourceRoot']=str(source_root);result['nativeHelper']=str(root/'mechanize-native');result['nativeLaunch']['helperRequirement']=manifest['helperRequirement'];result['nativeConsole']['designatedRequirement']=manifest['consoleRequirement'];result['nativeVault']['brokerRequirement']=manifest['brokerRequirement']
    if 'chromeRetirement' in result:result['chromeRetirement']['brokerRequirement']=manifest['brokerRequirement']
    result['chrome']['processTrust']['nativeHostRequirement']=manifest['nativeHostRequirement']
    return result

def prepare(inputs,output,inspect=inspect_process,verify=package.verify_artifact,pin=pin_from_signature):
    optional=tuple(k for k in ('chromeRecovery','enableRecordStore','unifiedManifest','unifiedLaunchdPath','preinstalledUnifiedApp','preinstalledApprovalConsole','samePathUnifiedUpdate') if k in inputs)
    inputs=package.closed(inputs,(*INPUT_KEYS,*optional))
    update=inputs.get('samePathUnifiedUpdate',False)
    if update is not False and update is not True:raise ValueError('Explicit same-path update choice required')
    if update and ('unifiedManifest' not in inputs or inputs.get('preinstalledUnifiedApp') or inputs.get('preinstalledApprovalConsole')):raise ValueError('Same-path replacement needs a separate candidate')
    if ('unifiedManifest' in inputs)!=('unifiedLaunchdPath' in inputs):raise ValueError('Unified stage and reviewed relocated launchd resource both required')
    if 'preinstalledApprovalConsole' in inputs and (inputs['preinstalledApprovalConsole'] is not True or inputs.get('preinstalledUnifiedApp') is not True):raise ValueError('Explicit preinstalled approving console required')
    if 'preinstalledUnifiedApp' in inputs and (inputs['preinstalledUnifiedApp'] is not True or 'unifiedManifest' not in inputs):raise ValueError('Explicit unified preinstallation required')
    if 'enableRecordStore' in inputs and type(inputs['enableRecordStore'])!=bool:raise ValueError('Explicit record-store routing choice required')
    if type(inputs['version'])!=int or inputs['version']!=1:raise ValueError('Review input version required')
    output=package.external(output);owned_directory(output.parent);root=owned_directory(inputs['installationRoot']);output.mkdir(mode=0o700)
    config_path=root/'config.json';config_raw=package.read_file(config_path,1_048_576,private=True);current=package.decode(config_raw);config=current;recovery=None
    def sorted_maps(value):return {k:sorted_maps(value[k]) for k in sorted(value)} if isinstance(value,dict) else [sorted_maps(x) for x in value] if isinstance(value,list) else value
    if 'chromeRecovery' in inputs:
        original_ref=package.ref(inputs['chromeRecovery']);retained_raw=package.read_file(original_ref['path'],1_048_576,private=True)
        if package.sha(retained_raw)!=original_ref['sha256'] or original_ref['path']==str(config_path):raise ValueError('Retained configuration reference mismatch')
        retained=package.decode(retained_raw);without=copy.deepcopy(retained);chrome=without.pop('chrome',None)
        if not isinstance(chrome,dict) or 'chrome' in current or package.wire(sorted_maps(without))!=package.wire(sorted_maps(current)):raise ValueError('Recovery must differ only by disabled Chrome')
        config=copy.deepcopy(current);config['chrome']=chrome
        recovery={'originalConfig':original_ref,'originalChromeSHA256':package.sha(package.wire(sorted_maps(chrome)))}
    validate_config_metadata(config)
    reference=package.ref(inputs['stagedManifest']);manifest_raw=package.read_file(reference['path'],private=True)
    if package.sha(manifest_raw)!=reference['sha256']:raise ValueError('Staged manifest changed')
    manifest=package.decode(manifest_raw);source=package.physical(manifest['sourceRoot'])
    namespace=derived_identity(config,inputs['identity']);item=package.closed(inputs['keychain'],('alias','service','account'))
    for value in item.values():package.text(value)
    enrolled_item=ci(config['keychain'],'Items',{}).get(item['alias'])
    if not isinstance(enrolled_item,dict) or ci(enrolled_item,'Service')!=item['service'] or ci(enrolled_item,'Account')!=item['account'] or config['nativeVault']['keyAlias']!=item['alias']:raise ValueError('Existing master item metadata mismatch')
    approval=package.closed(inputs['approvalConsole'],('path','requirement'));package.requirement(approval['requirement'],'consent')
    compatibility=inputs.get('preinstalledApprovalConsole',False)
    old_console_requirement=config['nativeConsole']['designatedRequirement'];package.requirement(old_console_requirement,'consent')
    if config['nativeConsole']['expectedUID']!=os.getuid():raise ValueError('Original console owner mismatch')
    old_broker=config['nativeVault']['brokerRequirement'];package.requirement(old_broker,'broker')
    console=Path.home()/'Applications/Mechanize.app' if update else root/'Mechanize Permissions.app';broker=console/'Contents/Helpers/mechanize' if update else root/'mechanize';approval_path=package.physical(approval['path'])
    verify(approval_path,approval['requirement'],output);verify(console,old_console_requirement,output)
    if compatibility:
        unified,_=package.unified_manifest(inputs['unifiedManifest'],manifest,verify,output)
        if approval_path!=Path.home()/'Applications/Mechanize.app' or approval['requirement']!=unified['consoleRequirement'] or package.inventory(approval_path)!=package.ordered_inventory(unified['inventory']):raise ValueError('Approving console differs from preinstalled reviewed bundle')
    elif old_console_requirement!=approval['requirement'] or package.inventory(approval_path)!=package.inventory(console):raise ValueError('Approval console must match current enrollment')
    console_main=(approval_path if compatibility else console)/'Contents/MacOS/MechanizeConsent'
    processes=package.closed(inputs['processes'],('broker','console','chrome'));trust=config['chrome']['processTrust']
    if trust.get('expectedUID')!=os.getuid() or trust.get('nativeHostExecutable')!=str(broker.parent/'mechanize-native-host'):raise ValueError('Original Chrome trust path/owner mismatch')
    chrome_requirement=trust['chromeRequirement']
    if recovery:
        verify(trust['chromeExecutable'],GOOGLE_SIGNER,output)
        # Exact CDHash is read only after independent vendor validation.
        current_pin=pin(trust['chromeExecutable'],'google-chrome',output)
        package.chrome_requirement(current_pin)
        chrome_requirement=GOOGLE_SIGNER if chrome_requirement==GOOGLE_SIGNER else current_pin
        package.chrome_requirement(chrome_requirement)
    observed={}
    for role,executable,requirement in [('broker',broker,old_broker),('console',console_main,approval['requirement']),('chrome',trust['chromeExecutable'],chrome_requirement)]:observed[role]=check_process(processes[role],executable,requirement,output,inspect,verify,role=='chrome',bool(recovery) and role=='chrome')
    old_hash=package.sha(package.read_file(broker,512*1024*1024));active=package.physical(config['nativeHelper']);verify(active,config['nativeLaunch']['helperRequirement'],output);active_hash=package.sha(package.read_file(active,512*1024*1024))
    resources=verifier_resources(config)
    extension=inputs['extension'];package.closed(extension,('path','extensionID','windowTitle',*(['runtimeResourcesOnly'] if 'runtimeResourcesOnly' in extension else [])))
    if 'runtimeResourcesOnly' in extension and extension['runtimeResourcesOnly'] is not True:raise ValueError('Explicit runtime-only preservation required')
    ext_path=package.physical(extension['path']);package.text(extension['windowTitle'])
    if not re.fullmatch('[a-p]{32}',extension['extensionID']) or not any(g.get('extensionOrigin')=='chrome-extension://'+extension['extensionID']+'/' for g in config['chrome']['grants']):raise ValueError('Extension ID is not enrolled')
    import extension_package
    runtime_only=extension.get('runtimeResourcesOnly',False)
    inventory_reader=package.runtime_resources_inventory if runtime_only else package.inventory
    inventory=inventory_reader(ext_path);public={'files':{n:e['sha256'] for n,e in inventory.items() if n!='.'}}
    if not runtime_only:extension_package.inventory(ext_path,allow_legacy=True)
    key=extension_package.identity(ext_path)
    if key:
        import base64
        encoded=hashlib.sha256(base64.b64decode(key,validate=True)).hexdigest()[:32];computed=''.join(chr(ord('a')+int(x,16)) for x in encoded)
        if computed!=extension['extensionID']:raise ValueError('Extension public key identity mismatch')
    artifacts=[]
    for role,filename,identifier in [('helper','mechanize-native','native'),('native-host','mechanize-native-host','chrome.nativehost'),('console','Mechanize Permissions.app','consent')]:
        target=console if update and role=='console' else broker.parent/filename;old=package.inventory(target);requirement=pin(target,identifier,output)
        if role=='console' and requirement!=old_console_requirement:raise ValueError('Old console pin changed')
        if role=='native-host' and requirement!=trust['nativeHostRequirement']:raise ValueError('Old native-host pin differs from frozen config')
        artifacts.append({'role':role,'target':str(target),'Old':old,'OldDigest':package.sha(package.wire(old)),'OldRequirement':requirement})
    launchd,listen=launchd_metadata(inputs['launchdPath'],broker,config_path)
    if 'unifiedManifest' in inputs:
        launchd,relocated_listen=launchd_metadata(inputs['unifiedLaunchdPath'],Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize',config_path)
        if relocated_listen!=listen:raise ValueError('Relocation listener must remain unchanged')
    observer=package.ref(inputs['observerCredential'])
    if hash_private(observer['path'])!=observer:raise ValueError('Observer credential reference changed')
    session=secrets.token_hex(32);suffix=session[:16]
    candidate_manifest=manifest
    if 'unifiedManifest' in inputs:
        _,candidate_manifest=package.unified_manifest(inputs['unifiedManifest'],manifest,verify,output)
    if update:
        original_info=plistlib.loads(package.read_file(console/'Contents/Info.plist'))
        next_info=plistlib.loads(package.read_file(Path(candidate_manifest['console'])/'Contents/Info.plist'))
        if not original_info.get('MechanizeEnrollmentAccount') or not next_info.get('MechanizeEnrollmentAccount') or next_info.get('MechanizeEnrollmentAccount')==original_info.get('MechanizeEnrollmentAccount'):raise ValueError('Fresh candidate console enrollment required')
    candidate=candidate_config(config,candidate_manifest,source,root)
    if 'unifiedManifest' in inputs:
        destination=Path.home()/'Applications/Mechanize.app/Contents/Helpers'
        candidate['nativeHelper']=str(destination/'mechanize-native')
        candidate['chrome']['processTrust']['nativeHostExecutable']=str(destination/'mechanize-native-host')
    if recovery:candidate['chrome']['processTrust']['chromeRequirement']=chrome_requirement
    record_root=None
    if inputs.get('enableRecordStore'):
        if config['nativeVault'].get('recordRoot') not in (None,'') or config['nativeVault']['root']!=str(Path.home()/'.secret/vault'):raise ValueError('Only previously absent native record-store routing may be added')
        record_root=str(Path.home()/'.secret/vault-records');candidate['nativeVault']['recordRoot']=record_root
    candidate_path=output/'candidate-config.json';candidate_raw=package.wire(candidate)
    package.write_private(candidate_path,candidate_raw)
    enrollment={'version':1,'session':session,'config':{'path':str(config_path),'sha256':package.sha(config_raw)},'resources':resources,'consoleRequirement':approval['requirement'],'expectedUID':os.getuid(),'namespace':namespace,'clientID':inputs['identity']['clientID'],'canonicalExecutable':str(broker),'oldRequirement':old_broker,'newRequirement':manifest['brokerRequirement'],**item,'journalRoot':str(root/'.secret/mechanize-custody-migration')}
    runtime={'BrokerPath':str(broker),'OldBrokerRequirement':old_broker,'ActiveHelperPath':str(active),'ActiveHelperRequirement':config['nativeLaunch']['helperRequirement'],'ActiveHelperSHA256':active_hash,'ChromeExecutable':trust['chromeExecutable'],'ExtensionID':extension['extensionID'],'OldConsoleBirth':observed['console']['start'],'Artifacts':artifacts,'Mode':'preserve-extension-v1','PreservedExtension':{'path':str(ext_path),'extensionID':extension['extensionID'],'inventory':inventory,'inventorySHA256':package.sha(package.wire(inventory))},'ChromeRequirement':chrome_requirement}
    if runtime_only:runtime['PreservedExtension']['runtimeResourcesOnly']=True
    if recovery:runtime['ChromeRecovery']=recovery
    if record_root:runtime['NativeRecordRoot']=record_root
    plan={'version':1,'oldBrokerSHA256':old_hash,'configCandidate':{'path':str(candidate_path),'sha256':package.sha(candidate_raw)},'backup':str(root/('broker-backup-'+suffix)),'stageJournalRoot':str(root/'.secret/mechanize-runtime-staging'),'artifactJournalRoot':str(root/'.secret/mechanize-runtime-artifacts'),'newSourceRoot':str(source),'runtime':runtime,'readiness':{'launchd':launchd,'listen':listen}}
    review={'version':1,'title':inputs['title'],'stagedManifest':reference,'enrollment':enrollment,'installPlan':plan,'observer':{'port':int(listen.rsplit(':',1)[1]),'brokerPID':observed['broker']['pid'],'brokerStart':observed['broker']['start'],'brokerRequirement':old_broker,'credentialURL':observer['path'],'credentialSHA256':observer['sha256'],'windowTitle':extension['windowTitle'],'chromePID':observed['chrome']['pid'],'chromeStart':observed['chrome']['start'],'consentBinding':copy.deepcopy(inputs['consentBinding'])}}
    if 'unifiedManifest' in inputs:review['unifiedManifest']=copy.deepcopy(inputs['unifiedManifest'])
    if update:review['samePathUnifiedUpdate']=True
    if inputs.get('preinstalledUnifiedApp'):review['preinstalledUnifiedApp']=True
    if compatibility:review['preinstalledApprovalConsole']=True
    package.assemble_plan(review,manifest,verify,output)
    if package.read_file(config_path,1_048_576,private=True)!=config_raw or verifier_resources(config)!=resources or hash_private(observer['path'])!=observer:raise ValueError('Original metadata/resources changed during review')
    for role,executable,requirement in [('broker',broker,old_broker),('console',console_main,approval['requirement']),('chrome',trust['chromeExecutable'],chrome_requirement)]:
        if check_process(processes[role],executable,requirement,output,inspect,verify,role=='chrome',bool(recovery) and role=='chrome')!=observed[role]:raise ValueError('Reviewed process changed')
    for artifact in artifacts:
        if package.inventory(artifact['target'])!=artifact['Old']:raise ValueError('Original artifact changed')
    if inventory_reader(ext_path)!=inventory:raise ValueError('Preserved extension changed')
    package.write_private(output/'review.json',package.wire(review))
    summary={'reviewPrepared':True,'metadataOnly':True,'originalConfigUnchanged':True,'verifierResourceCount':len(resources),'oldArtifactsSnapshotted':3,'preservedExtensionFileCount':len(public['files']),'processReferencesMatched':True,'runtimeReady':False,'nativeApprovalGranted':False,'installedFilesChanged':False,'vaultContentsLoaded':False,'keychainAccessed':False,'chromeRecoveryReviewed':recovery is not None,'recordStoreEnabledInCandidate':record_root is not None}
    package.write_private(output/'readiness.json',package.wire(summary));return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output-directory',type=Path,required=True);args=parser.parse_args()
    inputs=package.decode(package.read_file(args.input,1_048_576,private=True));print(json.dumps(prepare(inputs,args.output_directory)))

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Upgrade review preparation failed; private diagnostics withheld') from None
