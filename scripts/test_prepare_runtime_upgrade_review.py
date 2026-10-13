import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).parent))
import test_package_runtime_upgrade as producer_test
import extension_package
spec=importlib.util.spec_from_file_location('prepare_review',Path(__file__).with_name('prepare-runtime-upgrade-review.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
p=helper.package
pin=producer_test.pin

def private(path,data):path.write_bytes(data);path.chmod(0o600)

class PrepareReviewTests(unittest.TestCase):
    def test_native_console_transport_is_closed_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,inputs,config,manifest,processes=self.fixture(directory)
            config['nativeLaunch']['transport']='console-v1'
            config['nativeVault']['windowProtection']='helper-v1'
            private(root/'config.json',p.wire(config))
            helper.prepare(inputs,top/'review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:pin(role))
            candidate=json.loads((top/'review/candidate-config.json').read_bytes())
            self.assertEqual(candidate['nativeLaunch']['transport'],'console-v1')
            self.assertEqual(candidate['nativeVault']['windowProtection'],'helper-v1')
            for transport in ('arbitrary',None,True,{}):
                changed=copy.deepcopy(config);changed['nativeLaunch']['transport']=transport
                with self.assertRaises(ValueError):helper.validate_config_metadata(changed)
            for protection in ('arbitrary',None,True,{}):
                changed=copy.deepcopy(config);changed['nativeVault']['windowProtection']=protection
                with self.assertRaises(ValueError):helper.validate_config_metadata(changed)

    def test_same_path_unified_update_preserves_external_config_and_custody_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,inputs,config,manifest,processes=self.fixture(directory)
            with patch.object(Path,'home',return_value=top/'synthetic-home'):
                installed=Path.home()/'Applications/Mechanize.app'
                installed.parent.mkdir(parents=True,mode=0o700)
                shutil.copytree(root/'Mechanize Permissions.app',installed)
                helpers=installed/'Contents/Helpers';helpers.mkdir(mode=0o700)
                for name in ('mechanize','mechanize-native','mechanize-native-host'):shutil.copyfile(root/name,helpers/name);(helpers/name).chmod(0o700)
                config['nativeHelper']=str(helpers/'mechanize-native')
                config['chrome']['processTrust']['nativeHostExecutable']=str(helpers/'mechanize-native-host')
                private(root/'config.json',p.wire(config));before=(root/'config.json').read_bytes();old_info=plistlib.loads((installed/'Contents/Info.plist').read_bytes());old_info.update(CFBundleIdentifier='com.viant.mechanize.consent',MechanizeEnrollmentAccount='com.viant.mechanize.consent:fixture');private(installed/'Contents/Info.plist',plistlib.dumps(old_info));old_inventory=p.inventory(installed)
                inputs['approvalConsole']['path']=str(installed)
                processes[10]['executable']=str(helpers/'mechanize');processes[20]['executable']=str(installed/'Contents/MacOS/MechanizeConsent')
                job=plistlib.loads(Path(inputs['launchdPath']).read_bytes());job['ProgramArguments'][0]=str(helpers/'mechanize')
                private(Path(inputs['launchdPath']),plistlib.dumps(job))
                app=Path(manifest['console']);info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
                info.update(CFBundleIdentifier='com.viant.mechanize.consent',CFBundleExecutable='MechanizeConsent',MechanizeHelperRequirement=manifest['helperRequirement'],MechanizeEnrollmentAccount='com.viant.mechanize.consent:new-fixture')
                private(app/'Contents/Info.plist',plistlib.dumps(info));manifest.update(schemaVersion=1,installationPerformed=False)
                staged=Path(inputs['stagedManifest']['path']);private(staged,p.wire(manifest));inputs['stagedManifest']['sha256']=p.sha(staged.read_bytes())
                spec=importlib.util.spec_from_file_location('update_unified_fixture',Path(__file__).with_name('build-unified-app.py'));builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
                builder.build(staged,top/'unified',verify=lambda *a:None,signer=lambda *a:pin('consent','c'),installed_app=installed)
                unified=top/'unified/unified-manifest.json';inputs.update(unifiedManifest={'path':str(unified),'sha256':p.sha(unified.read_bytes())},unifiedLaunchdPath=inputs['launchdPath'],samePathUnifiedUpdate=True)
                helper.prepare(inputs,top/'review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:pin(role))
                review=json.loads((top/'review/review.json').read_bytes());plan,enrollment,_=p.assemble_plan(review,manifest,lambda *a:None,top)
                self.assertEqual(plan['version'],3);self.assertEqual(enrollment['version'],3);self.assertNotIn('newCanonicalExecutable',enrollment)
                self.assertEqual(plan['runtime']['Mode'],'unified-app-update-v3');self.assertEqual(plan['runtime']['Artifacts'][0]['Old'],old_inventory)
                self.assertEqual(enrollment['canonicalExecutable'],str(helpers/'mechanize'));self.assertEqual(enrollment['config']['path'],str(root/'config.json'))
                self.assertEqual((root/'config.json').read_bytes(),before);self.assertEqual(p.inventory(installed),old_inventory)
                candidate=json.loads((top/'review/candidate-config.json').read_bytes())
                for key in ('root','recordRoot','keyAlias','keyVersion'):self.assertEqual(candidate['nativeVault'][key],config['nativeVault'][key])
                self.assertEqual(candidate['keychain'],config['keychain']);self.assertEqual(candidate['chrome']['grants'],config['chrome']['grants'])
                bad=copy.deepcopy(review);bad['enrollment']['config']['path']=str(helpers/'config.json')
                with self.assertRaises(ValueError):p.assemble_plan(bad,manifest,lambda *a:None,top)
                bad=copy.deepcopy(review);bad['preinstalledUnifiedApp']=True
                with self.assertRaises(ValueError):p.assemble_plan(bad,manifest,lambda *a:None,top)

    def test_unified_review_changes_only_nested_paths_and_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,inputs,config,manifest,processes=self.fixture(directory)
            home_patch=patch.object(Path,'home',return_value=top/'synthetic-home');home_patch.start();self.addCleanup(home_patch.stop)
            app=Path(manifest['console']);info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
            info.update(CFBundleIdentifier='com.viant.mechanize.consent',CFBundleExecutable='MechanizeConsent',MechanizeHelperRequirement=manifest['helperRequirement'])
            private(app/'Contents/Info.plist',plistlib.dumps(info));manifest.update(schemaVersion=1,installationPerformed=False)
            stage_manifest=Path(inputs['stagedManifest']['path']);private(stage_manifest,p.wire(manifest));inputs['stagedManifest']['sha256']=p.sha(stage_manifest.read_bytes())
            spec=importlib.util.spec_from_file_location('unified_fixture',Path(__file__).with_name('build-unified-app.py'));builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
            builder.build(stage_manifest,top/'unified',verify=lambda *a:None,signer=lambda *a:pin('consent','c'))
            unified=top/'unified/unified-manifest.json';inputs['unifiedManifest']={'path':str(unified),'sha256':p.sha(unified.read_bytes())}
            job=plistlib.loads(Path(inputs['launchdPath']).read_bytes());job['ProgramArguments'][0]=str(Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize')
            private(top/'relocated.plist',plistlib.dumps(job));inputs['unifiedLaunchdPath']=str(top/'relocated.plist')
            helper.prepare(inputs,top/'review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:pin(role))
            candidate=json.loads((top/'review/candidate-config.json').read_bytes())
            self.assertEqual(candidate['nativeHelper'],str(Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize-native'))
            self.assertEqual(candidate['chrome']['processTrust']['nativeHostExecutable'],str(Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize-native-host'))
            self.assertEqual(candidate['nativeVault']['keyAlias'],config['nativeVault']['keyAlias'])
            self.assertEqual(candidate['chrome']['grants'],config['chrome']['grants'])
            review=json.loads((top/'review/review.json').read_bytes());plan,enrollment,_=p.assemble_plan(review,manifest,lambda *a:None,top)
            self.assertEqual(plan['version'],2);self.assertEqual(enrollment['version'],2)
            import shutil
            installed=Path.home()/'Applications/Mechanize.app';installed.parent.mkdir(parents=True,mode=0o700);shutil.copytree(top/'unified/Mechanize.app',installed)
            inputs['preinstalledUnifiedApp']=True;inputs['preinstalledApprovalConsole']=True
            inputs['approvalConsole']={'path':str(installed),'requirement':pin('consent','c')}
            processes[20]['executable']=str(installed/'Contents/MacOS/MechanizeConsent')
            helper.prepare(inputs,top/'approval-review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:pin(role))
            reviewed=json.loads((top/'approval-review/review.json').read_bytes());approved,enrolled,_=p.assemble_plan(reviewed,manifest,lambda *a:None,top)
            self.assertEqual(enrolled['consoleRequirement'],pin('consent','c'))
            self.assertEqual(enrolled['originalConsoleRequirement'],config['nativeConsole']['designatedRequirement'])
            self.assertEqual(approved['runtime']['OriginalConsoleArtifact']['requirement'],config['nativeConsole']['designatedRequirement'])
            compatibility=next(a for a in approved['runtime']['LegacyArtifacts'] if a['role']=='console')
            self.assertEqual(compatibility['target'],compatibility['candidate']);self.assertEqual(compatibility['OldRequirement'],pin('consent','c'))
            self.assertEqual(approved['runtime']['ApprovalConsole']['birth'],processes[20]['start'])


    def test_runtime_resources_only_never_traverses_extras(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,inputs,config,manifest,processes=self.fixture(directory)
            ext=Path(inputs['extension']['path']);(ext/'node_modules').mkdir();(ext/'node_modules'/'private').symlink_to('/does-not-exist')
            (ext/'README.md').write_text('not runtime')
            inputs['extension']['runtimeResourcesOnly']=True
            helper.prepare(inputs,top/'review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:pin(role))
            review=json.loads((top/'review/review.json').read_bytes());preserved=review['installPlan']['runtime']['PreservedExtension']
            self.assertIs(preserved['runtimeResourcesOnly'],True)
            self.assertEqual(set(preserved['inventory']),{'.',*extension_package.FILES})
            (ext/'content.js').unlink();(ext/'content.js').symlink_to(ext/'worker.js')
            with self.assertRaises(ValueError):p.runtime_resources_inventory(ext)

    def test_universal_chrome_pin_includes_every_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();image=root/'Chrome';image.write_bytes(b'fixture')
            calls=[]
            def run(args,**kwargs):
                calls.append(args)
                if args[0]=='lipo':return SimpleNamespace(returncode=0,stdout=b'x86_64 arm64',stderr=b'')
                value=b'a'*40 if args[args.index('--arch')+1]=='arm64' else b'b'*40
                return SimpleNamespace(returncode=0,stdout=b'',stderr=b'CDHash='+value+b'\n')
            with patch('subprocess.run',side_effect=run),patch.object(p,'verify_artifact') as verify:
                result=helper.pin_from_signature(image,'google-chrome',root)
                self.assertEqual(result,'identifier "com.google.Chrome" and (cdhash H"'+'a'*40+'" or cdhash H"'+'b'*40+'")')
                verify.assert_called_once_with(image,result,root)
            self.assertEqual(len(calls),3)

    def fixture(self,directory):
        top=Path(directory).resolve();top.chmod(0o700);root=top/'installed';root.mkdir(mode=0o700)
        stage=top/'stage';_,manifest=producer_test.PackageTests().fixture(stage)
        manifest['sourceRoot']=str(Path(__file__).resolve().parents[1]);private(stage/'manifest.json',p.wire(manifest))
        for name in ('mechanize','mechanize-native','mechanize-native-host','Chrome'):
            file=root/name;file.write_bytes(('old public '+name).encode());file.chmod(0o700)
        app=root/'Mechanize Permissions.app';(app/'Contents/MacOS').mkdir(parents=True,mode=0o700);app.chmod(0o700);(app/'Contents').chmod(0o700)
        main=app/'Contents/MacOS/MechanizeConsent';main.write_bytes(b'old public console');main.chmod(0o700)
        private(app/'Contents/Info.plist',plistlib.dumps({'MechanizeBrokerRequirement':pin('broker')}))
        credentials=root/'credentials';credentials.mkdir(mode=0o700);private(credentials/'verifier',b'SYNTHETIC-KEY-CANARY');private(credentials/'observer',b'SYNTHETIC-TOKEN-CANARY')
        extension=root/'extension';extension.mkdir(mode=0o700)
        for name in extension_package.FILES:private(extension/name,('// public '+name).encode())
        private(extension/'manifest.json',p.wire({'manifest_version':3,'background':{'service_worker':'worker.js','type':'module'},'options_page':'options.html'}))
        config={'sourceRoot':'/original/source','storageRoot':'/never-read/storage','nativeHelper':str(root/'mechanize-native'),'keys':{'HMAC':{'URL':str(credentials/'verifier')}},'identityPolicy':{'issuer':'fixture-issuer','audience':'fixture-audience','algorithms':['HS256'],'clients':{'console-client':'Fixture console'}},'stdioCredential':{'URL':str(credentials/'observer')},'users':[{'subject':'fixture-user','tenant':'','desktopAccess':True,'nativeBundles':[],'webOrigins':[]}],'nativeConsole':{'socketPath':str(root/'consent.sock'),'designatedRequirement':pin('consent'),'expectedUID':os.getuid()},'nativeLaunch':{'mode':'semantic','helperRequirement':pin('native'),'expectedUID':os.getuid(),'lockPath':str(root/'control.lock')},'nativeVault':{'root':'/never-read/vault','recordRoot':'/never-read/records','keyVersion':'fixture-v1','keyAlias':'master','brokerRequirement':pin('broker')},'keychain':{'Items':{'master':{'Service':'fixture-service','Account':'fixture-account'}}},'chromeRetirement':{'brokerRequirement':pin('broker')},'chrome':{'socketPath':str(root/'chrome.sock'),'fixtureEnrollment':False,'grants':[{'extensionOrigin':'chrome-extension://'+'a'*32+'/','credentialResource':{'URL':'/never-read/enrollment.sec','Key':'blowfish://file/never-read/key'},'trustScope':'desktop','allWebsites':True,'origins':[]}],'processTrust':{'expectedUID':os.getuid(),'nativeHostExecutable':str(root/'mechanize-native-host'),'nativeHostRequirement':pin('chrome.nativehost'),'chromeExecutable':str(root/'Chrome'),'chromeRequirement':'fixture Chrome pin'}}}
        private(root/'config.json',p.wire(config));job=root/'broker.plist';private(job,plistlib.dumps({'Label':'com.viant.mechanize.fixture','ProgramArguments':[str(root/'mechanize'),'serve','-config',str(root/'config.json'),'-listen','127.0.0.1:7777'],'KeepAlive':False}))
        input={'version':1,'title':'Synthetic reviewed upgrade','installationRoot':str(root),'stagedManifest':{'path':str(stage/'manifest.json'),'sha256':p.sha((stage/'manifest.json').read_bytes())},'approvalConsole':{'path':str(app),'requirement':pin('consent')},'processes':{'broker':{'pid':10,'start':'100:1'},'console':{'pid':20,'start':'100:2'},'chrome':{'pid':30,'start':'100:3'}},'extension':{'path':str(extension),'extensionID':'a'*32,'windowTitle':'Mechanize'},'consentBinding':{'sessionID':'fixture-session','purpose':'inspect management'},'observerCredential':{'path':str(credentials/'observer'),'sha256':p.sha(b'SYNTHETIC-TOKEN-CANARY')},'keychain':{'alias':'master','service':'fixture-service','account':'fixture-account'},'identity':{'subject':'fixture-user','tenant':'','clientID':'console-client'},'launchdPath':str(job)}
        processes={10:{'pid':10,'uid':os.getuid(),'start':'100:1','executable':str(root/'mechanize')},20:{'pid':20,'uid':os.getuid(),'start':'100:2','executable':str(main)},30:{'pid':30,'uid':os.getuid(),'start':'100:3','executable':str(root/'Chrome')}}
        return top,root,input,config,manifest,processes

    def test_concrete_review_old_inventories_and_strict_candidate_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,input,config,manifest,processes=self.fixture(directory);original=(root/'config.json').read_bytes();verifies=[]
            summary=helper.prepare(input,top/'review',lambda pid:dict(processes[pid]),lambda *args:verifies.append(args),lambda path,role,work:pin(role))
            self.assertEqual((root/'config.json').read_bytes(),original);self.assertTrue(summary['reviewPrepared']);self.assertFalse(summary['runtimeReady']);self.assertFalse(summary['installedFilesChanged']);self.assertFalse(summary['keychainAccessed'])
            review=p.decode((top/'review/review.json').read_bytes());candidate=p.decode((top/'review/candidate-config.json').read_bytes())
            self.assertEqual(review['enrollment']['resources'],[{'path':str(root/'credentials/verifier'),'sha256':p.sha(b'SYNTHETIC-KEY-CANARY')}])
            self.assertEqual(review['enrollment']['namespace'],p.sha(p.wire(['mechanize.identity.v1','fixture-issuer','','fixture-user'])))
            expected=helper.candidate_config(config,manifest,Path(manifest['sourceRoot']),root);self.assertEqual(candidate,expected)
            for key in ('keys','identityPolicy','stdioCredential','users','keychain','storageRoot'):self.assertEqual(candidate[key],config[key])
            self.assertEqual(candidate['chrome']['grants'],config['chrome']['grants'])
            for artifact in review['installPlan']['runtime']['Artifacts']:self.assertEqual(artifact['Old'],p.inventory(artifact['target']))
            output=(top/'review/review.json').read_bytes()+(top/'review/candidate-config.json').read_bytes()+p.wire(summary)
            self.assertNotIn(b'SYNTHETIC-KEY-CANARY',output);self.assertNotIn(b'SYNTHETIC-TOKEN-CANARY',output)
            self.assertGreaterEqual(len(verifies),8)

    def test_verifier_resolution_covers_exact_rules_and_rejects_unsupported_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,input,config,_,_=self.fixture(directory)
            second=root/'credentials/rsa';private(second,b'public verification fixture')
            config['keys']['Rules']=[{'Resource':['fixture-scope'],'Algorithm':'RS256','RSA':[{'URL':str(second)}]},{'HMAC':{'URL':str(root/'credentials/verifier')}}]
            refs=helper.verifier_resources(config);self.assertEqual({x['path'] for x in refs},{str(second),str(root/'credentials/verifier')})
            for extra in ({'Data':'PRIVATE-CANARY'},{'Fallback':{'URL':str(second)}},{'Key':'mechanize-keychain://generic-password/master'},{'URL':'https://remote.invalid/key'}):
                changed=copy.deepcopy(config);changed['keys']['HMAC'].update(extra)
                with self.subTest(extra=list(extra)),self.assertRaises(ValueError):helper.verifier_resources(changed)
            changed=copy.deepcopy(config);changed['keys']['CertURL']='https://remote.invalid/cert'
            with self.assertRaises(ValueError):helper.verifier_resources(changed)

    def test_refuses_pin_subject_item_pid_and_loaded_extension_substitutions(self):
        for kind in ('approval','subject','client','keychain','pid','extension','inlineCredential'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                top,root,input,config,_,processes=self.fixture(directory)
                if kind=='approval':input['approvalConsole']['requirement']=pin('consent','c')
                if kind=='subject':input['identity']['subject']='foreign'
                if kind=='client':input['identity']['clientID']='foreign'
                if kind=='keychain':input['keychain']['account']='foreign'
                if kind=='pid':processes[10]['start']='200:1'
                if kind=='extension':input['extension']['extensionID']='b'*32
                if kind=='inlineCredential':config['stdioCredential']['Data']='PRIVATE-CANARY';private(root/'config.json',p.wire(config))
                with self.assertRaises(ValueError):helper.prepare(input,top/'review',lambda pid:dict(processes[pid]),lambda *a:None,lambda path,role,work:pin(role))
                self.assertFalse((top/'review/review.json').exists())

    def test_metadata_process_check_allows_only_same_inode_chrome_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,input,_,_,processes=self.fixture(directory);canonical=root/'Chrome';clone=root/'clone-image';os.link(canonical,clone);processes[30]['executable']=str(clone)
            helper.check_process(input['processes']['chrome'],canonical,'fixture pin',top,lambda pid:dict(processes[pid]),lambda *a:None,True)
            clone.unlink();shutil.copyfile(canonical,clone);clone.chmod(0o700)
            with self.assertRaises(ValueError):helper.check_process(input['processes']['chrome'],canonical,'fixture pin',top,lambda pid:dict(processes[pid]),lambda *a:None,True)
            self.assertEqual(ctypes.sizeof(helper.BSDInfo),136)

    def test_recovery_restores_only_retained_chrome_and_explicit_new_record_root(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,input,config,manifest,processes=self.fixture(directory)
            config['nativeVault']['root']=str(Path.home()/'.secret/vault');config['nativeVault'].pop('recordRoot')
            retained=top/'retained-config.json';private(retained,p.wire(config));disabled=copy.deepcopy(config);disabled.pop('chrome');private(root/'config.json',p.wire(disabled))
            input['chromeRecovery']={'path':str(retained),'sha256':p.sha(retained.read_bytes())};input['enableRecordStore']=True
            chrome_pin='identifier "com.google.Chrome" and cdhash H"'+'f'*40+'"';calls=[]
            pinning=lambda path,role,work:chrome_pin if role=='google-chrome' else pin(role)
            result=helper.prepare(input,top/'recovery',lambda pid:dict(processes[pid]),lambda *args:calls.append(args),pinning)
            candidate=p.decode((top/'recovery/candidate-config.json').read_bytes());review=p.decode((top/'recovery/review.json').read_bytes())
            self.assertTrue(result['chromeRecoveryReviewed']);self.assertTrue(result['recordStoreEnabledInCandidate'])
            self.assertEqual(candidate['chrome']['grants'],config['chrome']['grants']);self.assertEqual(candidate['chrome']['processTrust']['chromeRequirement'],chrome_pin)
            self.assertEqual(candidate['nativeVault']['recordRoot'],str(Path.home()/'.secret/vault-records'));self.assertEqual(candidate['nativeVault']['keyAlias'],config['nativeVault']['keyAlias'])
            self.assertEqual(review['installPlan']['runtime']['ChromeRecovery']['originalConfig'],input['chromeRecovery'])
            self.assertTrue(any(args[1]==helper.GOOGLE_SIGNER for args in calls))
            disabled['users']=[];private(root/'config.json',p.wire(disabled))
            with self.assertRaises(ValueError):helper.prepare(input,top/'bad-recovery',lambda pid:dict(processes[pid]),lambda *a:None,pinning)

    def test_recovery_preserves_existing_follow_updates_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            top,root,inputs,config,manifest,processes=self.fixture(directory)
            config['chrome']['processTrust']['chromeRequirement']=helper.GOOGLE_SIGNER
            retained=top/'retained-config.json';private(retained,p.wire(config))
            disabled=copy.deepcopy(config);disabled.pop('chrome');private(root/'config.json',p.wire(disabled))
            inputs['chromeRecovery']={'path':str(retained),'sha256':p.sha(retained.read_bytes())}
            current_pin='identifier "com.google.Chrome" and cdhash H"'+'f'*40+'"'
            helper.prepare(inputs,top/'recovery',lambda pid:dict(processes[pid]),lambda *a:None,lambda path,role,work:current_pin if role=='google-chrome' else pin(role))
            candidate=p.decode((top/'recovery/candidate-config.json').read_bytes())
            self.assertEqual(candidate['chrome']['processTrust']['chromeRequirement'],helper.GOOGLE_SIGNER)
            self.assertEqual(candidate['chrome']['grants'],config['chrome']['grants'])

    def test_key_fingerprint_refuses_symlink_and_permissions_without_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);key=root/'key';private(key,b'opaque key bytes')
            link=root/'alias';link.symlink_to(key)
            with self.assertRaises(ValueError):helper.hash_private(link)
            key.chmod(0o644)
            with self.assertRaises(ValueError):helper.hash_private(key)

if __name__=='__main__':unittest.main()
