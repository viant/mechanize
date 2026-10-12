import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location('runtime_package',Path(__file__).with_name('package-runtime-upgrade.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
import extension_package

def pin(role,letter='a'):return 'identifier "com.viant.mechanize.'+role+'" and cdhash H"'+letter*40+'"'
def entry(kind='file',raw=b'old',mode=0o700):return {'kind':kind,'mode':mode,'size':len(raw) if kind=='file' else 0,'sha256':p.sha(raw) if kind=='file' else ''}

class PackageTests(unittest.TestCase):
    def fixture(self,root):
        manifest={};root.mkdir(mode=0o700,exist_ok=True)
        for role,key,identifier in [('broker','broker','broker'),('helper','helper','native'),('native-host','nativeHost','chrome.nativehost')]:
            file=root/role;file.write_bytes(('new '+role).encode());file.chmod(0o700)
            manifest[key]=str(file);manifest[key+'SHA256']=p.sha(file.read_bytes());manifest[key+'Requirement']=pin(identifier,'b')
        app=root/'candidate.app';(app/'Contents/MacOS').mkdir(parents=True,mode=0o700);app.chmod(0o700);(app/'Contents').chmod(0o700)
        main=app/'Contents/MacOS/MechanizeConsent';main.write_bytes(b'new console');main.chmod(0o700)
        plist=app/'Contents/Info.plist';plist.write_bytes(plistlib.dumps({'MechanizeBrokerRequirement':manifest['brokerRequirement']}));plist.chmod(0o600)
        manifest.update(console=str(app),consoleRequirement=pin('consent','b'),nativeHostBrokerRequirement=manifest['brokerRequirement'])
        original={'.':entry()};old_digest=p.sha(p.wire(original));runtime='/fixture/runtime'
        artifacts=[{'role':role,'target':runtime+'/'+('Mechanize Permissions.app' if role=='console' else {'helper':'mechanize-native','native-host':'mechanize-native-host'}[role]),'Old':copy.deepcopy(original),'OldDigest':old_digest,'OldRequirement':pin(identifier)} for role,identifier in [('helper','native'),('native-host','chrome.nativehost'),('console','consent')]]
        artifacts[2]['Old']={'.':entry('directory')};artifacts[2]['OldDigest']=p.sha(p.wire(artifacts[2]['Old']))
        preserved={'.':entry('directory')};preserved.update({name:entry(raw=b'public code',mode=0o600) for name in extension_package.FILES});preserved=p.ordered_inventory(preserved)
        enrollment={'version':1,'session':'a'*64,'config':{'path':runtime+'/config.json','sha256':'b'*64},'resources':[{'path':'/never-read/credential','sha256':'c'*64}],'consoleRequirement':pin('consent'),'expectedUID':os.getuid(),'namespace':'d'*64,'clientID':'fixture-client','canonicalExecutable':runtime+'/mechanize','oldRequirement':pin('broker'),'newRequirement':manifest['brokerRequirement'],'alias':'master','service':'fixture-service','account':'fixture-account','journalRoot':runtime+'/.secret/mechanize-custody-migration'}
        rt={'BrokerPath':enrollment['canonicalExecutable'],'OldBrokerRequirement':enrollment['oldRequirement'],'ActiveHelperPath':runtime+'/helper','ActiveHelperRequirement':pin('native'),'ActiveHelperSHA256':'e'*64,'ChromeExecutable':'/fixture/Chrome','ExtensionID':'a'*32,'OldConsoleBirth':'123:1','Artifacts':artifacts,'Mode':'preserve-extension-v1','PreservedExtension':{'path':runtime+'/extension','extensionID':'a'*32,'inventory':preserved,'inventorySHA256':p.sha(p.wire(preserved))},'ChromeRequirement':'fixture Chrome requirement'}
        plan={'version':1,'oldBrokerSHA256':'f'*64,'configCandidate':{'path':'/never-read/config-candidate','sha256':'c'*64},'backup':runtime+'/backup','stageJournalRoot':runtime+'/.secret/mechanize-runtime-staging','artifactJournalRoot':runtime+'/.secret/mechanize-runtime-artifacts','newSourceRoot':'/fixture/source','runtime':rt,'readiness':{'launchd':{'path':'/never-read/job.plist','sha256':'e'*64},'listen':'127.0.0.1:7777'}}
        manifest_path=root/'manifest.json';manifest_path.write_bytes(p.wire(manifest));manifest_path.chmod(0o600)
        observer={'port':7777,'brokerPID':12,'brokerStart':'123:1','brokerRequirement':pin('broker'),'credentialURL':'/never-read/observer-credential','credentialSHA256':'c'*64,'consentBinding':{'sessionID':'fixture-session','purpose':'inspect management'},'windowTitle':'Mechanize','chromePID':13,'chromeStart':'124:1'}
        return {'version':1,'title':'Fixture reviewed runtime upgrade','stagedManifest':{'path':str(manifest_path),'sha256':p.sha(manifest_path.read_bytes())},'enrollment':enrollment,'installPlan':plan,'observer':observer},manifest

    def test_unified_plan_binds_one_app_and_retains_legacy_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();review,manifest=self.fixture(root)
            app=Path(manifest['console']);helpers=app/'Contents/Helpers';helpers.mkdir(mode=0o700)
            import shutil
            runtime={}
            for role,name in [('broker','mechanize'),('helper','mechanize-native'),('nativeHost','mechanize-native-host')]:
                relative='Contents/Helpers/'+name;shutil.copyfile(manifest[role],app/relative);(app/relative).chmod(0o700)
                runtime[role]={'relativePath':relative,'requirement':manifest[role+'Requirement'],'sha256':manifest[role+'SHA256']}
            unified={'schemaVersion':1,'layout':'unified-app-v1','app':str(app),'bundleIdentifier':'com.viant.mechanize.consent','consoleRequirement':manifest['consoleRequirement'],'runtime':runtime,'inventory':p.inventory(app),'sourceManifestSHA256':review['stagedManifest']['sha256'],'migrationRequired':True,'installationPerformed':False,'credentialsProvisioned':False,'systemPermissionsGranted':False,'singleTCCEntryQualified':False}
            ref=root/'unified.json';p.write_private(ref,p.wire(unified));review['unifiedManifest']={'path':str(ref),'sha256':p.sha(ref.read_bytes())}
            with mock.patch.object(Path,'home',return_value=root/'home'):
                plan,enrollment,_=p.assemble_plan(review,manifest,lambda *a:None,root)
            self.assertEqual(plan['version'],2);self.assertEqual(enrollment['version'],2)
            self.assertEqual(plan['runtime']['Mode'],'unified-app-v2');self.assertEqual(len(plan['runtime']['Artifacts']),1)
            self.assertEqual({a['role'] for a in plan['runtime']['LegacyArtifacts']},{'helper','native-host','console'})
            self.assertEqual(plan['runtime']['NewBrokerPath'],enrollment['newCanonicalExecutable'])
            self.assertEqual(plan['brokerCandidate']['path'],str(app/'Contents/Helpers/mechanize'))
            self.assertEqual(plan['runtime']['Artifacts'][0]['Old'],{})
            target=root/'home/Applications/Mechanize.app';target.parent.mkdir(parents=True,mode=0o700);shutil.copytree(app,target)
            review['preinstalledUnifiedApp']=True
            with mock.patch.object(Path,'home',return_value=root/'home'):
                adopted,_,_=p.assemble_plan(review,manifest,lambda *a:None,root)
                self.assertIs(adopted['runtime']['preinstalledUnifiedApp'],True)
                for invalid in (False,None,1,'true'):
                    review['preinstalledUnifiedApp']=invalid
                    with self.assertRaises(ValueError):p.assemble_plan(review,manifest,lambda *a:None,root)
                review['preinstalledUnifiedApp']=True
                (target/'Contents/MacOS/MechanizeConsent').write_bytes(b'substitution')
                with self.assertRaises(ValueError):p.assemble_plan(review,manifest,lambda *a:None,root)


    def test_closed_old_metadata_and_computed_new_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();review,manifest=self.fixture(root);checks=[]
            plan,enrollment,observer=p.assemble_plan(review,manifest,lambda *a:checks.append(a),root)
            self.assertEqual(len(checks),4)
            self.assertEqual(list(plan),list(p.PLAN_KEYS))
            self.assertEqual(list(plan['runtime']),list(p.RUNTIME_KEYS))
            self.assertNotIn('ExtensionStorageSHA256',plan['runtime'])
            self.assertEqual(plan['readiness']['consoleInventory'],plan['runtime']['Artifacts'][2]['New'])
            self.assertEqual(enrollment,review['enrollment'])
            self.assertNotIn('nativeHuman',observer)
            for change in ('newInventory','approval','oldDigest','configData','extensionOverlap','badPin','wrongBroker'):
                bad=copy.deepcopy(review);m=copy.deepcopy(manifest)
                if change=='newInventory':bad['installPlan']['runtime']['Artifacts'][0]['New']={}
                if change=='approval':bad['approved']=True
                if change=='oldDigest':bad['installPlan']['runtime']['Artifacts'][0]['OldDigest']='0'*64
                if change=='configData':bad['enrollment']['config']['data']='secret'
                if change=='extensionOverlap':bad['installPlan']['runtime']['Artifacts'][0]['target']='/fixture/runtime/extension/helper'
                if change=='badPin':m['helperRequirement']=pin('broker')
                if change=='wrongBroker':m['nativeHostBrokerRequirement']=pin('broker','d')
                with self.subTest(change=change),self.assertRaises(ValueError):p.assemble_plan(bad,m,lambda *a:None,root)

    def test_package_build_order_and_exact_worker_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);review,manifest=self.fixture(root/'stage');review_file=root/'review.json';review_file.write_bytes(p.wire(review));review_file.chmod(0o600);output=root/'package';calls=[]
            def build(enrollment,destination,identity):
                calls.append(copy.deepcopy(enrollment));n=len(calls)
                return {'executable':str(destination/'mechanize-custody-migration'),'requirement':pin('custody-migration',str(n)),'sha256':str(n)*64}
            def sign_child(args,cwd):
                payload=(output/'reviewed-package.json').read_bytes()
                p.write_private(output/'signed-package.json',p.wire({'version':1,'payloadBase64':base64.b64encode(payload).decode(),'signatureBase64':base64.b64encode(bytes(64)).decode()}))
            with mock.patch.object(p,'worker',side_effect=build),mock.patch.object(p,'verify_artifact'),mock.patch.object(p,'child',side_effect=sign_child) as child:
                result=p.package(review_file,output,root/'key.pem')
            self.assertFalse(result['installationPerformed']);self.assertFalse(result['approvalGranted'])
            self.assertIn('installPlan',calls[0]);self.assertNotIn('preparation',calls[0]);self.assertIn('preparation',calls[1]);self.assertNotIn('installPlan',calls[1])
            payload=p.decode((output/'reviewed-package.json').read_bytes());raw=(output/'install-plan.json').read_bytes()
            self.assertEqual(base64.b64decode(payload['installPlanBase64']),raw)
            self.assertEqual(calls[1]['preparation']['runtimeManifestSHA256'],p.sha(raw));self.assertEqual(calls[1]['preparation']['mutationRequirement'],payload['installerWorker']['requirement'])
            self.assertEqual(payload['bootstrap']['workerRequirement'],payload['installerWorker']['requirement'])
            self.assertEqual(child.call_count,1);self.assertIn('sign-runtime-upgrade-package.py',child.call_args.args[0][1])

    def test_worker_requires_built_file_and_exact_enrollment_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);review,_=self.fixture(root/'stage')
            enrollment=copy.deepcopy(review['enrollment']);enrollment['installPlan']={'path':str(root/'plan.json'),'sha256':'f'*64}
            for wrong in (False,True):
                destination=root/('bad' if wrong else 'good')
                def fake_build(args,cwd):
                    destination.mkdir(mode=0o700);binary=destination/'mechanize-custody-migration';binary.write_bytes(b'built worker');binary.chmod(0o700)
                    spec=importlib.util.spec_from_file_location('custody',Path(__file__).with_name('build-custody-migration.py'));builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
                    digest=p.sha(base64.b64decode(builder.encode_enrollment(enrollment)))
                    manifest={'schemaVersion':1,'executable':str(binary),'requirement':pin('custody-migration'),'sha256':p.sha(binary.read_bytes()),'enrollmentSHA256':'0'*64 if wrong else digest,'installationPerformed':False,'migrationPerformed':False}
                    p.write_private(destination/'manifest.json',p.wire(manifest))
                with mock.patch.object(p,'child',side_effect=fake_build),mock.patch.object(p,'verify_artifact'):
                    if wrong:
                        with self.assertRaises(ValueError):p.worker(enrollment,destination,None)
                    else:self.assertEqual(p.worker(enrollment,destination,None)['sha256'],p.sha(b'built worker'))

    def test_inventory_rejects_symlink_hardlink_and_signature_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();review,manifest=self.fixture(root)
            file=Path(manifest['helper']);link=root/'linked';os.link(file,link)
            with self.assertRaises(ValueError):p.inventory(file)
            link.unlink();file.unlink();file.symlink_to(Path(manifest['broker']))
            with self.assertRaises(ValueError):p.inventory(file)

    def test_runtime_resources_canonical_golden(self):
        fixture=Path(__file__).resolve().parents[1]/'testdata/runtime-upgrade-plan-runtime-resources-v1.json'
        raw=fixture.read_bytes();value=p.decode(raw)
        self.assertEqual(p.wire(value),raw)
        self.assertEqual(list(value['runtime']['PreservedExtension']),['path','extensionID','inventory','inventorySHA256','runtimeResourcesOnly'])
        self.assertIs(value['runtime']['PreservedExtension']['runtimeResourcesOnly'],True)

    def test_unified_v2_go_canonical_golden(self):
        raw=(Path(__file__).resolve().parents[1]/'testdata/runtime-upgrade-plan-unified-v2.json').read_bytes();value=p.decode(raw)
        self.assertEqual(p.wire(value),raw)
        self.assertEqual(list(value['runtime'])[-2:],['NewBrokerPath','LegacyArtifacts'])
        self.assertEqual(value['version'],2)

    def test_preinstalled_v2_go_canonical_golden(self):
        raw=(Path(__file__).resolve().parents[1]/'testdata/runtime-upgrade-plan-preinstalled-v2.json').read_bytes();value=p.decode(raw)
        self.assertEqual(p.wire(value),raw);self.assertEqual(list(value['runtime'])[-1],'preinstalledUnifiedApp')
        self.assertIs(value['runtime']['preinstalledUnifiedApp'],True)

    def test_go_canonical_golden_bytes(self):
        fixture=Path(__file__).resolve().parents[1]/'testdata/runtime-upgrade-plan-v1.json'
        raw=fixture.read_bytes();value=p.decode(raw)
        self.assertEqual(list(value),list(p.PLAN_KEYS));self.assertEqual(list(value['runtime']),list(p.RUNTIME_KEYS))
        self.assertEqual(p.wire(value),raw)

if __name__=='__main__':unittest.main()
