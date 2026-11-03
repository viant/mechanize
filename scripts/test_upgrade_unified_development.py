import copy
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('unified_update',Path(__file__).with_name('upgrade-unified-development.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)

def pin(role,letter):return f'identifier "com.viant.mechanize.{role}" and cdhash H"{letter*40}"'

class UnifiedUpdateTests(unittest.TestCase):
    def fixture(self,root):
        root=Path(root).resolve();root.chmod(0o700)
        installed=root/'Applications/Mechanize.app';candidate=root/'candidate/Mechanize.app'
        def app(path,letter):
            (path/'Contents/Helpers').mkdir(parents=True);(path/'Contents/MacOS').mkdir()
            (path/'Contents/MacOS/MechanizeConsent').write_bytes(b'console-'+letter.encode())
            roles={}
            for role,(filename,suffix) in u.ROLES.items():
                f=path/'Contents/Helpers'/filename;f.write_bytes((role+letter).encode());f.chmod(0o700)
                roles[role]={'relativePath':'Contents/Helpers/'+filename,'requirement':pin(suffix,letter),'sha256':u.package.sha(f.read_bytes())}
            info={'CFBundleIdentifier':'com.viant.mechanize.consent','MechanizeHelperLaunchTransport':'console-v1','MechanizeRuntimeLayoutVersion':1,'MechanizeEnrollmentAccount':'account-'+letter,'MechanizeBrokerRequirement':roles['broker']['requirement'],'MechanizeHelperRequirement':roles['helper']['requirement']}
            (path/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
            return roles
        old=app(installed,'a');roles=app(candidate,'b')
        source=root/'frozen';(source/'dist/development').mkdir(parents=True);(source/'go.mod').write_text('module fixture\n')
        build={'sourceRoot':str(source)}
        for role in roles:build.update({role+'Requirement':roles[role]['requirement'],role+'SHA256':roles[role]['sha256']})
        bp=source/'dist/development/manifest.json';u.shared.atomic(bp,json.dumps(build).encode())
        manifest={'layout':'unified-app-v1','installationPerformed':False,'bundleIdentifier':'com.viant.mechanize.consent','app':str(candidate),'consoleRequirement':pin('consent','b'),'runtime':roles,'inventory':u.package.inventory(candidate),'sourceManifestSHA256':u.package.sha(bp.read_bytes())}
        mp=root/'unified.json';u.shared.atomic(mp,json.dumps(manifest).encode())
        state=root/'state';state.mkdir(mode=0o700)
        config={'sourceRoot':str(root/'old-source'),'storageRoot':str(state/'storage'),'keys':{'HMAC':{'URL':str(state/'key')}},'identityPolicy':{'fixture':'unchanged'},'users':[{'subject':'fixture','desktopAccess':True}],'nativeHelper':str(installed/'Contents/Helpers/mechanize-native'),'nativeLaunch':{'transport':'console-v1','helperRequirement':old['helper']['requirement'],'mode':'semantic'},'nativeConsole':{'designatedRequirement':pin('consent','a'),'socketPath':str(state/'socket')},'stdioCredential':{'URL':str(state/'token')}}
        u.shared.atomic(state/'config.json',json.dumps(config).encode())
        (state/'storage').mkdir();(state/'storage/grants').write_bytes(b'preserved-grants')
        return installed,candidate,source,state,mp,manifest,config

    def test_config_preserves_credentials_grants_and_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            app,_,source,_,_,m,c=self.fixture(tmp);before=copy.deepcopy(c)
            result=u.candidate_config(c,app,source,m)
            self.assertEqual(c,before)
            for k in ['keys','identityPolicy','users','storageRoot','stdioCredential','nativeHelper']:self.assertEqual(result[k],c[k])
            self.assertNotIn('nativeEffectReconciliation',result)
            for change in [{'nativeVault':{'root':'fixture'}},{'keychain':{'items':{}}},{'nativeHelper':'/other/helper'}]:
                bad={**c,**change}
                with self.assertRaises(ValueError):u.candidate_config(bad,app,source,m)

    def test_inventory_and_role_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,candidate,_,_,_,m,_=self.fixture(tmp)
            u.verify_bundle(candidate,m,verify=lambda *a:None)
            bad=copy.deepcopy(m);bad['runtime']['helper']['relativePath']='Contents/Helpers/other'
            with self.assertRaises(ValueError):u.verify_bundle(candidate,bad,verify=lambda *a:None)
            (candidate/'Contents/Helpers/mechanize-native').write_bytes(b'changed')
            with self.assertRaises(ValueError):u.verify_bundle(candidate,m,verify=lambda *a:None)

    def test_apply_preserves_state_and_retains_original_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            app,candidate,source,state,mp,m,c=self.fixture(tmp)
            old=u.package.inventory(app);new=u.package.inventory(candidate);events=[]
            real_verify=u.verify_bundle
            def swap(a,b):
                third=a.parent/'exchange-temp';os.rename(a,third);os.rename(b,a);os.rename(third,b);events.append('exchange')
            args=['updater','--installation',str(state),'--manifest',str(mp),'--source',str(source),'--apply','--broker-pid','42','--idle-verified']
            with mock.patch('sys.argv',args),mock.patch.object(Path,'home',return_value=Path(tmp).resolve()),mock.patch.object(u,'verify_bundle',side_effect=lambda p,m:real_verify(p,m,verify=lambda *a:None)),mock.patch.object(u.shared,'requirement',return_value=pin('consent','a')),mock.patch.object(u,'certificate',return_value='same-certificate'),mock.patch.object(u.runtime,'verify'),mock.patch.object(u.runtime,'preflight_chrome_native_host',return_value=None),mock.patch.object(u.shared,'process_identity',return_value='owned'),mock.patch.object(u.shared,'stop_consoles',side_effect=lambda *a:events.append('stop-console')),mock.patch.object(u.shared,'stop',side_effect=lambda *a:events.append('stop-broker')),mock.patch.object(u.shared,'run',return_value=mock.Mock(stdout=b'')),mock.patch.object(u.runtime,'require_helpers_stopped'),mock.patch.object(u,'exchange',side_effect=swap),mock.patch.object(u.shared,'enroll',side_effect=lambda *a:events.append('enroll')),mock.patch.object(u,'start',return_value=77),mock.patch.object(u.shared,'verify_console_connection',return_value={'stage':'complete'}):
                u.main()
                self.assertEqual(u.package.inventory(app),new)
                backup=next(state.glob('unified-backup-*'));record=json.loads((backup/'update.json').read_text())
                self.assertEqual(record['state'],'verified');self.assertEqual(u.package.inventory(Path(record['retainedApp'])),old)
                u.rollback(state,backup,None,True,'127.0.0.1:4987')
            self.assertEqual(events,['stop-console','stop-broker','exchange','enroll','stop-console','exchange'])
            self.assertEqual(u.package.inventory(app),old)
            self.assertEqual(json.loads((backup/'update.json').read_text())['state'],'rolled-back')
            self.assertEqual(u.package.inventory(Path(record['retainedApp'])),new)
            self.assertEqual((state/'storage/grants').read_bytes(),b'preserved-grants')
            self.assertEqual(json.loads((state/'config.json').read_text()),c)

if __name__=='__main__':unittest.main()
