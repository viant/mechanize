import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('unified',Path(__file__).with_name('build-unified-app.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
p=u.p

def pin(role):return 'identifier "com.viant.mechanize.'+role+'" and cdhash H"'+'a'*40+'"'

class UnifiedAppTests(unittest.TestCase):
    def fixture(self,root):
        root=Path(root).resolve();root.chmod(0o700)
        app=root/'old.app';(app/'Contents/MacOS').mkdir(parents=True)
        for d in (app,app/'Contents',app/'Contents/MacOS'):d.chmod(0o700)
        (app/'Contents/MacOS/MechanizeConsent').write_bytes(b'console');(app/'Contents/MacOS/MechanizeConsent').chmod(0o700)
        info={'CFBundleIdentifier':'com.viant.mechanize.consent','CFBundleExecutable':'MechanizeConsent','MechanizeBrokerRequirement':pin('broker'),'MechanizeHelperRequirement':pin('native'),'MechanizeEnrollmentAccount':'retained-account'}
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps(info));(app/'Contents/Info.plist').chmod(0o600)
        manifest={'schemaVersion':1,'installationPerformed':False,'console':str(app),'consoleRequirement':pin('consent'),'nativeHostBrokerRequirement':pin('broker')}
        for role,suffix in [('broker','broker'),('helper','native'),('nativeHost','chrome.nativehost')]:
            f=root/role;f.write_bytes(role.encode());f.chmod(0o700)
            manifest.update({role:str(f),role+'SHA256':p.sha(f.read_bytes()),role+'Requirement':pin(suffix)})
        path=root/'manifest.json';p.write_private(path,p.wire(manifest))
        return root,path,manifest
    def test_stages_one_app_without_changing_original_bytes_or_custody(self):
        with tempfile.TemporaryDirectory() as d:
            root,path,manifest=self.fixture(d);before=p.inventory(Path(manifest['console']));calls=[]
            out=u.build(path,root/'output',verify=lambda *a:calls.append(a),signer=lambda *a:pin('consent'))
            app=Path(out['app']);info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
            self.assertEqual(info['MechanizeHelperLaunchTransport'],'console-v1');self.assertEqual(info['CFBundleDisplayName'],'Mechanize');self.assertEqual(info['MechanizeEnrollmentAccount'],'retained-account')
            self.assertEqual(info['CFBundleIdentifier'],'com.viant.mechanize.consent')
            self.assertEqual(p.inventory(Path(manifest['console'])),before)
            self.assertEqual(set(x.name for x in (root/'output').iterdir()),{'Mechanize.app','unified-manifest.json'})
            for role,relative in u.LAYOUT.items():self.assertEqual((app/relative).read_bytes(),role.encode())
            self.assertFalse(out['installationPerformed']);self.assertFalse(out['singleTCCEntryQualified']);self.assertTrue(out['migrationRequired'])
            self.assertGreater(len(calls),8)
    def test_rejects_digest_substitution_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root,path,m=self.fixture(d);Path(m['broker']).write_bytes(b'changed')
            with self.assertRaises(ValueError):u.build(path,root/'output',verify=lambda *a:None,signer=lambda *a:pin('consent'))
            with self.assertRaises(ValueError):u.build(path,root/'output',verify=lambda *a:None,signer=lambda *a:pin('consent'))
if __name__=='__main__':unittest.main()
