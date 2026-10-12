#!/usr/bin/env python3
"""Synthetic full production-producer payload for cross-language decoder tests."""
import base64
import importlib.util
from pathlib import Path
import plistlib
import tempfile
from unittest.mock import patch
import test_prepare_runtime_upgrade_review as fixture

p=fixture.p

def _payload(approval=False):
    with tempfile.TemporaryDirectory() as directory:
        top,root,inputs,config,manifest,processes=fixture.PrepareReviewTests().fixture(directory)
        config['keychain']['Items']['master']['Service']='com.viant.mechanize.vault'
        inputs['keychain']['service']='com.viant.mechanize.vault'
        fixture.private(root/'config.json',p.wire(config))
        app=Path(manifest['console']);info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        info.update(CFBundleIdentifier='com.viant.mechanize.consent',CFBundleExecutable='MechanizeConsent',MechanizeHelperRequirement=manifest['helperRequirement'])
        fixture.private(app/'Contents/Info.plist',plistlib.dumps(info));manifest.update(schemaVersion=1,installationPerformed=False)
        staged=Path(inputs['stagedManifest']['path']);fixture.private(staged,p.wire(manifest));inputs['stagedManifest']['sha256']=p.sha(staged.read_bytes())
        spec=importlib.util.spec_from_file_location('unified_fixture',Path(__file__).with_name('build-unified-app.py'));builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        builder.build(staged,top/'unified',verify=lambda *a:None,signer=lambda *a:fixture.pin('consent','c'))
        unified=top/'unified/unified-manifest.json';inputs['unifiedManifest']={'path':str(unified),'sha256':p.sha(unified.read_bytes())}
        job=plistlib.loads(Path(inputs['launchdPath']).read_bytes());job['ProgramArguments'][0]=str(Path.home()/'Applications/Mechanize.app/Contents/Helpers/mechanize')
        fixture.private(top/'relocated.plist',plistlib.dumps(job));inputs['unifiedLaunchdPath']=str(top/'relocated.plist')
        fixture.helper.prepare(inputs,top/'review',inspect=lambda pid:dict(processes[pid]),verify=lambda *a:None,pin=lambda path,role,work:fixture.pin(role))
        if approval:
            review=p.decode((top/'review/review.json').read_bytes());review['preinstalledUnifiedApp']=True;review['preinstalledApprovalConsole']=True
            review['enrollment']['consoleRequirement']=fixture.pin('consent','c')
            review['installPlan']['runtime']['OldConsoleBirth']='1800000000:2'
            (top/'review/review.json').write_bytes(p.wire(review))
        output=top/'package';count=0
        def worker(enrollment,destination,identity):
            nonlocal count
            count+=1
            return {'executable':str(destination/'mechanize-custody-migration'),'requirement':fixture.pin('custody-migration',str(count)),'sha256':str(count)*64}
        def signer(args,cwd):
            raw=(output/'reviewed-package.json').read_bytes()
            p.write_private(output/'signed-package.json',p.wire({'version':1,'payloadBase64':base64.b64encode(raw).decode(),'signatureBase64':base64.b64encode(b'x'*64).decode()}))
        original_inventory=p.inventory;target=Path.home()/'Applications/Mechanize.app';candidate=top/'unified/Mechanize.app'
        with patch.object(p,'inventory',side_effect=lambda path:original_inventory(candidate if Path(path)==target else path)),patch.object(p,'worker',side_effect=worker),patch.object(p,'verify_artifact'),patch.object(p,'child',side_effect=signer):
            p.package(top/'review/review.json',output,top/'synthetic-unused-key')
        return (output/'reviewed-package.json').read_bytes()
def payload(approval=False):
    # This synthetic fixture must never inspect a real installed application.
    target=Path.home()/'Applications/Mechanize.app'
    exists,symlink=Path.exists,Path.is_symlink
    with patch.object(Path,'exists',lambda value:False if value==target else exists(value)),patch.object(Path,'is_symlink',lambda value:False if value==target else symlink(value)):
        return _payload(approval)

if __name__=='__main__':
    import sys
    sys.stdout.buffer.write(payload('--approval-compatibility' in sys.argv))
