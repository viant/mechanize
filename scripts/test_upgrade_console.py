"""Readiness fixtures only; no processes, enrollment, keys or installed files."""
import importlib.util
import base64
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('console_upgrade',Path(__file__).with_name('upgrade-console.py'))
upgrade=importlib.util.module_from_spec(spec);spec.loader.exec_module(upgrade)

class ConsoleReadinessTests(unittest.TestCase):
    def testReviewEnrollmentSurvivesPreservedPlistWithoutChangingPins(self):
        original={'MechanizeBrokerRequirement':'original-broker','MechanizeHelperRequirement':'original-helper','MechanizeEnrollmentAccount':'original-account'}
        staged={'MechanizeUpgradeReviewPublicKey':base64.b64encode(b'x'*32).decode(),'MechanizeUpgradePackagePath':'/private/fixture/updates/reviewed.json','MechanizeBrokerRequirement':'unrelated-broker'}
        result=upgrade.retain_review_enrollment(original,staged,Path('/private/fixture/Mechanize Permissions.app'))
        for k,v in original.items():self.assertEqual(result[k],v)
        self.assertEqual(result['MechanizeUpgradeReviewPublicKey'],staged['MechanizeUpgradeReviewPublicKey'])
        self.assertEqual(result['MechanizeUpgradePackagePath'],staged['MechanizeUpgradePackagePath'])
        self.assertEqual(upgrade.retain_review_enrollment(result,{},Path('/private/fixture/Mechanize Permissions.app')),result)
    def testReviewEnrollmentRejectsPartialMalformedAndBundledPaths(self):
        key=base64.b64encode(b'x'*32).decode()
        for value in [
            {'MechanizeUpgradeReviewPublicKey':key},
            {'MechanizeUpgradeReviewPublicKey':'invalid','MechanizeUpgradePackagePath':'/private/fixture/reviewed.json'},
            {'MechanizeUpgradeReviewPublicKey':key,'MechanizeUpgradePackagePath':'/private/fixture/../reviewed.json'},
            {'MechanizeUpgradeReviewPublicKey':key,'MechanizeUpgradePackagePath':'/private/fixture/Mechanize Permissions.app/Contents/reviewed.json'}]:
            with self.assertRaises(ValueError):upgrade.retain_review_enrollment({},value,Path('/private/fixture/Mechanize Permissions.app'))
    def report(self,stage='complete',error=None,ready=True):
        value={'stage':stage,'brokerVerified':ready,'credentialAvailable':ready,'authenticated':ready}
        if error is not None:value['errorCode']=error
        return json.dumps(value).encode()
    def verify(self,responses,identities=None):
        now=[0.0];calls=[];identity_calls=[]
        def diagnostic():
            calls.append(1)
            return responses[min(len(calls)-1,len(responses)-1)]
        def identity(pid,path):
            identity_calls.append(1)
            return identities[min(len(identity_calls)-1,len(identities)-1)] if identities else 'same-process'
        def pause(seconds):now[0]+=seconds
        return upgrade.verify_console_connection(Path('/synthetic/console.app'),1,Path('/synthetic/broker'),
            diagnostic=diagnostic,identity=identity,clock=lambda:now[0],pause=pause),calls
    def testUnavailablePreauthEndpointCanBecomeReady(self):
        report,calls=self.verify([(1,self.report('broker','unavailable',False)),(0,self.report())])
        self.assertTrue(report['authenticated']);self.assertEqual(len(calls),2)
    def testUnavailableEndpointExpiresWithoutEnrollmentOrSuccess(self):
        with self.assertRaisesRegex(RuntimeError,'readiness expired'):
            self.verify([(1,self.report('broker','unavailable',False))])
    def testTrustCredentialAndRemoteErrorsAreNotRetried(self):
        for error in ['unsafeEndpoint','untrustedPeer','missingEnrollment','remoteRejected','malformedFrame']:
            attempts=[]
            def diagnostic():attempts.append(1);return 1,self.report('broker',error,False)
            with self.subTest(error=error),self.assertRaisesRegex(RuntimeError,'connection rejected'):
                upgrade.verify_console_connection(Path('/synthetic/console.app'),1,Path('/synthetic/broker'),
                    identity=lambda *_:'same-process',diagnostic=diagnostic)
            self.assertEqual(len(attempts),1)
    def testProcessChangeCannotBeReportedAsReady(self):
        for identities in [['original','replacement'],['original','original','replacement']]:
            with self.subTest(identities=identities),self.assertRaisesRegex(RuntimeError,'identity changed'):
                self.verify([(0,self.report())],identities)
    def testPartialAndStringBooleanSuccessAreRejected(self):
        for data in [self.report(ready=False),b'{"stage":"complete","brokerVerified":"true","credentialAvailable":true,"authenticated":true}']:
            with self.subTest(data=data),self.assertRaises(RuntimeError):self.verify([(0,data)])
    def testUnknownFieldsAndMalformedOutputAreWithheld(self):
        for data in [b'{"credential":"DO_NOT_EXPORT_SYNTHETIC_SECRET"}',b'invalid JSON',b'x'*2049]:
            with self.subTest(data=data[:20]),self.assertRaises(RuntimeError) as context:self.verify([(0,data)])
            self.assertNotIn('DO_NOT_EXPORT_SYNTHETIC_SECRET',str(context.exception))
    def testAuthenticatedFailureIsNotAStartupRetry(self):
        with self.assertRaisesRegex(RuntimeError,'connection rejected'):
            self.verify([(1,self.report('snapshot','unavailable',True))])

if __name__=='__main__':unittest.main()
