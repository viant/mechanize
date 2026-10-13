import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recover_chrome_update', HERE / 'recover-chrome-update.py')
repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)


class ChromePinRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.chrome = self.root / 'Chrome'; self.chrome.write_bytes(b'inert synthetic image'); self.chrome.chmod(0o755)
        self.host = self.root / 'mechanize-native-host'; self.host.write_bytes(b'inert host')
        self.broker = self.root / 'mechanize'; self.broker.write_bytes(b'inert broker')
        self.old = 'identifier "com.google.Chrome" and cdhash H"' + 'c' * 40 + '"'
        self.new = 'identifier "com.google.Chrome" and cdhash H"' + 'd' * 40 + '"'
        self.trust = {'expectedUID': os.getuid(), 'nativeHostExecutable': str(self.host),
                      'nativeHostRequirement': 'identifier "com.viant.mechanize.chrome.nativehost" and cdhash H"' + 'b' * 40 + '"',
                      'chromeExecutable': str(self.chrome), 'chromeRequirement': self.old, 'maximumAncestors': 1}
        self.broker_pin = 'identifier "com.viant.mechanize.broker" and cdhash H"' + 'a' * 40 + '"'
        grant = {'profileChannel': 'fixture-profile', 'browserInstance': 'fixture-browser',
                 'extensionOrigin': 'chrome-extension://' + 'a' * 32 + '/', 'credentialResource': {'URL': 'never-read-credential-resource'},
                 'allWebsites': True, 'origins': [], 'trustScope': 'desktop'}
        self.config = {'chrome': {'socketPath': str(self.root / 'chrome.sock'), 'processTrust': self.trust, 'grants': [grant]},
                       'nativeVault': {'brokerRequirement': self.broker_pin, 'root': 'never-read-vault'}, 'other': {'preserved': 'opaque-fixture'}}
        self.native = dict(grant, socketPath=self.config['chrome']['socketPath'], processTrust=copy.deepcopy(self.trust), brokerRequirement=self.broker_pin)
        self.paths = [self.root / 'config.json', self.root / 'native-host.json']
        for path, value in zip(self.paths, (self.config, self.native)):
            self.write(path, value)
        self.originals = [p.read_bytes() for p in self.paths]
        self.reference = {'pid': 123, 'start': '100:1'}
        self.process = dict(self.reference, uid=os.getuid(), executable=str(self.chrome))
        self.verified = []

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def verify(self, path, requirement, work):
        self.verified.append((str(path), requirement))

    def prepare(self):
        return repair.prepare(*self.paths, self.reference, self.root, inspect=lambda pid: self.process.copy(),
                              verifier=self.verify, pin=lambda *args: self.new)

    def apply(self, plan, **kwargs):
        return repair.apply(plan, self.root / 'backup', self.root, inspect=lambda pid: self.process.copy(),
                            verifier=self.verify, stopped=kwargs.pop('stopped', lambda paths: None), **kwargs)

    def test_prepare_and_apply_change_only_both_chrome_pins(self):
        plan = self.prepare()
        self.assertEqual([p.read_bytes() for p in self.paths], self.originals)
        self.assertIn((str(self.chrome), repair.review.GOOGLE_SIGNER), self.verified)
        self.assertTrue(self.apply(plan))
        for index, path in enumerate(self.paths):
            expected = copy.deepcopy((self.config, self.native)[index])
            (expected['chrome']['processTrust'] if index == 0 else expected['processTrust'])['chromeRequirement'] = self.new
            self.assertEqual(json.loads(path.read_bytes()), expected)
        self.assertEqual((self.root / 'backup/broker.original.json').read_bytes(), self.originals[0])
        self.assertEqual((self.root / 'backup/native-host.original.json').read_bytes(), self.originals[1])
        current = self.prepare()
        self.assertEqual(current['originals'], current['candidates'])

    def test_follow_updates_is_explicit_and_preserved_without_repinning(self):
        plan = repair.prepare(*self.paths, self.reference, self.root,
                              inspect=lambda pid: self.process.copy(), verifier=self.verify,
                              pin=lambda *args: self.new, follow_updates=True)
        self.assertEqual(plan['requirement'], repair.review.GOOGLE_SIGNER)
        self.assertTrue(self.apply(plan))
        self.assertEqual(json.loads(self.paths[0].read_bytes())['chrome']['processTrust']['chromeRequirement'], repair.review.GOOGLE_SIGNER)
        current = self.prepare()
        self.assertEqual(current['requirement'], repair.review.GOOGLE_SIGNER)
        self.assertEqual(current['originals'], current['candidates'])

    def test_requirement_validator_rejects_vendor_lookalikes(self):
        vendor = repair.review.GOOGLE_SIGNER
        self.assertEqual(repair.package.chrome_requirement(vendor), vendor)
        for invalid in (vendor + ' or true', vendor.replace('EQHXZ8M8AV', 'OTHERTEAM'),
                        vendor.replace('com.google.Chrome', 'org.chromium.Chromium'),
                        vendor.replace('anchor apple generic and ', '')):
            with self.assertRaises(ValueError): repair.package.chrome_requirement(invalid)

    def test_vendor_failure_and_changed_birth_refuse_before_writes(self):
        def refuse(*args): raise ValueError('synthetic signer refusal')
        with self.assertRaises(ValueError):
            repair.prepare(*self.paths, self.reference, self.root, inspect=lambda pid: self.process.copy(), verifier=refuse, pin=lambda *args: self.new)
        self.process['start'] = '100:2'
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual([p.read_bytes() for p in self.paths], self.originals)

    def test_configuration_race_refuses_without_overwriting_foreign_change(self):
        plan = self.prepare()
        changed = copy.deepcopy(self.native); changed['profileChannel'] = 'changed'
        self.write(self.paths[1], changed)
        with self.assertRaises(ValueError): self.apply(plan)
        self.assertEqual(self.paths[0].read_bytes(), self.originals[0])
        self.assertEqual(json.loads(self.paths[1].read_bytes()), changed)
        self.assertFalse((self.root / 'backup').exists())

    def test_live_runtime_refuses_before_backup_or_write(self):
        plan = self.prepare()
        def alive(paths):
            self.assertEqual(paths, {str(self.broker), str(self.host)})
            raise ValueError('synthetic active runtime')
        with self.assertRaises(ValueError): self.apply(plan, stopped=alive)
        self.assertEqual([p.read_bytes() for p in self.paths], self.originals)
        self.assertFalse((self.root / 'backup').exists())

    def test_partial_write_is_closed_and_retains_exact_private_backups(self):
        plan = self.prepare()
        def second_fails(path, payload, expected):
            if path == self.paths[1]: raise OSError('synthetic second write failure')
            repair.enrollment.atomic(path, payload, expected)
        with self.assertRaisesRegex(ValueError, 'incomplete'): self.apply(plan, atomic=second_fails)
        self.assertEqual(self.paths[0].read_bytes(), plan['candidates'][0])
        self.assertEqual(self.paths[1].read_bytes(), self.originals[1])
        self.assertEqual((self.root / 'backup/broker.original.json').read_bytes(), self.originals[0])
        self.assertEqual((self.root / 'backup/native-host.original.json').read_bytes(), self.originals[1])
        with self.assertRaises(ValueError): self.prepare()

    def test_mismatched_existing_enrollment_and_symlink_refuse(self):
        changed = copy.deepcopy(self.native); changed['processTrust']['chromeRequirement'] = self.new
        self.write(self.paths[1], changed)
        with self.assertRaises(ValueError): self.prepare()
        self.paths[1].unlink(); self.paths[1].symlink_to(self.paths[0])
        with self.assertRaises(ValueError): self.prepare()

    def test_process_changes_after_review_refuse_apply(self):
        plan = self.prepare(); self.process['start'] = '100:2'
        with self.assertRaises(ValueError): self.apply(plan)
        self.assertEqual([p.read_bytes() for p in self.paths], self.originals)


if __name__ == '__main__': unittest.main()
