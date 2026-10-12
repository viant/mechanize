"""Helper configuration projections only; no installed processes or secrets."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('helper_upgrade', Path(__file__).with_name('upgrade-helper.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class HelperProjectionTests(unittest.TestCase):
    requirement = 'identifier "com.viant.mechanize.native" and cdhash H"' + 'a' * 40 + '"'

    def test_exact_nested_enrolled_helper_and_foreign_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            nested = root / 'staged'; nested.mkdir()
            helper = nested / 'mechanize-native'; helper.write_bytes(b'fixture')
            self.assertEqual(upgrade.installed_helper(root, {'nativeHelper':str(helper)}),helper)
            for path in [str(root / '..' / root.name / 'staged' / 'mechanize-native'), str(root / 'missing'), 'relative-helper']:
                with self.assertRaises((ValueError,FileNotFoundError)):
                    upgrade.installed_helper(root, {'nativeHelper':path})
            alias = root / 'alias'; alias.symlink_to(nested,target_is_directory=True)
            with self.assertRaises(ValueError):
                upgrade.installed_helper(root, {'nativeHelper':str(alias / 'mechanize-native')})
            with self.assertRaises(ValueError):
                upgrade.installed_helper(root / 'different-installation', {'nativeHelper':str(helper)})

    def test_only_helper_pin_changes_and_input_is_not_mutated(self):
        original = {'nativeHelper': '/fixture/mechanize-native',
                    'nativeLaunch': {'helperRequirement': 'previous', 'sessionKeyboard': True},
                    'nativeVault': {'root': '/fixture/vault', 'keyAlias': 'opaque-key', 'brokerRequirement': 'existing-broker'},
                    'nativeConsole': {'designatedRequirement': 'existing-console'},
                    'keychain': {'items': {'opaque-key': {'service': 'fixture-service', 'account': 'fixture-account'}}},
                    'storageRoot': '/fixture/storage', 'users': [{'subject': 'fixture-user'}]}
        before = copy.deepcopy(original)
        updated = upgrade.helper_config(original, self.requirement)
        self.assertEqual(original, before)
        updated['nativeLaunch']['helperRequirement'] = 'previous'
        self.assertEqual(updated, before)

    def test_rejects_broad_foreign_or_malformed_requirements(self):
        for requirement in [None, 1, 'identifier "com.viant.mechanize.native"', self.requirement + ' or true',
                            self.requirement.replace('.native', '.broker'), self.requirement.replace('a' * 40, 'a' * 39)]:
            with self.subTest(requirement=requirement), self.assertRaises(ValueError):
                upgrade.helper_config({'nativeHelper': '/fixture/helper', 'nativeLaunch': {}}, requirement)

    def test_requires_existing_helper_enrollment(self):
        for config in [{}, {'nativeHelper': '/fixture/helper'}, {'nativeLaunch': {}},
                       {'nativeHelper': '/fixture/helper', 'nativeLaunch': None}]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                upgrade.helper_config(config, self.requirement)

    def test_frozen_source_rejects_changed_extra_and_traversal_files(self):
        for change in ['unchanged', 'changed', 'extra', 'traversal', 'symlink']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                path = root / 'fixture.swift'
                path.write_text('fixture code')
                checksum = hashlib.sha256(path.read_bytes()).hexdigest()
                inventory = [{'path': 'fixture.swift', 'sha256': checksum}]
                expected = hashlib.sha256(b'fixture.swift\0' + bytes.fromhex(checksum)).hexdigest()
                if change == 'changed': path.write_text('substituted code')
                if change == 'extra': (root / 'extra.swift').write_text('unbound code')
                if change == 'traversal': inventory[0]['path'] = '../fixture.swift'
                if change == 'symlink': (root / 'link').symlink_to(root, target_is_directory=True)
                manifest = root / '.mechanize-source-inventory.json'
                manifest.write_text(json.dumps(inventory)); manifest.chmod(0o600)
                if change == 'unchanged': upgrade.verify_source(root, expected)
                else:
                    with self.assertRaises(ValueError): upgrade.verify_source(root, expected)

    def test_built_or_staged_binary_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / 'helper'
            candidate.write_bytes(b'fixture binary')
            checksum = hashlib.sha256(candidate.read_bytes()).hexdigest()
            upgrade.verify_candidate(candidate, checksum)
            candidate.write_bytes(b'substituted binary')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                upgrade.verify_candidate(candidate, checksum)

    def test_launchd_requires_exact_job_without_restart_triggers(self):
        root = Path('/fixture/installation')
        label = 'com.viant.mechanize.fixture'
        job = {'Label': label, 'KeepAlive': False, 'ProgramArguments':
               [str(root / 'mechanize'), 'serve', '-config', str(root / 'config.json'), '-listen', '127.0.0.1:4987']}
        upgrade.validate_launchd_job(job, root, label)
        for field, value in [('KeepAlive', True), ('KeepAlive', None), ('StartInterval', 1),
                             ('WatchPaths', ['/fixture']), ('Sockets', {}), ('Label', 'foreign-job')]:
            changed = copy.deepcopy(job); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                upgrade.validate_launchd_job(changed, root, label)

    def test_supervisor_respawn_or_job_change_refuses_replacement(self):
        root, label = Path('/fixture/installation'), 'com.viant.mechanize.fixture'
        for pid, current in [(77, b'original-job'), (None, b'changed-job')]:
            with self.subTest(pid=pid), patch.object(upgrade, 'launchd_pid', return_value=pid), patch.object(upgrade.shared, 'private', return_value=current):
                with self.assertRaisesRegex(RuntimeError, 'no artifact replacement'):
                    upgrade.verify_stopped_job(root, label, b'original-job')
        with patch.object(upgrade, 'launchd_pid', return_value=None), patch.object(upgrade.shared, 'private', return_value=b'original-job'):
            upgrade.verify_stopped_job(root, label, b'original-job')


if __name__ == '__main__':
    unittest.main()
