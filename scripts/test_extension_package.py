#!/usr/bin/env python3
"""Pure extension packaging/upgrade fixtures; no browser or signing actions."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import extension_package as package
spec = importlib.util.spec_from_file_location('runtime_upgrade', Path(__file__).with_name('upgrade-runtime.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def fixture(path, version):
    path.mkdir(parents=True, mode=0o700)
    for name in package.FILES:
        data = ('// ' + version + ' ' + name).encode()
        if name == 'manifest.json':
            data = json.dumps({'manifest_version': 3, 'name': version,
                               'background': {'service_worker': 'worker.js', 'type': 'module'},
                               'options_page': 'options.html'}).encode()
        (path / name).write_bytes(data)
        (path / name).chmod(0o600)
    return package.inventory(path)


class ExtensionPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'source'
        self.expected = fixture(self.source, 'new-desktop-worker')

    def test_build_filters_development_files_and_pins_exact_runtime_set(self):
        (self.source / 'node_modules').mkdir()
        (self.source / 'node_modules/private-file').write_bytes(b'never-package')
        (self.source / 'README.md').write_bytes(b'never-package')
        destination = self.root / 'dist/extension/chrome'
        result = package.build(self.source, destination)
        self.assertEqual(result, self.expected)
        self.assertEqual(len(package.FILES), 11)
        self.assertEqual({p.name for p in destination.iterdir()}, set(package.FILES))
        self.assertTrue((destination / 'retirement.js').is_file())
        self.assertEqual(package.verify(destination, result['files'], result['sha256']), result)
        self.assertEqual((destination / 'worker.js').read_bytes(), (self.source / 'worker.js').read_bytes())
        self.assertEqual((self.source / 'README.md').read_bytes(), b'never-package')
        self.assertEqual(result['sha256'], hashlib.sha256(json.dumps(result['files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        # The real build recipe records the shared helper's inventory beside
        # signed artifacts without executing compilers or touching dist outputs.
        tree = ast.parse(Path(__file__).with_name('build-development.py').read_text())
        strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertTrue({'extension', 'extensionFiles', 'extensionSHA256'} <= strings)
        self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and
                            isinstance(n.func.value, ast.Name) and n.func.value.id == 'extension_package' and n.func.attr == 'build'
                            for n in ast.walk(tree)))

    def test_exact_set_hash_modes_links_and_manifest_fail_closed(self):
        for bad in ['extra', 'missing', 'missing-retirement', 'changed', 'digest', 'inventory', 'file-mode', 'directory-mode', 'symlink', 'hardlink', 'entry-point']:
            with self.subTest(bad=bad):
                target = self.root / bad
                fixture(target, 'new-desktop-worker')
                expected = copy.deepcopy(self.expected)
                if bad == 'extra': (target / 'unlisted.js').write_bytes(b'never-load')
                elif bad == 'missing': (target / 'content.js').unlink()
                elif bad == 'missing-retirement': (target / 'retirement.js').unlink()
                elif bad == 'changed': (target / 'worker.js').write_bytes(b'old-worker')
                elif bad == 'digest': expected['sha256'] = '0' * 64
                elif bad == 'inventory': expected['files']['../unlisted.js'] = '0' * 64
                elif bad == 'file-mode': (target / 'worker.js').chmod(0o660)
                elif bad == 'directory-mode': target.chmod(0o770)
                elif bad == 'symlink':
                    (target / 'worker.js').unlink(); (target / 'worker.js').symlink_to(self.source / 'worker.js')
                elif bad == 'hardlink':
                    (target / 'worker.js').unlink(); os.link(self.source / 'worker.js', target / 'worker.js')
                elif bad == 'entry-point':
                    (target / 'manifest.json').write_text(json.dumps({'manifest_version': 3, 'background': {'service_worker': 'unlisted.js'}, 'options_page': 'options.html'}))
                    expected['files']['manifest.json'] = hashlib.sha256((target / 'manifest.json').read_bytes()).hexdigest()
                    expected['sha256'] = package.inventory_hash(expected['files'])
                with self.assertRaises((ValueError, OSError)):
                    package.verify(target, expected['files'], expected['sha256'])
                if bad == 'hardlink': (target / 'worker.js').unlink()

    def test_replacement_preserves_fixed_path_and_recovers_failed_directory_publication(self):
        destination = self.root / 'extension/chrome'
        original = fixture(destination, 'old-worker')
        previous_bytes = {name: (destination / name).read_bytes() for name in package.FILES}
        real_replace = package.os.replace

        def fail_stage(source, target):
            if Path(source).name.startswith('.extension-stage-') and Path(target) == destination:
                raise OSError('fixture publication failed')
            return real_replace(source, target)

        with mock.patch.object(package.os, 'replace', side_effect=fail_stage):
            with self.assertRaises(OSError): package.replace(self.source, destination, self.expected)
        self.assertEqual(package.inventory(destination), original)
        self.assertEqual({name: (destination / name).read_bytes() for name in package.FILES}, previous_bytes)
        package.replace(self.source, destination, self.expected)
        self.assertEqual(package.inventory(destination), self.expected)
        self.assertEqual(destination, self.root / 'extension/chrome')
        self.assertEqual([p.name for p in destination.parent.iterdir()], ['chrome'])

    def test_upgrade_snapshot_restores_exact_old_tree_and_rejects_tampering(self):
        installation = self.root / 'installation'
        artifacts = self.root / 'frozen/dist/development'
        old = fixture(installation / 'extension/chrome', 'old-worker')
        current = fixture(artifacts / 'extension/chrome', 'new-desktop-worker')
        manifest = {'extension': str(artifacts / 'extension/chrome'), 'extensionFiles': current['files'], 'extensionSHA256': current['sha256']}
        snapshot = upgrade.preflight_extension(installation, manifest, artifacts)
        backup = self.root / 'backup'; backup.mkdir(mode=0o700)
        record = {'chromeExtension': upgrade.backup_extension_snapshot(snapshot, backup)}
        self.assertEqual(package.inventory(backup / 'extension/chrome'), old)
        package.replace(artifacts / 'extension/chrome', snapshot['path'], current)
        restore = upgrade.rollback_extension_snapshot({}, {}, record, backup, installation)
        upgrade.restore_extension(restore, backup)
        self.assertEqual(package.inventory(snapshot['path']), old)
        # Lost target during a crash can be restored from exact private backup;
        # arbitrary existing bytes can never be silently overwritten.
        shutil.rmtree(snapshot['path'])
        restore = upgrade.rollback_extension_snapshot({}, {}, record, backup, installation)
        upgrade.restore_extension(restore, backup)
        self.assertEqual(package.inventory(snapshot['path']), old)
        (snapshot['path'] / 'worker.js').write_bytes(b'unrelated-edited-worker')
        with self.assertRaises(ValueError): upgrade.rollback_extension_snapshot({}, {}, record, backup, installation)
        package.replace(artifacts / 'extension/chrome', snapshot['path'], current)
        (backup / 'extension/chrome/worker.js').write_bytes(b'tampered-backup')
        with self.assertRaises(ValueError): upgrade.rollback_extension_snapshot({}, {}, record, backup, installation)

    def test_legacy_missing_extension_snapshot_is_conservative(self):
        installation = self.root / 'installation'; installation.mkdir(mode=0o700)
        backup = self.root / 'backup'; backup.mkdir(mode=0o700)
        self.assertIsNone(upgrade.rollback_extension_snapshot({}, {}, {}, backup, installation))
        with self.assertRaises(ValueError): upgrade.rollback_extension_snapshot({'chrome': {}}, {}, {}, backup, installation)
        fixture(installation / 'extension/chrome', 'existing-extension')
        with self.assertRaises(ValueError): upgrade.rollback_extension_snapshot({}, {}, {}, backup, installation)

    def test_manifest_identity_key_change_is_not_silently_published(self):
        installation = self.root / 'installation'
        fixture(installation / 'extension/chrome', 'old-worker')
        manifest = json.loads((self.source / 'manifest.json').read_bytes()); manifest['key'] = 'different-public-extension-key'
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        expected = package.inventory(self.source)
        artifacts = self.root / 'artifacts'
        (artifacts / 'extension').mkdir(parents=True, mode=0o700)
        package.copy(self.source, artifacts / 'extension/chrome', expected)
        with self.assertRaises(ValueError): upgrade.preflight_extension(installation, {'extensionFiles': expected['files'], 'extensionSHA256': expected['sha256']}, artifacts)

    def test_enrolled_exact_chrome_and_native_host_must_be_stopped(self):
        installation = self.root / 'installation'
        config = {'chrome': {'processTrust': {'chromeExecutable': '/fixture/Google Chrome'}}}
        for executable in ['/fixture/Google Chrome', str(installation / 'mechanize-native-host')]:
            running = f'77 {os.getuid()} {executable}\n'.encode()
            with mock.patch.object(upgrade, 'run', return_value=subprocess.CompletedProcess([], 0, running, b'')) as run:
                with self.assertRaises(ValueError): upgrade.require_chrome_stopped(config, installation)
                self.assertIn('-ww', run.call_args.args)
        unrelated = f'77 {os.getuid()} /unrelated/Chrome\n'.encode()
        with mock.patch.object(upgrade, 'run', return_value=subprocess.CompletedProcess([], 0, unrelated, b'')):
            upgrade.require_chrome_stopped(config, installation)
        with mock.patch.object(upgrade, 'run', side_effect=AssertionError('no Chrome process enrollment consulted')):
            upgrade.require_chrome_stopped({}, installation)

    def test_build_manifest_extension_inventory_is_mandatory_and_rechecked(self):
        source = self.root / 'frozen'
        artifacts = source / 'dist/development'
        extension = artifacts / 'extension/chrome'
        expected = fixture(extension, 'new-desktop-worker')
        broker = 'identifier "com.viant.mechanize.broker" and cdhash H"' + 'a' * 40 + '"'
        account = 'com.viant.mechanize.consent:' + str(os.getuid()) + ':' + 'a' * 32
        manifest = {'schemaVersion': 1, 'mode': 'development', 'productionQualified': False, 'sourceRoot': str(source),
                    'extension': str(extension), 'extensionFiles': expected['files'], 'extensionSHA256': expected['sha256'],
                    'brokerRequirement': broker, 'helperRequirement': 'fixture-helper-pin',
                    'nativeHostBrokerRequirement': broker, 'consoleEnrollmentAccount': account}
        for name, (filename, _) in upgrade.ARTIFACTS.items():
            target = artifacts / filename
            manifest[name] = str(target)
            manifest.setdefault(name + 'Requirement', 'fixture-' + name + '-pin')
            if name == 'console':
                (target / 'Contents').mkdir(parents=True)
                (target / 'Contents/Info.plist').write_bytes(plistlib.dumps({'MechanizeBrokerRequirement': broker,
                    'MechanizeHelperRequirement': manifest['helperRequirement'], 'MechanizeEnrollmentAccount': account}))
            else:
                target.write_bytes(broker.encode() if name == 'nativeHost' else b'fixture-image')
                manifest[name + 'SHA256'] = hashlib.sha256(target.read_bytes()).hexdigest()
        with mock.patch.object(upgrade, 'verify'), mock.patch.object(upgrade, 'helper_metadata', return_value={'MechanizeBrokerRequirement': broker}):
            upgrade.verify_manifest(source, manifest, artifacts)
            for missing in ['extension', 'extensionFiles', 'extensionSHA256']:
                invalid = copy.deepcopy(manifest); invalid.pop(missing)
                with self.assertRaises(ValueError): upgrade.verify_manifest(source, invalid, artifacts)
            (extension / 'worker.js').write_bytes(b'old-pre-desktop-worker')
            with self.assertRaises(ValueError): upgrade.verify_manifest(source, manifest, artifacts)



class LegacyExtensionCompatibilityTests(unittest.TestCase):
    def test_exact_historical_backups_upgrade_and_rollback_without_accepting_arbitrary_subsets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            self.assertEqual(len(package.FILES), 11)
            self.assertEqual(len(package.OLDEST_LEGACY_FILES), 9)
            self.assertEqual(len(package.INTERMEDIATE_LEGACY_FILES), 10)
            source = root / 'source'
            new = fixture(source, 'new-v3-with-retirement')
            manifest = {'extensionFiles': new['files'], 'extensionSHA256': new['sha256']}
            artifacts = root / 'runtime'
            (artifacts / 'extension').mkdir(mode=0o700, parents=True)
            package.copy(source, artifacts / 'extension/chrome', new)

            historical_versions = [
                ('oldest-v1', package.OLDEST_LEGACY_FILES,
                 {'fingerprint.js', 'retirement.js'}),
                ('intermediate-v2', package.INTERMEDIATE_LEGACY_FILES,
                 {'retirement.js'}),
            ]
            for version, expected_files, removed_files in historical_versions:
                with self.subTest(version=version):
                    installation = root / version / 'installed'
                    original = installation / 'extension/chrome'
                    original.parent.mkdir(mode=0o700, parents=True)
                    fixture(original, version)
                    for name in removed_files:
                        (original / name).unlink()

                    old = package.inventory(original, allow_legacy=True)
                    self.assertEqual(set(old['files']), set(expected_files))
                    self.assertEqual(len(old['files']), len(expected_files))
                    with self.assertRaises(ValueError):
                        package.inventory(original)
                    with self.assertRaises(ValueError):
                        package.inventory_hash(old['files'])
                    with self.assertRaises(ValueError):
                        package.verify(original, old['files'], old['sha256'])
                    self.assertEqual(package.verify(original, old['files'], old['sha256'], allow_legacy=True), old)

                    snapshot = upgrade.preflight_extension(installation, manifest, artifacts)
                    backup = root / (version + '-backup')
                    backup.mkdir(mode=0o700)
                    entry = upgrade.backup_extension_snapshot(snapshot, backup)
                    package.replace(artifacts / 'extension/chrome', original, new, allow_legacy=True)
                    self.assertEqual(package.inventory(original), new)
                    restore = upgrade.rollback_extension_snapshot({}, {}, {'chromeExtension': entry}, backup, installation)
                    upgrade.restore_extension(restore, backup)
                    self.assertEqual(package.inventory(original, allow_legacy=True), old)
                    self.assertEqual({p.name for p in original.iterdir()}, set(expected_files))

                    # Exact-set compatibility remains closed: missing an extra
                    # historical resource is not silently accepted as a third version.
                    arbitrary = installation / 'arbitrary'
                    fixture(arbitrary, version + '-arbitrary')
                    (arbitrary / 'retirement.js').unlink()
                    (arbitrary / 'content.js').unlink()
                    with self.assertRaises(ValueError):
                        package.inventory(arbitrary, allow_legacy=True)
                    with self.assertRaises(ValueError):
                        package.inventory_hash({name: '0' * 64 for name in set(expected_files) - {'content.js'}}
                                                , allow_legacy=True)

                    with self.assertRaises(ValueError):
                        upgrade.preflight_extension(installation,
                            {'extensionFiles': old['files'], 'extensionSHA256': old['sha256']}, backup)

if __name__ == '__main__':
    unittest.main()
