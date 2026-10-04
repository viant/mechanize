#!/usr/bin/env python3
"""Initial package-copy fixtures only; no installation, signing, enrollment or UI."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install-development.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def requirement(identifier, value):
    return 'identifier "com.viant.mechanize.' + identifier + '" and cdhash H"' + value * 40 + '"'


class InitialPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'dist/development'
        self.source.mkdir(parents=True, mode=0o700)
        self.patch_root = mock.patch.object(installer, 'ROOT', self.root)
        self.patch_root.start(); self.addCleanup(self.patch_root.stop)
        self.command = mock.patch.object(installer, 'command')
        self.commands = self.command.start(); self.addCleanup(self.command.stop)
        self.manifest = {'schemaVersion': 1, 'mode': 'development', 'productionQualified': False, 'sourceRoot': str(self.root)}
        for index, (name, (filename, identifier)) in enumerate(installer.ARTIFACTS.items()):
            path = self.source / filename
            self.manifest[name] = str(path)
            self.manifest[name + 'Requirement'] = requirement(identifier, 'abcd'[index])
            if name == 'console':
                (path / 'Contents').mkdir(parents=True, mode=0o700)
                (path / 'Contents/fixture').write_bytes(b'fixture signed console')
            else:
                data = b'fixture-' + name.encode()
                if name == 'nativeHost': data += b'\x00' + self.manifest['brokerRequirement'].encode() + b'\x00'
                path.write_bytes(data); path.chmod(0o700)
                self.manifest[name + 'SHA256'] = hashlib.sha256(data).hexdigest()
        self.manifest['nativeHostBrokerRequirement'] = self.manifest['brokerRequirement']
        extension = self.source / 'extension/chrome'
        extension.mkdir(parents=True, mode=0o700)
        for filename in installer.extension_package.FILES:
            data = b'// runtime resource ' + filename.encode()
            if filename == 'manifest.json':
                data = json.dumps({'manifest_version': 3, 'name': 'Fixture',
                    'background': {'service_worker': 'worker.js', 'type': 'module'}, 'options_page': 'options.html'}).encode()
            (extension / filename).write_bytes(data); (extension / filename).chmod(0o600)
        inventory = installer.extension_package.inventory(extension)
        self.manifest.update(extension=str(extension), extensionFiles=inventory['files'], extensionSHA256=inventory['sha256'])

    def test_initial_copy_verifies_native_host_and_exact_extension_without_enrollment(self):
        destination = self.root / 'installation'
        destination.mkdir(mode=0o700)
        installed = installer.install_artifacts(self.manifest, destination)
        self.assertEqual(set(installed), {'broker', 'helper', 'console', 'nativeHost', 'extension'})
        self.assertEqual(installed['nativeHost'], str(destination / 'mechanize-native-host'))
        self.assertEqual(installed['extension'], str(destination / 'extension/chrome'))
        self.assertEqual((destination / 'mechanize-native-host').read_bytes(), Path(self.manifest['nativeHost']).read_bytes())
        self.assertEqual((destination / 'mechanize-native-host').stat().st_mode & 0o777, 0o700)
        self.assertEqual(installer.extension_package.inventory(destination / 'extension/chrome'),
                         {'files': self.manifest['extensionFiles'], 'sha256': self.manifest['extensionSHA256']})
        pins = [call.args for call in self.commands.call_args_list]
        self.assertTrue(any(str(destination / 'mechanize-native-host') in args and '=' + self.manifest['nativeHostRequirement'] in args for args in pins))
        self.assertTrue(all(args[0] == 'codesign' for args in pins))
        self.assertEqual({p.name for p in destination.iterdir()}, {'mechanize', 'mechanize-native', 'Mechanize Permissions.app', 'mechanize-native-host', 'extension'})
        # Preserve the installer's existing identity/consent setup; packaging
        # never invents Chrome process trust, grants or native-host registration.
        tree = ast.parse(Path(__file__).with_name('install-development.py').read_text())
        config = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign) and
                      any(isinstance(target, ast.Name) and target.id == 'config' for target in node.targets))
        self.assertIsInstance(config, ast.Dict)
        self.assertNotIn('chrome', [key.value for key in config.keys])
        self.assertFalse((destination / 'native-host.json').exists())
        self.assertFalse((destination / 'NativeMessagingHosts').exists())

    def test_missing_native_host_or_extension_manifest_metadata_fails_before_copy(self):
        for field in ['nativeHost', 'nativeHostRequirement', 'nativeHostSHA256', 'nativeHostBrokerRequirement', 'extension', 'extensionFiles', 'extensionSHA256']:
            with self.subTest(field=field):
                invalid = copy.deepcopy(self.manifest); invalid.pop(field)
                destination = self.root / ('missing-' + field); destination.mkdir(mode=0o700)
                with self.assertRaises((RuntimeError, ValueError)):
                    installer.install_artifacts(invalid, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_native_host_exact_identity_digest_and_reverse_pin_are_mandatory(self):
        for case in ['identifier', 'publisher-only', 'digest', 'reverse-metadata', 'reverse-bytes', 'multiple-pins']:
            with self.subTest(case=case):
                invalid = copy.deepcopy(self.manifest)
                host = Path(self.manifest['nativeHost'])
                original = host.read_bytes()
                if case == 'identifier': invalid['nativeHostRequirement'] = requirement('chromeXnativehost', 'd')
                elif case == 'publisher-only': invalid['nativeHostRequirement'] = 'identifier "com.viant.mechanize.chrome.nativehost"'
                elif case == 'digest': invalid['nativeHostSHA256'] = '0' * 64
                elif case == 'reverse-metadata': invalid['nativeHostBrokerRequirement'] = requirement('broker', 'e')
                elif case == 'reverse-bytes':
                    host.write_bytes(b'no embedded broker pin'); invalid['nativeHostSHA256'] = hashlib.sha256(host.read_bytes()).hexdigest()
                else:
                    host.write_bytes(original + requirement('broker', 'e').encode()); invalid['nativeHostSHA256'] = hashlib.sha256(host.read_bytes()).hexdigest()
                try:
                    with self.assertRaises(RuntimeError): installer.verify_package(invalid)
                finally:
                    host.write_bytes(original)

    def test_file_safeguards_prevent_symlinks_shared_write_and_linked_native_host(self):
        host = Path(self.manifest['nativeHost'])
        original = host.read_bytes()
        host.chmod(0o770)
        with self.assertRaises(RuntimeError): installer.verify_package(self.manifest)
        host.chmod(0o700)
        link = self.root / 'hardlink'; os.link(host, link)
        with self.assertRaises(RuntimeError): installer.verify_package(self.manifest)
        link.unlink()
        actual = self.root / 'actual-host'; host.rename(actual); host.symlink_to(actual)
        with self.assertRaises(RuntimeError): installer.verify_package(self.manifest)
        host.unlink(); actual.rename(host)
        self.assertEqual(host.read_bytes(), original)
        shared = self.source / 'Mechanize Permissions.app/Contents/fixture'
        shared.chmod(0o666)
        with self.assertRaises(RuntimeError): installer.verify_package(self.manifest)

    def test_extension_drift_and_nonfresh_destinations_are_rejected(self):
        target = self.root / 'occupied'; target.mkdir(mode=0o700); (target / 'unrelated').write_bytes(b'preserve')
        with self.assertRaises(RuntimeError): installer.install_artifacts(self.manifest, target)
        self.assertEqual((target / 'unrelated').read_bytes(), b'preserve')
        extension = Path(self.manifest['extension'])
        for change in ['changed', 'extra', 'bad-hash']:
            with self.subTest(change=change):
                invalid = copy.deepcopy(self.manifest)
                original = (extension / 'worker.js').read_bytes()
                if change == 'changed': (extension / 'worker.js').write_bytes(b'old-worker')
                elif change == 'extra': (extension / 'unexpected.js').write_bytes(b'not-allowed')
                else: invalid['extensionSHA256'] = '0' * 64
                destination = self.root / ('extension-' + change); destination.mkdir(mode=0o700)
                try:
                    with self.assertRaises(ValueError): installer.install_artifacts(invalid, destination)
                    self.assertEqual(list(destination.iterdir()), [])
                finally:
                    (extension / 'worker.js').write_bytes(original)
                    if (extension / 'unexpected.js').exists(): (extension / 'unexpected.js').unlink()


if __name__ == '__main__':
    unittest.main()
