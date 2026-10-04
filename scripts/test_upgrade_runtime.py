#!/usr/bin/env python3
"""Fixture-only runtime/Chrome pin upgrade tests; no installed files or processes."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('runtime_upgrade', Path(__file__).with_name('upgrade-runtime.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def pin(identifier, value):
    return 'identifier "com.viant.mechanize.' + identifier + '" and cdhash H"' + value * 40 + '"'


def extension_fixture(path, label):
    path.mkdir(parents=True, mode=0o700)
    for name in upgrade.extension_package.FILES:
        payload = (label + ':' + name).encode()
        if name == 'manifest.json':
            payload = upgrade.encode({'manifest_version': 3, 'name': label,
                                      'background': {'service_worker': 'worker.js', 'type': 'module'},
                                      'options_page': 'options.html'})
        upgrade.atomic(path / name, payload)
    return upgrade.extension_package.inventory(path)


class ChromeUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root, self.backup = self.base / 'installation', self.base / 'backup'
        self.root.mkdir(mode=0o700)
        self.backup.mkdir(mode=0o700)
        self.external_path = self.base / 'native-host.json'
        self.old_broker, self.old_host = pin('broker', 'a'), pin('chrome.nativehost', 'b')
        self.manifest = {'brokerRequirement': pin('broker', 'c'), 'nativeHostRequirement': pin('chrome.nativehost', 'd')}
        trust = {'expectedUID': os.getuid(), 'nativeHostExecutable': str(self.root / 'mechanize-native-host'),
                 'nativeHostRequirement': self.old_host, 'chromeExecutable': '/fixture/Chrome',
                 'chromeRequirement': 'opaque-original-chrome-pin', 'maximumAncestors': 1}
        resource = {'URL': str(self.base / 'unread-secret.sec'), 'Key': 'blowfish://file' + str(self.base / 'unread-secret.key')}
        grant = {'profileChannel': 'enrolled-channel', 'browserInstance': 'enrolled-browser',
                 'extensionOrigin': 'chrome-extension://' + 'a' * 32 + '/',
                 'profileDirectory': str(self.base / 'profile/Default'), 'credentialResource': resource}
        self.config = {'chrome': {'socketPath': str(self.base / 'broker.sock'), 'fixtureEnrollment': False,
                                  'processTrust': trust, 'grants': [grant]}}
        self.external = {'socketPath': self.config['chrome']['socketPath'], 'fixtureEnrollment': False,
                         'processTrust': copy.deepcopy(trust), 'brokerRequirement': self.old_broker, **copy.deepcopy(grant)}
        self.original = upgrade.encode(self.external)
        upgrade.atomic(self.external_path, self.original)
        self.path_patch = mock.patch.object(upgrade, 'chrome_native_host_path', return_value=self.external_path)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

    def preflight(self):
        with mock.patch.object(upgrade, 'verify') as verify:
            result = upgrade.preflight_chrome_native_host(self.config, self.root, self.old_broker, self.manifest)
        self.assertEqual(verify.call_args_list, [mock.call(self.root / 'mechanize', self.old_broker, 'broker'),
                                               mock.call(self.root / 'mechanize-native-host', self.old_host, 'chrome.nativehost')])
        return result

    def test_desktop_scope_requires_explicit_user_and_preserves_resources(self):
        principal = {'issuer': 'fixture', 'subject': 'owner', 'tenant': ''}
        self.config['identityPolicy'] = {'issuer': 'fixture'}
        self.config['users'] = [{'subject': 'owner', 'desktopAccess': True}]
        self.config['chrome']['grants'][0]['principal'] = principal
        snapshot = self.preflight()
        updated = copy.deepcopy(self.config)
        original_resource = copy.deepcopy(updated['chrome']['grants'][0]['credentialResource'])
        upgrade.enable_desktop_browser_scope(updated, snapshot)
        grant = updated['chrome']['grants'][0]
        external = json.loads(snapshot['after'])
        self.assertEqual(grant['trustScope'], 'desktop')
        self.assertEqual(grant['profileDirectory'], '')
        self.assertEqual(external['trustScope'], 'desktop')
        self.assertEqual(external['profileDirectory'], '')
        self.assertEqual(grant['credentialResource'], original_resource)
        self.assertEqual(external['credentialResource'], original_resource)
        # Native-host signature pin is normally updated in the broker copy too.
        updated['chrome']['processTrust']['nativeHostRequirement'] = self.manifest['nativeHostRequirement']
        upgrade.validate_chrome_native_host(updated, external, self.root, self.manifest['brokerRequirement'])
        for change in ('permission', 'identity', 'fixture'):
            candidate = copy.deepcopy(self.config)
            if change == 'permission': candidate['users'][0]['desktopAccess'] = False
            elif change == 'identity': candidate['chrome']['grants'][0]['principal']['subject'] = 'other'
            else: candidate['chrome']['fixtureEnrollment'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                upgrade.enable_desktop_browser_scope(candidate, copy.deepcopy(snapshot))
        self.assertNotIn('trustScope', self.config['chrome']['grants'][0])
        self.assertEqual(upgrade.private(self.external_path), self.original)

    def record(self, snapshot):
        entry = upgrade.backup_chrome_snapshot(snapshot, self.backup)
        return {'chromeNativeHost': entry, 'artifacts': {'broker': {'requirement': self.old_broker},
                                                       'nativeHost': {'requirement': self.old_host}}}

    def test_preflight_preserves_everything_except_exact_two_pins(self):
        before = copy.deepcopy(self.config)
        snapshot = self.preflight()
        expected = copy.deepcopy(self.external)
        expected['brokerRequirement'] = self.manifest['brokerRequirement']
        expected['processTrust']['nativeHostRequirement'] = self.manifest['nativeHostRequirement']
        self.assertEqual(json.loads(snapshot['after']), expected)
        self.assertEqual(snapshot['before'], self.original)
        self.assertEqual(self.external_path.read_bytes(), self.original)
        self.assertEqual(self.config, before)
        self.assertFalse((self.base / 'unread-secret.sec').exists())
        self.assertFalse((self.base / 'unread-secret.key').exists())

    def test_no_chrome_never_consults_external_file_or_missing_legacy_snapshot(self):
        with mock.patch.object(upgrade, 'private', side_effect=AssertionError('external file consulted')), \
             mock.patch.object(upgrade, 'chrome_native_host_path', side_effect=AssertionError('external path consulted')):
            self.assertIsNone(upgrade.preflight_chrome_native_host({}, self.root, self.old_broker, self.manifest))
            self.assertIsNone(upgrade.rollback_chrome_snapshot({}, {}, {}, self.backup, self.root))
        for current, saved in [(self.config, {}), ({}, self.config), (self.config, self.config)]:
            with mock.patch.object(upgrade, 'private', side_effect=AssertionError('legacy Chrome snapshot guessed')):
                with self.assertRaises(ValueError):
                    upgrade.rollback_chrome_snapshot(current, saved, {}, self.backup, self.root)

    def test_preflight_rejects_mismatched_or_ambiguous_enrollment(self):
        mutations = [lambda ext, cfg: ext.update(brokerRequirement=pin('broker', 'f')),
                     lambda ext, cfg: ext['processTrust'].update(nativeHostRequirement=pin('chrome.nativehost', 'f')),
                     lambda ext, cfg: ext.update(socketPath='/different/socket'),
                     lambda ext, cfg: ext.update(profileChannel='different'),
                     lambda ext, cfg: ext.update(browserInstance='different'),
                     lambda ext, cfg: ext.update(extensionOrigin='chrome-extension://' + 'b' * 32 + '/'),
                     lambda ext, cfg: ext.update(profileDirectory='/different/Default'),
                     lambda ext, cfg: ext['credentialResource'].update(URL='/different/secret.sec'),
                     lambda ext, cfg: cfg['chrome']['grants'].append(copy.deepcopy(cfg['chrome']['grants'][0])),
                     lambda ext, cfg: cfg['chrome']['processTrust'].update(nativeHostExecutable='/different/native-host'),
                     lambda ext, cfg: ext.update(fixtureEnrollment=True),
                     lambda ext, cfg: ext.update(unrecognized='private-value-not-for-output')]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                external, config = copy.deepcopy(self.external), copy.deepcopy(self.config)
                mutate(external, config)
                upgrade.atomic(self.external_path, upgrade.encode(external))
                with mock.patch.object(upgrade, 'verify') as verify:
                    with self.assertRaises(ValueError) as rejected:
                        upgrade.preflight_chrome_native_host(config, self.root, self.old_broker, self.manifest)
                verify.assert_not_called()
                self.assertNotIn('private-value', str(rejected.exception))

    def test_private_external_ownership_modes_and_symlinks_remain_enforced(self):
        self.external_path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.preflight()
        self.external_path.chmod(0o600)
        original = self.base / 'original-native-host.json'
        self.external_path.rename(original)
        self.external_path.symlink_to(original)
        with self.assertRaises(ValueError):
            self.preflight()

    def test_backup_rollback_restores_original_for_partial_or_complete_apply(self):
        snapshot = self.preflight()
        record = self.record(snapshot)
        self.assertEqual(upgrade.private(self.backup / 'chrome-native-host.json'), self.original)
        self.assertEqual((self.backup / 'chrome-native-host.json').stat().st_mode & 0o777, 0o600)
        for payload in [snapshot['before'], snapshot['after']]:
            upgrade.atomic(self.external_path, payload)
            restore = upgrade.rollback_chrome_snapshot(self.config, self.config, record, self.backup, self.root)
            self.assertEqual(restore['after'], self.original)
            self.assertEqual(restore['before'], payload)
            upgrade.check_chrome_snapshot(restore)
            upgrade.atomic(restore['path'], restore['after'])
            self.assertEqual(self.external_path.read_bytes(), self.original)

    def test_changed_external_and_backup_records_fail_closed(self):
        snapshot = self.preflight()
        record = self.record(snapshot)
        upgrade.atomic(self.external_path, self.original + b' ')
        with self.assertRaises(ValueError):
            upgrade.check_chrome_snapshot(snapshot)
        with self.assertRaises(ValueError):
            upgrade.rollback_chrome_snapshot(self.config, self.config, record, self.backup, self.root)
        upgrade.atomic(self.external_path, self.original)
        for change in ['path', 'digest', 'saved_bytes', 'artifact_pin']:
            with self.subTest(change=change):
                altered = copy.deepcopy(record)
                if change == 'path':
                    altered['chromeNativeHost']['path'] = str(self.base / 'unrelated.json')
                elif change == 'digest':
                    altered['chromeNativeHost']['originalSHA256'] = 'invalid'
                elif change == 'saved_bytes':
                    upgrade.atomic(self.backup / 'chrome-native-host.json', self.original + b' ')
                else:
                    altered['artifacts']['nativeHost']['requirement'] = pin('chrome.nativehost', 'f')
                with self.assertRaises(ValueError):
                    upgrade.rollback_chrome_snapshot(self.config, self.config, altered, self.backup, self.root)
                upgrade.atomic(self.backup / 'chrome-native-host.json', self.original)

    def test_stopped_gate_checks_exact_native_host_process(self):
        running = f'77 {os.getuid()} {self.root / "mechanize-native-host"}\n'.encode()
        with mock.patch.object(upgrade, 'run', return_value=subprocess.CompletedProcess([], 0, running, b'')):
            with self.assertRaises(RuntimeError):
                upgrade.require_helpers_stopped(self.root)
        other = f'77 {os.getuid()} /unrelated/native-host\n'.encode()
        with mock.patch.object(upgrade, 'run', return_value=subprocess.CompletedProcess([], 0, other, b'')):
            upgrade.require_helpers_stopped(self.root)

    def test_apply_and_rollback_external_snapshot_while_stopped(self):
        source = self.base / 'frozen'
        artifacts = source / 'dist/development'
        artifacts.mkdir(parents=True, mode=0o700)
        manifest = {**self.manifest, 'sourceRoot': str(source), 'consoleRequirement': pin('consent', 'e'),
                    'helperRequirement': pin('native', 'f'), 'consoleEnrollmentAccount': 'new-account'}
        original_extension = extension_fixture(self.root / 'extension/chrome', 'old-worker')
        updated_extension = extension_fixture(artifacts / 'extension/chrome', 'new-desktop-worker')
        manifest.update(extension=str(artifacts / 'extension/chrome'), extensionFiles=updated_extension['files'],
                        extensionSHA256=updated_extension['sha256'])
        for directory, prefix, broker, helper, account, console in [
                (self.root, b'old-', self.old_broker, pin('native', '1'), 'old-account', pin('consent', '2')),
                (artifacts, b'new-', manifest['brokerRequirement'], manifest['helperRequirement'], 'new-account', manifest['consoleRequirement'])]:
            for filename in ['mechanize', 'mechanize-native', 'mechanize-native-host']:
                (directory / filename).write_bytes(prefix + filename.encode())
                (directory / filename).chmod(0o700)
            plist_dir = directory / 'Mechanize Permissions.app/Contents'
            plist_dir.mkdir(parents=True)
            (plist_dir / 'Info.plist').write_bytes(plistlib.dumps({'MechanizeBrokerRequirement': broker,
                                                                  'MechanizeHelperRequirement': helper,
                                                                  'MechanizeEnrollmentAccount': account,
                                                                  'fixtureSignature': console}))
        config = {**self.config, 'sourceRoot': '/old-frozen-source', 'nativeConsole': {'designatedRequirement': pin('consent', '2')}}
        original_config = upgrade.encode(config)
        upgrade.atomic(self.root / 'config.json', original_config)
        manifest_path = artifacts / 'manifest.json'
        upgrade.atomic(manifest_path, upgrade.encode(manifest))
        states, stages = [], []
        stopped = {'value': False}

        def requirement(app):
            return plistlib.loads((app / 'Contents/Info.plist').read_bytes())['fixtureSignature']

        def run(*args, **kwargs):
            if args[0] != 'codesign':
                return subprocess.CompletedProcess(args, 0, b'', b'')
            name = Path(args[-1]).name
            hashes = {'mechanize': 'a', 'mechanize-native': '1', 'mechanize-native-host': 'b', 'Mechanize Permissions.app': '2'}
            return subprocess.CompletedProcess(args, 0, b'', ('CDHash=' + hashes[name] * 40 + '\n').encode())

        def stop(*args):
            states.append('stop')
            stopped['value'] = True

        def start(*args):
            self.assertTrue(stopped['value'])
            current_config = json.loads(upgrade.private(self.root / 'config.json'))
            external = json.loads(upgrade.private(self.external_path))
            self.assertEqual(external['processTrust'], current_config['chrome']['processTrust'])
            if states.count('start') == 0:
                self.assertEqual(external['brokerRequirement'], manifest['brokerRequirement'])
                self.assertEqual(upgrade.extension_package.inventory(self.root / 'extension/chrome'), updated_extension)
            else:
                self.assertEqual(external['brokerRequirement'], self.old_broker)
                self.assertEqual(upgrade.extension_package.inventory(self.root / 'extension/chrome'), original_extension)
            states.append('start')
            stopped['value'] = False
            return 999

        real_atomic = upgrade.atomic

        def atomic(path, payload):
            if path == self.external_path:
                self.assertTrue(stopped['value'], 'external pins changed with live broker')
                states.append('external_write')
            real_atomic(path, payload)

        real_extension_replace = upgrade.extension_package.replace

        def replace_extension(source, target, expected, allow_legacy=False):
            self.assertEqual(target, self.root / 'extension/chrome')
            self.assertTrue(stopped['value'], 'extension changed with live broker')
            states.append('extension_write')
            real_extension_replace(source, target, expected, allow_legacy=allow_legacy)

        with mock.patch.object(upgrade, 'verify'), mock.patch.object(upgrade, 'verify_manifest'), \
                mock.patch.object(upgrade, 'run', side_effect=run), \
                mock.patch.object(upgrade.shared, 'requirement', side_effect=requirement), \
                mock.patch.object(upgrade.shared, 'process_identity'), \
                mock.patch.object(upgrade.shared, 'stop_consoles'), \
                mock.patch.object(upgrade.shared, 'stop', side_effect=stop), \
                mock.patch.object(upgrade.shared, 'start', side_effect=start), \
                mock.patch.object(upgrade.shared, 'enroll'), \
                mock.patch.object(upgrade, 'report_health', return_value={'connectionVerified': False}), \
                mock.patch.object(upgrade, 'atomic', side_effect=atomic), \
                mock.patch.object(upgrade.extension_package, 'replace', side_effect=replace_extension), \
                mock.patch.object(upgrade.sys, 'platform', 'darwin'):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(upgrade.sys, 'argv', [
                    'upgrade-runtime.py', '--source', str(source), '--manifest', str(manifest_path),
                    '--installation', str(self.root), '--apply', '--broker-pid', '77', '--idle-verified']):
                upgrade.main()
            reports = [json.loads(line) for line in output.getvalue().splitlines()]
            backup = Path(reports[0]['backup'])
            stages.append(Path(reports[0]['stage']))
            self.assertEqual(upgrade.private(backup / 'chrome-native-host.json'), self.original)
            self.assertEqual(json.loads(upgrade.private(backup / 'rollback.json'))['chromeNativeHost']['path'], str(self.external_path))
            self.assertEqual(json.loads(upgrade.private(backup / 'rollback.json'))['chromeExtension']['original'], original_extension)
            self.assertEqual(upgrade.extension_package.inventory(backup / 'extension/chrome'), original_extension)
            self.assertNotIn('unread-secret', output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(upgrade.sys, 'argv', [
                    'upgrade-runtime.py', '--rollback', str(backup), '--installation', str(self.root),
                    '--broker-pid', '999', '--idle-verified']):
                upgrade.main()
        self.assertEqual(states, ['stop', 'extension_write', 'external_write', 'start', 'stop', 'extension_write', 'external_write', 'start'])
        self.assertEqual(upgrade.private(self.root / 'config.json'), original_config)
        self.assertEqual(upgrade.private(self.external_path), self.original)
        for stage in stages:
            import shutil
            shutil.rmtree(stage)


if __name__ == '__main__':
    unittest.main()
