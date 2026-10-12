"""Fixture-only restart strategy checks; no processes or credentials are used."""
import importlib.util
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('console_strategy', Path(__file__).with_name('upgrade-console.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class ConsoleLaunchStrategyTests(unittest.TestCase):
    def fixture(self, arguments=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root / 'runtime').mkdir(mode=0o700)
        job = root / 'runtime/broker.plist'
        expected = [str(root / 'mechanize'), 'serve', '-config', str(root / 'config.json'), '-listen', '127.0.0.1:4987']
        job.write_bytes(plistlib.dumps({'Label': 'com.viant.mechanize.fixture', 'KeepAlive': False,
                                      'ProgramArguments': expected if arguments is None else arguments}))
        job.chmod(0o600)
        return root

    def test_preserves_launchd_and_waits_for_exec_without_relaunch(self):
        root = self.fixture()
        output = iter([b'state = waiting', b'', b'pid = 42', b'pid = 42'])
        with mock.patch.object(upgrade, 'run', side_effect=lambda *args: subprocess.CompletedProcess(args, 0, next(output))), \
             mock.patch.object(upgrade, 'process_identity', side_effect=[ValueError('pre-exec'), 'same-process']) as identity, \
             mock.patch.object(upgrade.time, 'sleep'), mock.patch.object(upgrade.subprocess, 'Popen') as direct:
            self.assertEqual(upgrade.start(root, '127.0.0.1:4987'), 42)
            self.assertEqual(identity.call_count, 2)
            direct.assert_not_called()

    def test_foreign_job_cannot_fall_back_to_direct_start(self):
        root = self.fixture(['/foreign/program'])
        with mock.patch.object(upgrade, 'run') as run, mock.patch.object(upgrade.subprocess, 'Popen') as direct:
            with self.assertRaisesRegex(ValueError, 'owned launchd'):
                upgrade.start(root, '127.0.0.1:4987')
            run.assert_not_called()
            direct.assert_not_called()

    def test_existing_job_process_is_not_restarted_or_signaled(self):
        root = self.fixture()
        with mock.patch.object(upgrade, 'run', return_value=subprocess.CompletedProcess([], 0, b'pid = 42')) as run:
            with self.assertRaisesRegex(ValueError, 'already running'):
                upgrade.start(root, '127.0.0.1:4987')
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
