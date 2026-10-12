"""Fixture-only exclusion tests; no installed runtime or credentials are used."""
import fcntl
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('console_lock', Path(__file__).with_name('upgrade-console.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class RuntimeLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / '.migration-placement.lock'

    def test_competing_open_and_updater_are_excluded(self):
        with upgrade.runtime_lock(self.root) as check:
            check()
            with self.assertRaisesRegex(ValueError, 'another runtime update'):
                with upgrade.runtime_lock(self.root):
                    self.fail('competing updater admitted')
            with self.path.open('rb') as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Never unlink the shared lock inode; next updater reuses it.
        inode = self.path.stat().st_ino
        with upgrade.runtime_lock(self.root):
            self.assertEqual(inode, self.path.stat().st_ino)

    def test_failure_releases_lock(self):
        with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
            with upgrade.runtime_lock(self.root):
                raise RuntimeError('fixture failure')
        with upgrade.runtime_lock(self.root) as check:
            check()

    def test_released_check_cannot_authorize_later_update(self):
        with upgrade.runtime_lock(self.root) as old_check:
            old_check()
        with upgrade.runtime_lock(self.root):
            with self.assertRaisesRegex(ValueError, 'lock released'):
                old_check()

    def test_replaced_lock_inode_is_detected_and_retained(self):
        displaced = self.root / 'retained-lock'
        with self.assertRaisesRegex(ValueError, 'lock changed'):
            with upgrade.runtime_lock(self.root) as check:
                self.path.rename(displaced)
                self.path.touch(mode=0o600)
                check()
        self.assertTrue(displaced.exists())
        self.assertTrue(self.path.exists())

    def test_lock_must_be_private_empty_regular_single_link(self):
        for kind in ('contents', 'permissions', 'hardlink', 'symlink', 'directory'):
            with self.subTest(kind=kind):
                if kind == 'directory':
                    self.path.mkdir()
                elif kind == 'symlink':
                    self.path.symlink_to(self.root / 'missing')
                else:
                    self.path.touch(mode=0o600)
                    if kind == 'contents':
                        self.path.write_bytes(b'fixture')
                    elif kind == 'permissions':
                        self.path.chmod(0o644)
                    elif kind == 'hardlink':
                        os.link(self.path, self.root / 'retained-link')
                with self.assertRaises((ValueError, OSError)):
                    with upgrade.runtime_lock(self.root):
                        self.fail('unsafe lock admitted')
                if self.path.is_dir():
                    self.path.rmdir()
                else:
                    self.path.unlink()

    def test_installation_must_remain_same_private_directory(self):
        with self.assertRaisesRegex(ValueError, 'lock changed'):
            with upgrade.runtime_lock(self.root) as check:
                self.root.chmod(0o755)
                check()
        self.root.chmod(0o700)

    def test_every_mutating_updater_joins_same_exclusion(self):
        scripts = {
            'upgrade-console.py': [],
            'upgrade-runtime.py': [],
            'upgrade-helper.py': ['--source-report', str(self.root / 'absent-report')],
            'extend-chrome-origins.py': ['--manifest', str(self.root / 'absent-manifest'),
                                         '--extension-id', 'a' * 32, '--all-websites'],
            'enroll-chrome.py': ['--manifest', str(self.root / 'absent-manifest'),
                                '--qualification-plan', str(self.root / 'absent-plan'),
                                '--extension-id', 'a' * 32],
        }
        with upgrade.runtime_lock(self.root):
            for filename, extra in scripts.items():
                with self.subTest(updater=filename):
                    module_spec = importlib.util.spec_from_file_location(
                        'competing_' + filename.replace('-', '_'), Path(__file__).with_name(filename))
                    module = importlib.util.module_from_spec(module_spec)
                    module_spec.loader.exec_module(module)
                    args = [filename, '--installation', str(self.root), '--apply', *extra]
                    with mock.patch('sys.argv', args), mock.patch('sys.platform', 'darwin'):
                        with self.assertRaisesRegex(ValueError, 'another runtime update'):
                            module.main()
        self.assertEqual({'.migration-placement.lock'}, {entry.name for entry in self.root.iterdir()})


if __name__ == '__main__':
    unittest.main()
