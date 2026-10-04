"""Window-click enrollment changes no user grants, credentials, or other modes."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('window_frame_upgrade', Path(__file__).with_name('upgrade-runtime.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class WindowFrameEnrollmentTests(unittest.TestCase):
    def test_explicit_semantic_enrollment_preserves_other_authority(self):
        config = {
            'nativeLaunch': {'mode': 'semantic', 'sessionKeyboard': False},
            'stdioCredential': {'URL': 'fixture://credential'},
            'users': [{'subject': 'fixture', 'nativeBundles': ['fixture.app']}],
            'nativeEffectReconciliation': ['native.focus.v1'],
        }
        expected = copy.deepcopy(config)
        expected['nativeLaunch']['windowFrameClick'] = True
        upgrade.enable_window_frame_click(config)
        self.assertEqual(expected, config)
        upgrade.enable_window_frame_click(config)
        self.assertEqual(expected, config)

    def test_missing_or_nonsemantic_profile_rejected_without_changes(self):
        for profile in (None, {}, {'mode': 'launch'}, {'mode': 'full'}, 'semantic'):
            with self.subTest(profile=profile):
                config = {'nativeLaunch': profile, 'users': [{'subject': 'fixture'}]}
                before = copy.deepcopy(config)
                with self.assertRaisesRegex(ValueError, 'semantic native profile'):
                    upgrade.enable_window_frame_click(config)
                self.assertEqual(before, config)


if __name__ == '__main__':
    unittest.main()
