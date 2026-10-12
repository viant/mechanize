import json
from pathlib import Path
import tempfile
import unittest

import playwright_package as package


class PlaywrightPackageTests(unittest.TestCase):
    def test_runtime_hash_covers_nested_code_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'nested').mkdir()
            code = root / 'nested' / 'engine.mjs'
            code.write_text('first')
            before = package.runtime_digest(root)
            code.write_text('changed')
            self.assertNotEqual(before, package.runtime_digest(root))
            (root / 'linked.mjs').symlink_to(code)
            with self.assertRaises(ValueError):
                package.runtime_digest(root)

    def test_group_writable_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            code = root / 'engine.mjs'
            code.write_text('fixture')
            code.chmod(0o664)
            with self.assertRaises(ValueError):
                package.runtime_digest(root)


if __name__ == '__main__':
    unittest.main()
