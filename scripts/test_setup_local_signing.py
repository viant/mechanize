import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("local_signing", Path(__file__).with_name("setup-local-signing.py"))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class LocalSigningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.home = Path(self.directory.name)
        self.commands = []
        self.identity_ready = False
        self.fail_import = False
        self.fail_trust = False
        self.fingerprint = hashlib.sha1(b"public-certificate-der").hexdigest().upper()
        self.old_umask = os.umask(0o077)
        self.home_patch = patch.object(Path, "home", return_value=self.home)
        self.run_patch = patch.object(signing, "run", side_effect=self.fake_run)
        self.home_patch.start()
        self.run_patch.start()

    def tearDown(self):
        self.run_patch.stop()
        self.home_patch.stop()
        os.umask(self.old_umask)
        self.directory.cleanup()

    def fake_run(self, args, timeout=90):
        self.commands.append(args)
        if args[:2] == ["security", "default-keychain"]:
            return b'"/fixture/login.keychain-db"\n'
        if args[:2] == ["security", "find-identity"]:
            return ('1) ' + self.fingerprint + ' "Mechanize Local Development"\n').encode() if self.identity_ready else b"0 valid identities found\n"
        if args[:2] == ["openssl", "genpkey"]:
            Path(args[args.index("-out") + 1]).write_bytes(b"private-key-canary")
        elif args[:2] == ["openssl", "pkey"]:
            Path(args[args.index("-out") + 1]).write_bytes(Path(args[args.index("-in") + 1]).read_bytes())
        elif args[:2] == ["openssl", "req"]:
            Path(args[args.index("-out") + 1]).write_bytes(b"public certificate")
        elif args[:2] == ["openssl", "x509"]:
            return b"public-certificate-der"
        elif args[:2] == ["security", "import"]:
            if self.fail_import:
                raise RuntimeError("fixture import outcome unknown")
        elif args[:2] == ["security", "add-trusted-cert"]:
            if self.fail_trust:
                raise RuntimeError("fixture trust outcome unknown")
            self.identity_ready = True
        return b""

    def test_success_keeps_private_key_only_in_nonextractable_scoped_keychain(self):
        result = signing.setup(create=True)
        self.assertTrue(result["ready"])
        root = self.home / ".secret/mechanize-signing"
        self.assertEqual({p.name for p in root.iterdir()}, {"certificate.pem", "identity.json"})
        self.assertNotIn("private-key-canary", (root / "identity.json").read_text())
        imported = next(c for c in self.commands if c[:2] == ["security", "import"])
        self.assertIn("-x", imported)
        self.assertEqual(imported[imported.index("-T") + 1], "/usr/bin/codesign")
        self.assertNotIn("-A", imported)
        trust = next(c for c in self.commands if c[:2] == ["security", "add-trusted-cert"])
        self.assertEqual(trust[trust.index("-p") + 1], "codeSign")
        self.assertNotIn("-d", trust)

    def test_unknown_key_import_is_not_replayed_or_replaced(self):
        self.fail_import = True
        with self.assertRaises(RuntimeError):
            signing.setup(create=True)
        count = len([c for c in self.commands if c[:2] == ["security", "import"]])
        with self.assertRaisesRegex(RuntimeError, "NeedsInspection"):
            signing.setup(create=True)
        self.assertEqual(count, len([c for c in self.commands if c[:2] == ["security", "import"]]))
        state = json.loads((self.home / ".secret/mechanize-signing/identity.json").read_text())
        self.assertEqual(state["stage"], "keyImportAttempted")

    def test_lost_trust_reply_can_be_confirmed_without_repeating_mutation(self):
        self.fail_trust = True
        with self.assertRaises(RuntimeError):
            signing.setup(create=True)
        count = len(self.commands)
        self.identity_ready = True
        result = signing.setup(create=True)
        self.assertTrue(result["ready"])
        self.assertEqual([c[:2] for c in self.commands[count:]], [["security", "find-identity"]])


if __name__ == "__main__":
    unittest.main()
