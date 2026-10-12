import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import development_signing as signing


class SigningTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" and os.environ.get("MECHANIZE_TEST_SIGNING_IDENTITY_SHA1"), "explicit local certificate fixture only")
    def test_real_codesign_command_and_leaf_verification(self):
        identity = signing.select_identity(os.environ["MECHANIZE_TEST_SIGNING_IDENTITY_SHA1"])
        with tempfile.TemporaryDirectory(prefix="mechanize-signing-fixture-") as directory:
            artifact = Path(directory) / "fixture"
            subprocess.run(["/usr/bin/clang", "-x", "c", "-", "-o", str(artifact)], input=b"int main(void) { return 0; }", check=True, capture_output=True)
            subprocess.run(["codesign", *signing.signing_arguments(identity, "com.viant.mechanize.broker"), str(artifact)], check=True, capture_output=True)
            signing.verify_certificate(artifact, identity)
            subprocess.run(["codesign", "--verify", "--strict", "--test-requirement", '=identifier "com.viant.mechanize.broker" and certificate leaf = H"' + identity.lower() + '"', str(artifact)], check=True, capture_output=True)
            with self.assertRaises(ValueError):
                signing.verify_certificate(artifact, "AB" * 20)

    def test_stable_certificate_requirement_is_bound_to_one_role_and_leaf(self):
        fingerprint = "AB" * 20
        args = signing.signing_arguments(fingerprint, "com.viant.mechanize.broker")
        self.assertEqual(args[-1], '=designated => identifier "com.viant.mechanize.broker" and certificate leaf = H"' + fingerprint.lower() + '"')
        self.assertNotEqual(args[-1], signing.signing_arguments(fingerprint, "com.viant.mechanize.native")[-1])
        self.assertNotEqual(args[-1], signing.signing_arguments("CD" * 20, "com.viant.mechanize.broker")[-1])
        self.assertNotIn("--requirements", signing.signing_arguments("-", "com.viant.mechanize.broker"))
        for identifier in ['com.viant.mechanize.broker" or true', "", "a\n"]:
            with self.assertRaises(ValueError):
                signing.signing_arguments(fingerprint, identifier)

    def test_default_does_not_access_keychain(self):
        run = mock.Mock()
        with mock.patch.object(signing, "configured_identity", return_value=None):
            self.assertEqual(signing.select_identity(None, run), "-")
        signing.verify_certificate("unused", "-", run)
        run.assert_not_called()

    def test_configured_identity_is_reused_and_never_silently_downgraded(self):
        fingerprint = "AB" * 20
        run = mock.Mock(return_value=mock.Mock(stdout='  1) ' + fingerprint + ' "Development"\n'))
        with mock.patch.object(signing, "configured_identity", return_value=fingerprint):
            self.assertEqual(signing.select_identity(None, run), fingerprint)
            run.return_value.stdout = "0 valid identities found"
            with self.assertRaises(ValueError):
                signing.select_identity(None, run)

    def test_requires_exact_valid_identity(self):
        fingerprint = "AB" * 20
        run = mock.Mock(return_value=mock.Mock(stdout='  1) ' + fingerprint + ' "Development"\n'))
        self.assertEqual(signing.select_identity(fingerprint.lower(), run), fingerprint)
        for value in ["Development", "-", "A" * 39, "A" * 41, "A" * 39 + "G", "A" * 40 + "\n"]:
            with self.assertRaises(ValueError):
                signing.select_identity(value, run)
        run.return_value.stdout = "0 valid identities found"
        with self.assertRaises(ValueError):
            signing.select_identity(fingerprint, run)

    def test_verifies_actual_leaf_and_rejects_wrong_or_missing_certificate(self):
        data = b"fixture leaf DER"
        fingerprint = hashlib.sha1(data).hexdigest().upper()
        def extract(arguments, **options):
            Path(arguments[2].split("=", 1)[1] + "0").write_bytes(data)
        signing.verify_certificate("artifact", fingerprint, extract)
        with self.assertRaises(ValueError):
            signing.verify_certificate("artifact", "AB" * 20, extract)
        with self.assertRaises(ValueError):
            signing.verify_certificate("artifact", fingerprint, mock.Mock())


if __name__ == "__main__":
    unittest.main()
