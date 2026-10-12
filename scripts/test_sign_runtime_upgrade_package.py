import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('package_signer', Path(__file__).with_name('sign-runtime-upgrade-package.py'))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


@unittest.skipUnless(shutil.which('openssl'), 'local OpenSSL required')
class SignedPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mechanize-review-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.key = self.root / 'key.pem'
        self.payload = self.root / 'reviewed.json'
        self.payload.write_bytes(b'{"version":1,"title":"Synthetic reviewed metadata"}')
        self.payload.chmod(0o600)
        p = subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(self.key)], stdin=subprocess.DEVNULL, capture_output=True)
        if p.returncode: self.skipTest('Ed25519 unavailable')
        self.key.chmod(0o600)

    def test_signature_binds_exact_payload_and_domain(self):
        output = self.root / 'signed.json'
        signer.sign(self.payload, self.key, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        envelope = json.loads(output.read_bytes())
        self.assertEqual(set(envelope), {'version', 'payloadBase64', 'signatureBase64'})
        payload = base64.b64decode(envelope['payloadBase64'], validate=True)
        self.assertEqual(payload, self.payload.read_bytes())
        signature = self.root / 'signature'
        signature.write_bytes(base64.b64decode(envelope['signatureBase64'], validate=True))
        public = self.root / 'public.pem'
        p = subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(public)], stdin=subprocess.DEVNULL, capture_output=True)
        self.assertEqual(p.returncode, 0)
        for valid, message in [(True, signer.DOMAIN + payload), (False, payload), (False, signer.DOMAIN + payload + b' ' )]:
            data = self.root / 'message'; data.write_bytes(message)
            p = subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public), '-in', str(data), '-sigfile', str(signature)], stdin=subprocess.DEVNULL, capture_output=True)
            self.assertEqual(p.returncode == 0, valid)
        with self.assertRaises(FileExistsError): signer.sign(self.payload, self.key, output)

    def test_key_alias_and_nonprivate_inputs_rejected(self):
        alias = self.root / 'alias.pem'; alias.symlink_to(self.key)
        with self.assertRaises(ValueError): signer.sign(self.payload, alias, self.root / 'output')
        self.key.chmod(0o644)
        with self.assertRaises(ValueError): signer.sign(self.payload, self.key, self.root / 'output')
        self.key.chmod(0o600)
        os.link(self.key, self.root / 'other.pem')
        with self.assertRaises(ValueError): signer.sign(self.payload, self.key, self.root / 'output')

    def test_private_diagnostics_never_returned(self):
        fake = self.root / 'fail'
        fake.write_text('#!/bin/sh\nprintf "private-diagnostic-canary" >&2\nexit 1\n')
        fake.chmod(0o700)
        with self.assertRaises(ValueError) as caught:
            signer.sign(self.payload, self.key, self.root / 'output', str(fake))
        self.assertNotIn('private-diagnostic-canary', str(caught.exception))
        self.assertFalse((self.root / 'output').exists())


if __name__ == '__main__': unittest.main()
