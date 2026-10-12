#!/usr/bin/env python3
"""Create or reuse one local development signer; never a distribution identity.

The private key is imported non-extractable into the user's default Keychain,
with /usr/bin/codesign as its only preauthorized application. Certificate trust
is limited to code signing in the user domain. No passwords or key bytes are
accepted as arguments, printed, or written to logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


def run(arguments, timeout=90):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("localSigningSetupFailed")
    return result.stdout


def write_state(path, value):
    temporary = path.with_name(".state-" + uuid.uuid4().hex)
    temporary.write_text(json.dumps(value, sort_keys=True))
    temporary.chmod(0o600)
    os.replace(temporary, path)


def valid_identity(fingerprint):
    output = run(["security", "find-identity", "-v", "-p", "codesigning"])
    return fingerprint.upper().encode() in [value.upper() for value in re.findall(
        rb'^\s*\d+\) ([0-9A-Fa-f]{40}) "', output, re.M)]


def owned_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("unsafeLocalSigningDirectory")
    path.chmod(0o700)


def setup(create=False):
    os.umask(0o077)
    root = Path.home() / ".secret" / "mechanize-signing"
    owned_directory(root.parent)
    owned_directory(root)
    state_path = root / "identity.json"
    if state_path.exists():
        info = state_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("unsafeLocalSigningState")
        state = json.loads(state_path.read_text())
        fingerprint = state.get("identitySHA1", "")
        if not re.fullmatch(r"[A-F0-9]{40}", fingerprint):
            raise RuntimeError("invalidLocalSigningState")
        if valid_identity(fingerprint):
            state["stage"] = "complete"
            write_state(state_path, state)
            return {"ready": True, "kind": "localDevelopment", "identitySHA1": fingerprint}
        if not create:
            return {"ready": False, "kind": "localDevelopment", "stage": state.get("stage", "unavailable")}
        if state.get("stage") != "keyImported":
            raise RuntimeError("localSigningOutcomeNeedsInspection")
    else:
        if not create:
            return {"ready": False, "kind": "localDevelopment", "stage": "notConfigured"}
        keychain = run(["security", "default-keychain", "-d", "user"]).decode().strip().strip('"')
        if not keychain.startswith("/") or "\n" in keychain:
            raise RuntimeError("defaultKeychainUnavailable")
        private_key = root / (".private-key-" + uuid.uuid4().hex + ".pem")
        certificate = root / "certificate.pem"
        if certificate.exists():
            raise RuntimeError("existingCertificateNeedsInspection")
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private_key)])
        private_key.chmod(0o600)
        native_key = root / (".native-key-" + uuid.uuid4().hex + ".pem")
        run(["openssl", "pkey", "-in", str(private_key), "-traditional", "-out", str(native_key)])
        native_key.chmod(0o600)
        os.replace(native_key, private_key)
        run(["openssl", "req", "-new", "-x509", "-key", str(private_key), "-sha256", "-days", "3650",
             "-subj", "/CN=Mechanize Local Development/O=Viant Local Development",
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "keyUsage=critical,digitalSignature",
             "-addext", "extendedKeyUsage=codeSigning", "-out", str(certificate)])
        der = run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"])
        state = {"version": 1, "kind": "localDevelopment", "identitySHA1": hashlib.sha1(der).hexdigest().upper(),
                 "certificateSHA256": hashlib.sha256(der).hexdigest(), "certificatePath": str(certificate),
                 "keychain": keychain, "privateKeyExportable": False, "trustPolicy": "codeSigningOnly", "stage": "keyImportAttempted"}
        write_state(state_path, state)
        run(["security", "import", str(private_key), "-k", keychain, "-t", "priv", "-f", "openssl", "-x", "-T", "/usr/bin/codesign"])
        state["stage"] = "keyImported"
        write_state(state_path, state)
        private_key.unlink()
    # User-domain trust for code signing only; no admin/TLS trust changes.
    state["stage"] = "trustAttempted"
    write_state(state_path, state)
    run(["security", "add-trusted-cert", "-r", "trustRoot", "-p", "codeSign", "-k", state["keychain"], state["certificatePath"]])
    if not valid_identity(state["identitySHA1"]):
        raise RuntimeError("localSigningIdentityUnavailable")
    state["stage"] = "complete"
    write_state(state_path, state)
    return {"ready": True, "kind": "localDevelopment", "identitySHA1": state["identitySHA1"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", action="store_true", help="Explicitly provision the local Keychain identity")
    arguments = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("Local signing setup requires macOS")
    try:
        print(json.dumps(setup(arguments.create), separators=(",", ":")))
    except Exception:
        raise SystemExit("Local signing setup did not complete; private state retained for inspection, no automatic retry")
