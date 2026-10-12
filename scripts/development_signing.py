"""Select an existing certificate; never provision keys or change trust."""
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


def signing_arguments(fingerprint, identifier):
    """Keep a role-bound certificate identity stable while image pins still vary."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", identifier):
        raise ValueError("Exact code identifier required")
    if fingerprint != "-" and not re.fullmatch(r"[0-9a-fA-F]{40}", fingerprint):
        raise ValueError("Exact signing certificate fingerprint required")
    arguments = ["--force", "--sign", fingerprint, "--identifier", identifier]
    if fingerprint != "-":
        requirement = f'identifier "{identifier}" and certificate leaf = H"{fingerprint.lower()}"'
        arguments.extend(["--requirements", "=designated => " + requirement])
    return arguments


def configured_identity():
    path = Path.home() / ".secret" / "mechanize-signing" / "identity.json"
    if not path.exists():
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
        raise ValueError("Configured local signing identity metadata is unsafe")
    metadata = json.loads(path.read_text())
    fingerprint = metadata.get("identitySHA1", "")
    if metadata.get("version") != 1 or metadata.get("kind") != "localDevelopment" or metadata.get("stage") != "complete" or metadata.get("trustPolicy") != "codeSigningOnly" or metadata.get("privateKeyExportable") is not False or not re.fullmatch(r"[A-F0-9]{40}", fingerprint):
        raise ValueError("Configured local signing identity is not ready; ad-hoc fallback refused")
    return fingerprint


def select_identity(fingerprint, run=subprocess.run):
    if fingerprint is None:
        fingerprint = configured_identity()
        if fingerprint is None:
            return "-"
    if not re.fullmatch(r"[0-9a-fA-F]{40}", fingerprint):
        raise ValueError("Signing identity must be an exact certificate SHA-1 fingerprint")
    result = run(["security", "find-identity", "-v", "-p", "codesigning"],
                 check=True, capture_output=True, text=True)
    identities = re.findall(r'^\s*\d+\) ([0-9A-Fa-f]{40}) "', result.stdout, re.MULTILINE)
    fingerprint = fingerprint.upper()
    if fingerprint not in [value.upper() for value in identities]:
        raise ValueError("Requested signing certificate is not a valid local code-signing identity")
    return fingerprint


def verify_certificate(path, fingerprint, run=subprocess.run):
    if fingerprint == "-":
        return
    with tempfile.TemporaryDirectory(prefix="mechanize-signing-") as directory:
        prefix = str(Path(directory) / "certificate")
        run(["codesign", "--display", "--extract-certificates=" + prefix, str(path)],
            check=True, capture_output=True, text=True)
        certificate = Path(prefix + "0")
        if not certificate.is_file() or hashlib.sha1(certificate.read_bytes()).hexdigest().upper() != fingerprint:
            raise ValueError("Signed artifact does not carry the selected leaf certificate")
