#!/usr/bin/env python3
"""Install an isolated, pinned developer package; never start it or change TCC."""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).absolute().parents[1]
extension_spec = importlib.util.spec_from_file_location('extension_package', Path(__file__).absolute().parent / 'extension_package.py')
extension_package = importlib.util.module_from_spec(extension_spec)
extension_spec.loader.exec_module(extension_package)
ARTIFACTS = {'broker': ('mechanize', 'broker'), 'helper': ('mechanize-native', 'native'),
             'console': ('Mechanize Permissions.app', 'consent'),
             'nativeHost': ('mechanize-native-host', 'chrome.nativehost')}


def safe_path(path):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise RuntimeError("canonical absolute paths required")
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise RuntimeError(f"symlink rejected: {part}")
    return path


def private_dir(path):
    safe_path(path)
    path.mkdir(mode=0o700)
    return path


def ensure_private(path):
    safe_path(path)
    if path.exists():
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError(f"existing directory must be owned and mode 0700: {path}")
    else:
        path.mkdir(mode=0o700)


def write_private(path, data):
    safe_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)


def encode(value):
    return json.dumps(value, indent=2).encode() + b"\n"


def command(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.decode(errors='replace')[:2000]}")
    return result


def verify(path, requirement, digest=None):
    path = safe_path(path)
    for entry in ([path, *path.rglob("*")] if path.is_dir() else [path]):
        safe_path(entry)
        info = entry.stat()
        if (info.st_uid != os.getuid() or info.st_mode & 0o022 or
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or
                stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise RuntimeError("owned regular non-shared-writable artifact required")
    if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise RuntimeError("manifest SHA256 mismatch")
    command("codesign", "--verify", "--strict", "--test-requirement", "=" + requirement, str(path))


def verify_native_host_pin(path, manifest):
    broker = manifest['brokerRequirement']
    embedded = set(re.findall(rb'identifier "com\.viant\.mechanize\.broker" and cdhash H"[a-f0-9]{40}"', path.read_bytes()))
    if manifest.get('nativeHostBrokerRequirement') != broker or embedded != {broker.encode()}:
        raise RuntimeError('native host embedded broker reverse pin mismatch')


def verify_package(manifest):
    if (manifest.get("schemaVersion") != 1 or manifest.get("mode") != "development" or
            manifest.get("productionQualified") is not False or manifest.get("sourceRoot") != str(ROOT)):
        raise RuntimeError("incompatible development manifest")
    source = ROOT / "dist/development"
    for name, (filename, identifier) in ARTIFACTS.items():
        if manifest.get(name) != str(source / filename):
            raise RuntimeError("unexpected manifest artifact path")
        requirement = manifest.get(name + 'Requirement')
        if not isinstance(requirement, str) or not re.fullmatch(r'identifier "com\.viant\.mechanize\.' + re.escape(identifier) + r'" and cdhash H"[a-f0-9]{40}"', requirement):
            raise RuntimeError("exact development code requirement required")
        digest = manifest.get(name + 'SHA256')
        if name != 'console' and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise RuntimeError("exact manifest binary SHA256 required")
        verify(source / filename, requirement, digest)
    verify_native_host_pin(source / 'mechanize-native-host', manifest)
    if manifest.get('extension') != str(source / 'extension/chrome'):
        raise RuntimeError('fixed packaged Chrome extension path required')
    extension_package.verify(source / 'extension/chrome', manifest.get('extensionFiles'), manifest.get('extensionSHA256'))


def install_artifacts(manifest, destination):
    destination = safe_path(destination)
    info = destination.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or any(destination.iterdir()):
        raise RuntimeError('fresh private installation destination required')
    verify_package(manifest)
    installed = {}
    for name, (filename, _) in ARTIFACTS.items():
        original = Path(manifest[name])
        target = destination / filename
        if original.is_dir():
            shutil.copytree(original, target, symlinks=False)
        else:
            shutil.copyfile(original, target)
            target.chmod(0o700)
        verify(target, manifest[name + 'Requirement'], manifest.get(name + 'SHA256'))
        installed[name] = str(target)
    verify_native_host_pin(destination / 'mechanize-native-host', manifest)
    private_dir(destination / 'extension')
    extension = destination / 'extension/chrome'
    extension_package.copy(Path(manifest['extension']), extension,
                           {'files': manifest['extensionFiles'], 'sha256': manifest['extensionSHA256']})
    installed['extension'] = str(extension)
    return installed


def token(key, issuer, audience, subject, client, scopes, now):
    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64(json.dumps({"iss": issuer, "aud": audience, "sub": subject, "client_id": client,
                            "scope": scopes, "iat": now, "nbf": now - 30, "exp": now + 86400}, separators=(",", ":")).encode())
    payload = header + b"." + claims
    return payload + b"." + b64(hmac.new(key, payload, hashlib.sha256).digest())


def main():
    if sys.platform != "darwin" or len(sys.argv) != 1:
        raise RuntimeError("macOS only; this installer accepts no overrides or credentials")
    os.umask(0o077)
    manifest_path = safe_path(ROOT / "dist/development/manifest.json")
    manifest = json.loads(manifest_path.read_text())
    verify_package(manifest)
    home = safe_path(Path.home())
    support = home / "Library/Application Support/Mechanize"
    ensure_private(support)
    ensure_private(support / "runtime")
    ensure_private(support / "development")
    # Fresh directory only, so neither production nor earlier development files are replaced.
    now = int(time.time())
    destination = private_dir(support / "development" / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + os.urandom(4).hex()))
    installed = install_artifacts(manifest, destination)
    private_dir(destination / "credentials")
    private_dir(destination / "storage")
    key = os.urandom(32)
    issuer, audience, subject = "mechanize:development:" + str(os.getuid()), "mechanize-development", "local-uid-" + str(os.getuid())
    files = destination / "credentials"
    write_private(files / "hmac", base64.b64encode(key))
    write_private(files / "artifact.json", encode({"key": base64.b64encode(os.urandom(32)).decode()}))
    write_private(files / "stdio.jwt", token(key, issuer, audience, subject, "development-agent", "desktop:observe desktop:control", now))
    config = {
        "sourceRoot": str(ROOT), "storageRoot": str(destination / "storage"), "nativeHelper": installed["helper"],
        "keys": {"HMAC": {"URL": str(files / "hmac")}},
        "identityPolicy": {"issuer": issuer, "audience": audience, "algorithms": ["HS256"],
                           "clients": {"development-agent": "Local development agent", "development-console": "Local permissions console"}},
        "stdioCredential": {"URL": str(files / "stdio.jwt")},
        "users": [{"subject": subject, "desktopAccess": True, "nativeBundles": [], "webOrigins": [], "recordingAllowed": True}],
        "nativeConsole": {"socketPath": str(support / "runtime/consent.sock"), "designatedRequirement": manifest["consoleRequirement"], "expectedUID": os.getuid()},
        "artifacts": {"sourceKeyReference": "development-v1", "keyResources": {"development-v1": {"URL": str(files / "artifact.json")}},
                      "maxBytes": 16777216, "namespaceQuotaBytes": 134217728}, "maxUsers": 1
    }
    write_private(destination / "config.json", encode(config))
    enroller = destination / "enroll-console"
    command("swiftc", str(ROOT / "native/enrollment/main.swift"), "-o", str(enroller))
    enroller.chmod(0o700)
    console_token = token(key, issuer, audience, subject, "development-console", "desktop:observe consent:admin", now)
    enroll_args = [str(enroller), installed["console"], manifest["consoleRequirement"]]
    if manifest.get("consoleEnrollmentAccount"):
        enroll_args.append(manifest["consoleEnrollmentAccount"])
    enrolled = subprocess.run(enroll_args, input=console_token,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    acl_verified = False
    if enrolled.returncode == 0 and not manifest.get("consoleEnrollmentAccount"):
        auditor = destination / "audit-enrollment"
        command("swiftc", str(ROOT / "native/enrollment/audit.swift"), "-o", str(auditor))
        auditor.chmod(0o700)
        audit = json.loads(command(str(auditor)).stdout)
        secret_acls = [entry for entry in audit if any(auth in entry["authorizations"] for auth in
                       ("ACLAuthorizationDecrypt", "ACLAuthorizationExportClear", "ACLAuthorizationAny"))]
        acl_verified = bool(secret_acls) and all(not entry["unrestrictedApplicationList"] and
                       entry["trustedApplications"] == [installed["console"]] for entry in secret_acls)
        write_private(destination / "enrollment-acl-audit.json", encode(audit))
    report = {"mode": "development", "productionQualified": False, "installationRoot": str(destination),
              **installed, "config": str(destination / "config.json"), "manifestSHA256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
              "signaturesVerified": True, "tokenExpiresAt": now + 86400, "consoleEnrollmentProvisioned": enrolled.returncode == 0,
              "consoleSecretACLVerified": acl_verified,
              "consoleEnrollmentAccount": manifest.get("consoleEnrollmentAccount"),
              "consoleEnrollmentStatus": (enrolled.stdout + enrolled.stderr).decode().strip(),
              "brokerStarted": False, "systemPermissionsChanged": False, "scope": "Desktop-wide ceiling; recording and control require explicit session consent"}
    write_private(destination / "setup-report.json", encode(report))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(str(error))
