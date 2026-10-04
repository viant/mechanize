#!/usr/bin/env python3
"""Build local ad-hoc signed artifacts without installing or granting access."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import shutil
import subprocess
import sys
import uuid

import extension_package


def run(*args, env=None, capture=False):
    return subprocess.run(args, cwd=ROOT, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, text=True)


def pin(path, identifier):
    run("codesign", "--force", "--sign", "-", "--identifier", identifier, str(path))
    run("codesign", "--verify", "--strict", str(path))
    info = run("codesign", "--display", "--verbose=4", str(path), capture=True)
    match = re.search(r"^CDHash=([0-9a-fA-F]{40})$", info.stderr, re.MULTILINE)
    if not match:
        raise RuntimeError("codesign did not return an exact code-directory hash")
    requirement = f'identifier "{identifier}" and cdhash H"{match.group(1).lower()}"'
    run("codesign", "--verify", "--strict", "--test-requirement", "=" + requirement, str(path))
    return requirement


ROOT = Path(__file__).resolve().parents[1]
if sys.platform != "darwin":
    sys.exit("Local developer packaging requires macOS.")
if len(sys.argv) != 1:
    sys.exit("This script accepts no installation, credential, or trust overrides.")
for tool in ("go", "swift", "codesign"):
    if not shutil.which(tool):
        sys.exit(f"Missing build tool: {tool}")

destination = ROOT / "dist" / "development"
if destination.is_symlink():
    sys.exit("Development output must not be a symlink.")
destination.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(destination, 0o700)
broker = destination / "mechanize"
helper = destination / "mechanize-native"
native_host = destination / "mechanize-native-host"
build_environment = os.environ.copy()
build_environment.update({"GOOS": "darwin", "GOARCH": "arm64" if platform.machine() == "arm64" else "amd64", "CGO_ENABLED": "1"})
run("go", "build", "-o", str(broker), "./cmd/mechanize", env=build_environment)
broker_requirement = pin(broker, "com.viant.mechanize.broker")
# Embed the already-signed broker pin before signing the native-messaging
# bridge. Production cannot replace this reverse pin through config or env.
run("go", "build", "-ldflags",
    f"-X 'main.embeddedBrokerRequirement={broker_requirement}'",
    "-o", str(native_host), "./cmd/mechanize-native-host", env=build_environment)
native_host_requirement = pin(native_host, "com.viant.mechanize.chrome.nativehost")
# Pin the already-signed broker inside the helper's signed Mach-O metadata.
# The helper never accepts a broker requirement through launch environment.
helper_plist = destination / "native-identity.plist"
with helper_plist.open("wb") as output:
    plistlib.dump({"CFBundleIdentifier": "com.viant.mechanize.native",
                  "CFBundleName": "Mechanize Native",
                  "CFBundleVersion": "0.1.0",
                  "MechanizeBrokerRequirement": broker_requirement}, output)
os.chmod(helper_plist, 0o600)
run("swift", "build", "--package-path", "native/macos", "-c", "release",
    "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT",
    "-Xlinker", "__info_plist", "-Xlinker", str(helper_plist))
native_bin = Path(run("swift", "build", "--package-path", "native/macos", "-c", "release", "--show-bin-path", capture=True).stdout.strip())
shutil.copyfile(native_bin / "mechanize-native", helper)
os.chmod(helper, 0o700)
helper_requirement = pin(helper, "com.viant.mechanize.native")

environment = os.environ.copy()
environment["MECHANIZE_BROKER_REQUIREMENT"] = broker_requirement
run("sh", "native/console/build-app.sh", env=environment)
source_app = ROOT / "native" / "console" / "dist" / "Mechanize Permissions.app"
app = destination / "Mechanize Permissions.app"
if app.exists():
    if app.is_symlink() or not app.is_dir():
        sys.exit("Development app output is not a real directory.")
    shutil.rmtree(app)
shutil.copytree(source_app, app)
plist_path = app / "Contents" / "Info.plist"
with plist_path.open("rb") as source:
    plist = plistlib.load(source)
plist["CFBundleDisplayName"] = "Mechanize Permissions (Development)"
plist["MechanizeDevelopmentMode"] = True
plist["MechanizeHelperRequirement"] = helper_requirement
enrollment_account = f"com.viant.mechanize.consent:{os.getuid()}:{uuid.uuid4().hex}"
plist["MechanizeEnrollmentAccount"] = enrollment_account
with plist_path.open("wb") as output:
    plistlib.dump(plist, output)
console_requirement = pin(app, "com.viant.mechanize.consent")
extension = destination / "extension" / "chrome"
extension_inventory = extension_package.build(ROOT / "extension" / "chrome", extension)
manifest = {
    "schemaVersion": 1, "mode": "development", "productionQualified": False,
    "sourceRoot": str(ROOT), "broker": str(broker), "helper": str(helper), "console": str(app),
    "brokerRequirement": broker_requirement, "helperRequirement": helper_requirement,
    "nativeHost": str(native_host), "nativeHostRequirement": native_host_requirement,
    "nativeHostBrokerRequirement": broker_requirement,
    "nativeHostSHA256": hashlib.sha256(native_host.read_bytes()).hexdigest(),
    "chromeProfileQualified": False, "chromeExecutorQualified": False,
    "consoleRequirement": console_requirement,
    "consoleEnrollmentAccount": enrollment_account,
    "extension": str(extension), "extensionFiles": extension_inventory["files"],
    "extensionSHA256": extension_inventory["sha256"],
    "nativeConsoleConfig": {
        "socketPath": str(Path.home() / "Library/Application Support/Mechanize/runtime/consent.sock"),
        "designatedRequirement": console_requirement, "expectedUID": os.getuid()
    },
    "brokerSHA256": hashlib.sha256(broker.read_bytes()).hexdigest(),
    "helperSHA256": hashlib.sha256(helper.read_bytes()).hexdigest(),
    "installationPerformed": False, "credentialsProvisioned": False, "systemPermissionsGranted": False
}
manifest_path = destination / "manifest.json"
with manifest_path.open("w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
os.chmod(manifest_path, 0o600)
print(manifest_path)
