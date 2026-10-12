#!/bin/sh
set -eu
cd "$(dirname "$0")"
swift build -c release
BIN_DIR=$(swift build -c release --show-bin-path)
APP="$PWD/dist/Mechanize Permissions.app"
MECHANIZE_BUILD_VERSION=$(python3 - "$APP/Contents/Info.plist" <<'PYVERSION'
import os,pathlib,plistlib,re,sys
override=os.environ.get('MECHANIZE_BUNDLE_VERSION')
if override:
    if not re.fullmatch(r'[0-9]{1,4}(?:\.[0-9]{1,2}){0,2}(?:(?:d|a|b|fc)[1-9][0-9]{0,2})?',override):
        raise SystemExit('Invalid explicit bundle version')
    print(override)
else:
    path=pathlib.Path(sys.argv[1])
    previous=plistlib.loads(path.read_bytes()).get('CFBundleVersion','0') if path.exists() else '0'
    if not isinstance(previous,str) or not previous.isdecimal() or int(previous)>=9999:
        raise SystemExit('Set MECHANIZE_BUNDLE_VERSION for this version scheme')
    print(int(previous)+1)
PYVERSION
)
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swift Branding/build-icons.swift "$APP/Contents/Resources"
iconutil -c icns "$APP/Contents/Resources/Mechanize.iconset" -o "$APP/Contents/Resources/Mechanize.icns"
rm -r "$APP/Contents/Resources/Mechanize.iconset"
cp "$BIN_DIR/MechanizeConsent" "$APP/Contents/MacOS/MechanizeConsent"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.viant.mechanize.consent</string>
<key>CFBundleName</key><string>Mechanize Permissions</string>
<key>CFBundleExecutable</key><string>MechanizeConsent</string>
<key>CFBundleIconFile</key><string>Mechanize</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
python3 - "$APP/Contents/Info.plist" "$MECHANIZE_BUILD_VERSION" <<'PYVERSION'
import plistlib,sys
path=sys.argv[1]
with open(path,'rb') as source:value=plistlib.load(source)
value['CFBundleVersion']=sys.argv[2]
with open(path,'wb') as target:plistlib.dump(value,target)
PYVERSION
python3 ../../scripts/package-console-skills.py "$APP/Contents/Resources/ApplicationSkills.json"
if [ -n "${MECHANIZE_BROKER_REQUIREMENT:-}" ]; then
 python3 - "$APP/Contents/Info.plist" <<'PYPLIST'
import os,plistlib,sys
path=sys.argv[1]
with open(path,'rb') as f: value=plistlib.load(f)
value['MechanizeBrokerRequirement']=os.environ['MECHANIZE_BROKER_REQUIREMENT']
with open(path,'wb') as f: plistlib.dump(value,f)
PYPLIST
fi
if [ -n "${MECHANIZE_UPGRADE_REVIEW_PUBLIC_KEY:-}${MECHANIZE_UPGRADE_PACKAGE_PATH:-}" ]; then
 python3 - "$APP/Contents/Info.plist" <<'PYUPGRADE'
import base64,os,pathlib,plistlib,sys
key=os.environ.get('MECHANIZE_UPGRADE_REVIEW_PUBLIC_KEY','')
path=os.environ.get('MECHANIZE_UPGRADE_PACKAGE_PATH','')
try:
    raw=base64.b64decode(key,validate=True)
except ValueError:
    raise SystemExit('Invalid upgrade review public key')
if len(raw)!=32 or base64.b64encode(raw).decode()!=key:
    raise SystemExit('Invalid upgrade review public key')
if not path.startswith('/') or any(p in ('','.','..') for p in path.split('/')[1:]) or any(c in path for c in '\x00\r\n'):
    raise SystemExit('Upgrade package requires a canonical absolute path')
app=pathlib.Path(sys.argv[1]).parent.parent
if pathlib.Path(path).is_relative_to(app):
    raise SystemExit('Upgrade package must be outside the signed console bundle')
with open(sys.argv[1],'rb') as f: value=plistlib.load(f)
value['MechanizeUpgradeReviewPublicKey']=key
value['MechanizeUpgradePackagePath']=path
with open(sys.argv[1],'wb') as f: plistlib.dump(value,f)
PYUPGRADE
fi
printf '%s\n' "$APP"
