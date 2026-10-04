#!/bin/sh
set -eu
cd "$(dirname "$0")"
swift build -c release
BIN_DIR=$(swift build -c release --show-bin-path)
APP="$PWD/dist/Mechanize Permissions.app"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN_DIR/MechanizeConsent" "$APP/Contents/MacOS/MechanizeConsent"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.viant.mechanize.consent</string>
<key>CFBundleName</key><string>Mechanize Permissions</string>
<key>CFBundleExecutable</key><string>MechanizeConsent</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
if [ -n "${MECHANIZE_BROKER_REQUIREMENT:-}" ]; then
 python3 - "$APP/Contents/Info.plist" <<'PYPLIST'
import os,plistlib,sys
path=sys.argv[1]
with open(path,'rb') as f: value=plistlib.load(f)
value['MechanizeBrokerRequirement']=os.environ['MECHANIZE_BROKER_REQUIREMENT']
with open(path,'wb') as f: plistlib.dump(value,f)
PYPLIST
fi
printf '%s\n' "$APP"
