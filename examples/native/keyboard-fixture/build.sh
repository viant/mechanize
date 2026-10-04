#!/bin/bash
set -euo pipefail

source_dir="$(cd "$(dirname "$0")" && pwd)"
app="/private/tmp/mechanize-keyboard-fixture/Mechanize Keyboard Fixture.app"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
architecture="$(uname -m)"

mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$sdk" -target "$architecture-apple-macosx12.0" \
    -framework AppKit "$source_dir/main.swift" \
    -o "$app/Contents/MacOS/MechanizeKeyboardFixture"

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.viant.mechanize.keyboardfixture</string>
    <key>CFBundleName</key><string>Mechanize Keyboard Fixture</string>
    <key>CFBundleExecutable</key><string>MechanizeKeyboardFixture</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

codesign --force --sign - "$app"
codesign --verify --strict "$app"
printf '%s\n' "$app"
