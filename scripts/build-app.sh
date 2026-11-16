#!/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
VERSION=2.0.0
DIST="${1:-$PROJECT_ROOT/dist}"
mkdir -p "$DIST" "$PROJECT_ROOT/.build/ModuleCache"
DIST="$(cd "$DIST" && pwd)"
STAGE=$(mktemp -d "$PROJECT_ROOT/.build/package.XXXXXX")
PAYLOAD="$STAGE/root"
APP="$PAYLOAD/Applications/PPTPClient.app"
HELPER="$PAYLOAD/Library/PrivilegedHelperTools/local.pptpclient.helper"
TRUST_DIR="$PAYLOAD/Library/Application Support/PPTPClient"
swift build -c release --cache-path .build/cache --config-path .build/config --security-path .build/security
BIN=$(swift build -c release --show-bin-path --cache-path .build/cache --config-path .build/config --security-path .build/security)
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$(dirname "$HELPER")" "$TRUST_DIR" "$PAYLOAD/Library/LaunchDaemons"
cp "$BIN/PPTPClientApp" "$APP/Contents/MacOS/PPTPClientApp"
cp "$BIN/pptp-helper" "$HELPER"
cp packaging/local.pptpclient.helper.plist "$PAYLOAD/Library/LaunchDaemons/"
chmod 755 "$HELPER" "$APP/Contents/MacOS/PPTPClientApp"
codesign --force --sign - --options runtime --identifier local.pptpclient.helper "$HELPER"
HELPER_REQUIREMENT=$(codesign -d -r- "$HELPER" 2>&1 | sed -n 's/^designated => //p')
export APP HELPER_REQUIREMENT VERSION TRUST_DIR
python3 - <<'PY'
import os,plistlib,pathlib
app=pathlib.Path(os.environ['APP'])
info={'CFBundleIdentifier':'local.pptpclient','CFBundleName':'PPTPClient','CFBundleDisplayName':'PPTPClient',
      'CFBundleExecutable':'PPTPClientApp','CFBundlePackageType':'APPL','CFBundleShortVersionString':os.environ['VERSION'],
      'CFBundleVersion':'2','LSMinimumSystemVersion':'26.0','NSHighResolutionCapable':True,
      'NSPrincipalClass':'NSApplication','CFBundleIconFile':'AppIcon','LSApplicationCategoryType':'public.app-category.utilities',
      'PPTPHelperRequirement':os.environ['HELPER_REQUIREMENT']}
with (app/'Contents/Info.plist').open('wb') as f: plistlib.dump(info,f)
PY
xcrun swiftc scripts/make-icon.swift -module-cache-path .build/ModuleCache -o "$STAGE/make-icon"
mkdir -p "$STAGE/AppIcon.iconset"
"$STAGE/make-icon" "$STAGE/icon.png"
for SIZE in 16 32 128 256 512; do
    sips -z "$SIZE" "$SIZE" "$STAGE/icon.png" --out "$STAGE/AppIcon.iconset/icon_${SIZE}x${SIZE}.png" >/dev/null
    DOUBLE=$((SIZE * 2))
    sips -z "$DOUBLE" "$DOUBLE" "$STAGE/icon.png" --out "$STAGE/AppIcon.iconset/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
done
iconutil -c icns "$STAGE/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - --options runtime --identifier local.pptpclient "$APP"
CLIENT_REQUIREMENT=$(codesign -d -r- "$APP" 2>&1 | sed -n 's/^designated => //p')
export CLIENT_REQUIREMENT
python3 - <<'PY'
import os,plistlib,pathlib
trust={'ownerUID':0,'clientRequirement':os.environ['CLIENT_REQUIREMENT'],
       'helperRequirement':os.environ['HELPER_REQUIREMENT'],'protocolVersion':2}
with (pathlib.Path(os.environ['TRUST_DIR'])/'trust.plist').open('wb') as f: plistlib.dump(trust,f)
PY
chmod +x packaging/scripts/preinstall packaging/scripts/postinstall
export STAGE
python3 - <<'PY'
import os,plistlib,pathlib
components=[{'RootRelativeBundlePath':'Applications/PPTPClient.app',
             'BundleIsRelocatable':False,'BundleIsVersionChecked':True,
             'BundleHasStrictIdentifier':True,'BundleOverwriteAction':'upgrade'}]
with (pathlib.Path(os.environ['STAGE'])/'components.plist').open('wb') as f: plistlib.dump(components,f)
PY
pkgbuild --root "$PAYLOAD" --component-plist "$STAGE/components.plist" --scripts packaging/scripts --identifier local.pptpclient.package \
    --version "$VERSION" --install-location / --ownership recommended "$DIST/PPTPClient.pkg"
export DIST
python3 - <<'PY'
import os,pathlib,shutil
destination=pathlib.Path(os.environ['DIST'])/'PPTPClient.app'
if destination.exists(): shutil.rmtree(destination)
shutil.copytree(os.environ['APP'],destination,symlinks=True)
PY
codesign --verify --deep --strict "$DIST/PPTPClient.app"
codesign --verify --strict "$HELPER"
shasum -a 256 "$DIST/PPTPClient.pkg" > "$DIST/SHA256SUMS"
printf 'Built: %s\n' "$DIST/PPTPClient.app" "$DIST/PPTPClient.pkg"
