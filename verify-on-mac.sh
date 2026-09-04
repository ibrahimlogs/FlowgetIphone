#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h}"
cd "$ROOT"

PIN="$(tr -d '[:space:]' < Native/flowshare-core.source)"
BUILT_PIN="$(cat Native/.build/installed-source 2>/dev/null || true)"
if [[ ! -d Native/FlowGetNativeCore.xcframework || "$BUILT_PIN" != "$PIN" ]]; then
  zsh build-flowshare-core.sh
fi

xcodebuild -resolvePackageDependencies -project FlowGet.xcodeproj -scheme FlowGet
xcodebuild -project FlowGet.xcodeproj -scheme FlowGet -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO clean test
