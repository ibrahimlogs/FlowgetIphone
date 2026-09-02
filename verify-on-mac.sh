#!/bin/zsh
set -euo pipefail

xcodebuild -resolvePackageDependencies -project FlowGet.xcodeproj -scheme FlowGet
xcodebuild -project FlowGet.xcodeproj -scheme FlowGet -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO clean test
