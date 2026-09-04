#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h}"
NATIVE_DIR="$ROOT/Native"
BUILD_DIR="$NATIVE_DIR/.build"
CRATE_DIR="$NATIVE_DIR/Vendor/crates/flowget-flowshare-core"
TARGET_DIR="$BUILD_DIR/cargo-target"
OUTPUT="$NATIVE_DIR/FlowGetNativeCore.xcframework"
PIN="$(tr -d '[:space:]' < "$NATIVE_DIR/flowshare-core.source")"

command -v cargo >/dev/null || { echo "Rust is required. Install it from https://rustup.rs first." >&2; exit 1; }
command -v rustup >/dev/null || { echo "rustup is required." >&2; exit 1; }
command -v xcodebuild >/dev/null || { echo "Xcode command-line tools are required." >&2; exit 1; }

mkdir -p "$BUILD_DIR"
[[ -f "$CRATE_DIR/Cargo.toml" ]] || { echo "Vendored FlowShare core is missing." >&2; exit 1; }
[[ ${#PIN} -eq 40 && "$PIN" != *[^0-9a-f]* ]] || { echo "FlowShare source revision is invalid." >&2; exit 1; }
cp "$NATIVE_DIR/flowshare-core.Cargo.lock" "$CRATE_DIR/Cargo.lock"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

export IPHONEOS_DEPLOYMENT_TARGET=17.0
export CARGO_TARGET_DIR="$TARGET_DIR"
cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --locked --release --features uniffi-bindings --target aarch64-apple-ios
cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --locked --release --features uniffi-bindings --target aarch64-apple-ios-sim
cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --locked --release --features uniffi-bindings --target x86_64-apple-ios
cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --locked --release --features uniffi-bindings

GENERATED="$BUILD_DIR/generated"
HEADERS="$BUILD_DIR/headers"
SIMULATOR_LIB="$BUILD_DIR/libflowget_flowshare_core-simulator.a"
FRAMEWORK_TMP="$BUILD_DIR/FlowGetNativeCore.xcframework"
rm -rf "$GENERATED" "$HEADERS" "$FRAMEWORK_TMP"
mkdir -p "$GENERATED" "$HEADERS"

(
  cd "$CRATE_DIR"
  "$TARGET_DIR/release/uniffi-bindgen" generate \
    --library "$TARGET_DIR/release/libflowget_flowshare_core.dylib" \
    --language swift \
    --no-format \
    --out-dir "$GENERATED"
)

# UniFFI's unformatted template leaves trailing blanks. Normalize only those
# blanks so the checked-in ABI comparison remains deterministic on every host.
sed -i '' -E 's/[[:blank:]]+$//' "$GENERATED/flowget_flowshare_core.swift"

cmp "$GENERATED/flowget_flowshare_core.swift" "$ROOT/FlowGet/Generated/flowget_flowshare_core.swift" || {
  echo "Generated Swift binding drifted from the pinned source. Regenerate and review it before building." >&2
  exit 1
}

cp "$GENERATED/flowget_flowshare_coreFFI.h" "$HEADERS/flowget_flowshare_coreFFI.h"
cp "$GENERATED/flowget_flowshare_coreFFI.modulemap" "$HEADERS/module.modulemap"

lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/libflowget_flowshare_core.a" \
  "$TARGET_DIR/x86_64-apple-ios/release/libflowget_flowshare_core.a" \
  -output "$SIMULATOR_LIB"

xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/libflowget_flowshare_core.a" \
  -headers "$HEADERS" \
  -library "$SIMULATOR_LIB" \
  -headers "$HEADERS" \
  -output "$FRAMEWORK_TMP"

rm -rf "$OUTPUT"
mv "$FRAMEWORK_TMP" "$OUTPUT"
print -r -- "$PIN" > "$BUILD_DIR/installed-source"
echo "Built $OUTPUT from FlowShare core $PIN"
