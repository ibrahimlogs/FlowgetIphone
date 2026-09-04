# FlowgetIphone

Native Swift/SwiftUI port of the FlowGet Android application. It does not modify or link to the Android workspace. Google Sign-In is integrated through Google's official Swift Package.

## Requirements

- macOS with Xcode 16 or newer
- iOS 17 or newer deployment target
- An Apple Developer team for device builds
- Rust with `rustup` (used to build the pinned FlowShare XCFramework)

## First run

1. Clone this repository on the Mac and open Terminal in its root.
2. Run `zsh verify-on-mac.sh`. On the first run it compiles the vendored, pinned FlowShare Rust core for iPhone and simulator, creates the local XCFramework, resolves packages, clean-builds, and executes tests. The native build can take several minutes.
3. Open `FlowGet.xcodeproj`.
4. Select the `FlowGet` target, choose **Signing & Capabilities**, and select your team.
5. Change the bundle identifier if `com.flowget.ios` is not available to your team.
6. Keep `FLOWGET_IOS_CLIENT_ID` in `Info.plist` set to the dedicated public iOS client registered by the FlowGet Laravel backend.
7. Create a Google OAuth client of type **iOS** for bundle ID `com.flowget.ios`, then run `zsh configure-google-ios.sh '<your-ios-client-id>.apps.googleusercontent.com'`. Never add a Google client secret to this app.
8. Select an actual simulator or connected iPhone (not `Any iOS Device`) and press Run.

On Windows, `powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1` validates the project structure, plists, asset catalogs, icon, and required sources. It cannot replace the Apple SDK compiler.

The app uses the production FlowGet Laravel, licensing, and FlowShare endpoints declared in `AppConfig.swift`. It supports password and Google login, Worker V3 Mobile licensing with an iOS Keychain-backed installation identity, background direct HTTP(S) downloads, authenticated browser downloads through native WebKit download handling, persistent download history, and FlowShare device/friend-code file transfer over the authoritative Rust protocol-v3 QUIC core. Native authorization secrets are protected with an iOS Keychain-backed AES-GCM key, received files appear under `On My iPhone/FlowGet`, and no Swift wire-protocol substitute is used. Torrent payload transfer and DASH/HLS segmentation remain separate follow-up native-engine work.
