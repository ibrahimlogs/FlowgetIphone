# FlowgetIphone

Native Swift/SwiftUI port of the FlowGet Android application. It does not modify or link to the Android workspace. Google Sign-In is integrated through Google's official Swift Package.

## Requirements

- macOS with Xcode 16 or newer
- iOS 17 or newer deployment target
- An Apple Developer team for device builds

## First run

1. Copy this folder to the Mac.
2. Open `FlowGet.xcodeproj`.
3. Select the `FlowGet` target, choose **Signing & Capabilities**, and select your team.
4. Change the bundle identifier if `com.flowget.ios` is not available to your team.
5. Keep `FLOWGET_IOS_CLIENT_ID` in `Info.plist` set to the dedicated public iOS client registered by the FlowGet Laravel backend.
6. Create a Google OAuth client of type **iOS** for bundle ID `com.flowget.ios`, then run `zsh configure-google-ios.sh '<your-ios-client-id>.apps.googleusercontent.com'`. Never add a Google client secret to this app.
7. Run on an iPhone or simulator.
8. Run `zsh verify-on-mac.sh` from Terminal to resolve packages, clean-build, and execute the unit tests.

On Windows, `powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1` validates the project structure, plists, asset catalogs, icon, and required sources. It cannot replace the Apple SDK compiler.

The app uses the production FlowGet Laravel and licensing endpoints declared in `AppConfig.swift`. It supports password and Google login, Worker V3 Mobile licensing with an iOS Keychain-backed installation identity, direct HTTP(S) downloads, browser download interception with same-site WebKit cookies, persistent download history, settings, file import/export, background scheduling UI, and activity history. Torrent payload transfer, DASH/HLS segmentation, and FlowShare's protocol-v3 QUIC data plane require an iOS build of the authoritative shared native core; the Swift UI does not silently substitute an incompatible transport.
