# FlowgetIphone

Native Swift/SwiftUI port of the FlowGet Android application. The project is intentionally dependency-free and does not modify or link to the Android workspace.

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
6. Run on an iPhone or simulator.
7. Run `zsh verify-on-mac.sh` from Terminal to clean-build and execute the unit tests.

On Windows, `powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1` validates the project structure, plists, asset catalogs, icon, and required sources. It cannot replace the Apple SDK compiler.

The app uses the production FlowGet Laravel and licensing endpoints declared in `AppConfig.swift`. Direct HTTP(S) downloads, persistent download history, the private browser, settings, account login/refresh, file import/export, background scheduling UI, license UI, and activity history are implemented in Swift. Torrent payload transfer and FlowShare's protocol-v3 QUIC data plane require an iOS build of the authoritative shared native core; the Swift UI reports this capability clearly instead of silently using an incompatible transport.
