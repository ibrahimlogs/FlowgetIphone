# Android to iPhone parity map

| Android area | iPhone implementation | Status |
|---|---|---|
| Compose design system | `DesignSystem.swift` + semantic color assets | Ported |
| Login/session storage | `AuthService.swift`, official Google Sign-In SDK, Keychain-backed session | Ported; password and Google use the dedicated production iOS public client |
| Licensing/device allocation | `LicensingService.swift`, Laravel worker assertions, Cloudflare Licensing V3 | Ported; iOS uses a Keychain-protected Ed25519 installation identity and the shared Mobile slot family |
| Downloads list/add/pause/delete/share | `DownloadsView.swift`, `DownloadManager.swift` | Ported for direct HTTP(S), including browser cookies/headers held in memory and background URLSession persistence |
| HLS/DASH muxing | URLSession source download | UI accepted; offline media muxing needs an AVFoundation-specific follow-up |
| FTP | — | Not available through Apple's native URLSession stack |
| Torrent engine | Native-core boundary in add-download UI | Requires an iOS XCFramework build of the authoritative native core |
| Browser | `WKWebView` browser, history, saved links, response interception, download discovery/handoff | Ported for direct files; segmented HLS/DASH media still needs the native engine |
| FlowShare | `FlowShareCoordinator.swift`, `NativeCoreBridge.swift`, generated UniFFI ABI, pinned vendored Rust core | Integrated for authenticated device and friend-code send/receive over protocol-v3 native QUIC; Apple SDK build/test runs through `verify-on-mac.sh` |
| Settings | Persistent download/browser/theme settings | Ported |
| Activity, Schedule, License, About | `MoreViews.swift` | Ported |
| Android services/Room/DataStore/SAF | background URLSession/JSON/Keychain/document picker | Replaced with iOS-native equivalents |
| Product Sans typography | Bundled TTF resources and app-wide SwiftUI font environment | Ported |

## External contracts required for production parity

The production iPhone app uses its own dedicated `ios` public client; the Android public client remains separate and platform-bound. FlowShare consumes an exact pinned snapshot of the same authoritative Rust protocol-v3 core as Android. `build-flowshare-core.sh` compiles it into a local XCFramework for iPhone and simulator and verifies the checked-in generated Swift ABI. Torrent payload parity still needs its separate authoritative native engine rather than a Swift protocol substitute.

No file under `FlowGetAndroid` was changed while creating this project.
