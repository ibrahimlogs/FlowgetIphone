# Android to iPhone parity map

| Android area | iPhone implementation | Status |
|---|---|---|
| Compose design system | `DesignSystem.swift` + semantic color assets | Ported |
| Login/session storage | `AuthService.swift`, Keychain-backed session | Ported; dedicated production iOS public client registered |
| Downloads list/add/pause/delete/share | `DownloadsView.swift`, `DownloadManager.swift` | Ported for direct HTTP(S), with background URLSession persistence |
| HLS/DASH muxing | URLSession source download | UI accepted; offline media muxing needs an AVFoundation-specific follow-up |
| FTP | — | Not available through Apple's native URLSession stack |
| Torrent engine | Native-core boundary in add-download UI | Requires an iOS XCFramework build of the authoritative native core |
| Browser | `WKWebView` browser, history, saved links, download handoff | Ported |
| FlowShare screens | Send/receive/nearby, codes, file selection, transfer list | Ported UI; protocol-v3 QUIC requires the authoritative native core XCFramework |
| Settings | Persistent download/browser/theme settings | Ported |
| Activity, Schedule, License, About | `MoreViews.swift` | Ported |
| Android services/Room/DataStore/SAF | background URLSession/JSON/Keychain/document picker | Replaced with iOS-native equivalents |
| Product Sans typography | Bundled TTF resources and app-wide SwiftUI font environment | Ported |

## External contracts required for production parity

The production iPhone app uses its own dedicated `ios` public client; the Android public client remains separate and platform-bound. FlowShare and torrent payload parity also cannot be truthfully recreated as a second Swift protocol: the Android architecture explicitly treats the shared Rust protocol-v3 core as authoritative. Compile that core for iOS as an XCFramework and connect it at the clearly marked FlowShare/torrent UI boundary.

No file under `FlowGetAndroid` was changed while creating this project.
