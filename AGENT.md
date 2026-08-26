# FlowGet iPhone project map

This repository is the native iPhone port of `H:\Android\Projects\FlowGetAndroid`.
It is intentionally independent: never edit the Android repository as a side effect
of iOS work, and never add Android/Kotlin sources here.

## Project

- Xcode project: `FlowGet.xcodeproj`
- Target: `FlowGet`
- Language/UI: Swift 5 and SwiftUI
- Minimum OS: iOS 17
- Bundle ID default: `com.flowget.ios`
- No third-party package dependencies

## Important entry points

| Concern | File |
|---|---|
| App lifecycle | `FlowGet/FlowGetApp.swift` |
| App/session state | `FlowGet/AppStore.swift` |
| Design system | `FlowGet/DesignSystem.swift` |
| Production auth | `FlowGet/AuthService.swift` |
| Background direct downloads | `FlowGet/DownloadManager.swift` |
| Downloads UI | `FlowGet/DownloadsView.swift` |
| Browser/WKWebView | `FlowGet/BrowserView.swift` |
| FlowShare UI boundary | `FlowGet/FlowShareView.swift` |
| Settings | `FlowGet/SettingsView.swift` |
| Activity/schedule/license/about | `FlowGet/MoreViews.swift` |
| Secure/persistent storage | `FlowGet/Persistence.swift` |

## Service boundaries

- Laravel auth: `https://flowget.xyz/`
- Licensing Worker: `https://flowget-worker-v2-production.flowget-api.workers.dev/`
- FlowShare signaling: `https://share.flowget.xyz/`
- Never log or persist plaintext access tokens, refresh tokens, assertions, private
  keys, entitlement JWTs, signaling credentials, or invitation secrets.
- Privileged service requests must never share a credential-bearing session with
  arbitrary browser/download traffic.

Production iPhone authentication requires a separately registered iOS native
client/platform contract. Configure its ID through `FLOWGET_IOS_CLIENT_ID` in
`Info.plist`. Do not reuse the Android client ID or mislabel iPhone traffic as Android.

FlowShare protocol-v3 QUIC and torrents are owned by the authoritative shared native
core. Do not create a second, incompatible Swift wire protocol. Integrate an iOS
XCFramework build of that core when it is available.

## Verification

On macOS, run:

```zsh
zsh verify-on-mac.sh
```

Select a development team in Xcode before installing on a physical iPhone.
