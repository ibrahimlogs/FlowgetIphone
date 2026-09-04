$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceRoot = Join-Path $projectRoot 'FlowGet'
$projectFile = Join-Path $projectRoot 'FlowGet.xcodeproj\project.pbxproj'

[xml](Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Info.plist')) | Out-Null
[xml](Get-Content -Raw -LiteralPath (Join-Path $sourceRoot 'PrivacyInfo.xcprivacy')) | Out-Null
[xml](Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'FlowGet.xcodeproj\xcshareddata\xcschemes\FlowGet.xcscheme')) | Out-Null

Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'Assets.xcassets') -Recurse -Filter 'Contents.json' |
    ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json | Out-Null }

Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Image]::FromFile((Join-Path $sourceRoot 'Assets.xcassets\AppIcon.appiconset\AppIcon-1024.png'))
try {
    if ($icon.Width -ne 1024 -or $icon.Height -ne 1024) {
        throw "App icon must be 1024x1024; found $($icon.Width)x$($icon.Height)."
    }
    if ([System.Drawing.Image]::IsAlphaPixelFormat($icon.PixelFormat)) {
        throw "App icon must be opaque; found pixel format $($icon.PixelFormat)."
    }
} finally {
    $icon.Dispose()
}

$project = Get-Content -Raw -LiteralPath $projectFile
$openBraces = ($project.ToCharArray() | Where-Object { $_ -eq '{' }).Count
$closeBraces = ($project.ToCharArray() | Where-Object { $_ -eq '}' }).Count
if ($openBraces -ne $closeBraces) { throw 'The Xcode project has unbalanced braces.' }

$requiredFiles = @(
    'FlowGet.xcodeproj\project.pbxproj',
    'FlowGet.xcodeproj\xcshareddata\xcschemes\FlowGet.xcscheme',
    'FlowGet\FlowGetApp.swift',
    'FlowGet\DownloadManager.swift',
    'FlowGet\BrowserView.swift',
    'FlowGet\GoogleSignInService.swift',
    'FlowGet\LicensingService.swift',
    'FlowGet\FlowShareCoordinator.swift',
    'FlowGet\NativeCoreBridge.swift',
    'FlowGet\Generated\flowget_flowshare_core.swift',
    'Native\flowshare-core.source',
    'Native\flowshare-core.Cargo.lock',
    'Native\Vendor\crates\flowget-flowshare-core\Cargo.toml',
    'Native\Vendor\crates\flowget-flowshare-core\src\cross_platform.rs',
    'build-flowshare-core.sh',
    'FlowGetTests\BrowserDownloadTests.swift',
    'FlowGetTests\FlowShareTests.swift',
    'FlowGetTests\URLInputTests.swift',
    'FlowGetTests\PolicyTests.swift'
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $relativePath))) {
        throw "Missing required project file: $relativePath"
    }
}

$forbidden = Get-ChildItem -LiteralPath $sourceRoot -Filter '*.swift' |
    Select-String -Pattern 'com\.flowget\.android|H:\\Android\\Projects\\FlowGetAndroid'
if ($forbidden) { throw 'An Android-only identifier or local Android path leaked into Swift source.' }

$pin = (Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Native\flowshare-core.source')).Trim()
if ($pin -notmatch '^[0-9a-f]{40}$') { throw 'FlowShare core source must be pinned to a full Git commit.' }
if ($project -notmatch 'FlowGetNativeCore\.xcframework') { throw 'The FlowShare XCFramework is not linked in the Xcode project.' }

$infoPlist = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Info.plist')
if ($infoPlist -notmatch 'NSAppTransportSecurity' -or $infoPlist -notmatch 'NSAllowsArbitraryLoads') {
    throw 'The user-facing downloader/browser must declare its intentional HTTP transport policy.'
}

$flowShareSource = Get-Content -Raw -LiteralPath (Join-Path $sourceRoot 'FlowShareCoordinator.swift')
if ($flowShareSource -notmatch 'validSignalingEndpoint' -or
    $flowShareSource -notmatch 'sendAckConfirmed' -or
    $flowShareSource -notmatch 'awaitReceiverReady') {
    throw 'FlowShare signaling validation, receiver readiness, or durable acknowledgement handling is missing.'
}

$browserSource = Get-Content -Raw -LiteralPath (Join-Path $sourceRoot 'BrowserView.swift')
$downloadManagerSource = Get-Content -Raw -LiteralPath (Join-Path $sourceRoot 'DownloadManager.swift')
if ($browserSource -notmatch 'startDownload' -or
    $downloadManagerSource -notmatch 'WKDownloadDelegate' -or
    $downloadManagerSource -notmatch 'stageTemporaryDownload') {
    throw 'Native authenticated WebKit download handling is missing.'
}

$swiftFiles = Get-ChildItem -LiteralPath $sourceRoot -Filter '*.swift'
$testFiles = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'FlowGetTests') -Filter '*.swift'
Write-Host "Static validation passed: $($swiftFiles.Count) app Swift files, $($testFiles.Count) test files."
Write-Host 'Run zsh verify-on-mac.sh on macOS for the Apple SDK build and tests.'
