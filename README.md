# HackerBar Mobile

Android security testing workbench, prototype 0.1.1. For systems you own or are explicitly authorized to test.

## Implemented
- HTTPS Repeater with exact-host allowlist, manual headers/body, bounded timeout and response display.
- Redirects disabled; no automatic cross-host requests. One-second minimum interval between manual sends.
- Curated starter payload library, manual WAF normalization lab, encoder/decoder, baseline comparison.
- GitHub Actions debug APK build.

## Limitations
This is not a full browser proxy, MITM, HTTP/2 smuggling engine, or production-grade WAF scanner. The library is a small curated starter set, not a claim of thousands of verified payloads. Response diff is a basic comparison, not semantic analysis. Findings persistence and browser inspection are not implemented. No APK has been device-tested merely because CI passes.

## Build
Run `./gradlew clean assembleDebug` or download the APK artifact from the Android APK GitHub Actions workflow. Debug APKs are not Play Store releases.

## Next engineering priorities
Extract the HTTP engine into testable modules; add unit/instrumentation tests, safe persistent collections, proper structured response diff, content-type-aware bodies, request cancellation, redirect inspection, signed payload packs with license attribution, and a real browser inspector. Verify all features on Android 16 before a stable release.
