# OMNI Capacitor Setup — Native App Preparation

## Status: Config ready, native build pending

The `capacitor.config.json` is prepared. To build native apps:

### iOS (requires Mac with Xcode)
```bash
npm install @capacitor/core @capacitor/cli
npx cap init
npx cap add ios
npx cap sync
npx cap open ios
```

### Android (requires Android Studio)
```bash
npx cap add android
npx cap sync
npx cap open android
```

## Required native plugins for App Store compliance (Guideline 4.2)

These provide the "native value" Apple requires beyond a web wrapper:

| Plugin | Purpose | Package |
|--------|---------|---------|
| NFC | Tap-to-share via Core NFC (iOS) / NFC (Android) | `@capacitor-community/nfc` |
| Contacts | Save received cards to phone contacts | `@capacitor/contacts` |
| Share | Native share sheet | `@capacitor/share` |
| Biometrics | Face ID / Touch ID / fingerprint unlock | `@capacitor-community/biometric-auth` |
| Haptics | Tap feedback | `@capacitor/haptics` |
| In-App Purchase | Pro/Premium subscriptions, token packs | `@capacitor-community/in-app-purchase` |

## IAP Product IDs (to register in App Store Connect / Play Console)
- `com.omnitap.pro.monthly` — Pro $4.99/month
- `com.omnitap.premium.monthly` — Premium $9.99/month
- `com.omnitap.tokens.1700` — 1,700 tokens $1.99
- `com.omnitap.tokens.3500` — 3,500 tokens $3.99
- `com.omnitap.tokens.9000` — 9,000 tokens $9.99

## Notes
- The web app already detects `window.Capacitor.isNativePlatform()` for Restore Purchases
- `subscribePlan()` and `buyTokens()` currently show "coming soon" — wire to IAP plugin when native
- Owner controls are hidden in production (enable via `?owner=1` URL param)
- Privacy policy: https://omni-tap.com/privacy.html
- Terms: https://omni-tap.com/terms.html
