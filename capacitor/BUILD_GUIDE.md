# OMNI Native App Build Guide

## What you need
- **iOS**: Mac with Xcode 15+, Apple Developer account ($99/year)
- **Android**: Android Studio, Google Play Developer account ($25 one-time)

## IAP Product IDs (register these FIRST)

### App Store Connect (iOS)
1. Go to App Store Connect → Your app → In-App Purchases
2. Create 5 products:
   - `com.omnitap.pro.monthly` — Auto-Renewable Subscription, $4.99/month
   - `com.omnitap.premium.monthly` — Auto-Renewable Subscription, $9.99/month
   - `com.omnitap.tokens.1700` — Consumable, $1.99
   - `com.omnitap.tokens.3500` — Consumable, $3.99
   - `com.omnitap.tokens.9000` — Consumable, $9.99

### Google Play Console (Android)
1. Go to Play Console → Your app → Monetize → Products
2. Create 2 subscriptions + 3 in-app products with the same IDs and prices

## Build Steps

### 1. Install dependencies
```bash
cd capacitor
npm install
```

### 2. Copy web assets
```bash
npm run build
# Copies ../index.html → www/
```

### 3. Add platforms
```bash
npx cap add ios
npx cap add android
```

### 4. Sync
```bash
npx cap sync
```

### 5. Open in IDE
```bash
npx cap open ios      # Opens Xcode
npx cap open android  # Opens Android Studio
```

### 6. Configure
**iOS (Xcode):**
- Set Bundle ID: `com.omnitap.app`
- Set Team (your Apple Developer account)
- Enable: NFC (Near Field Communication Tag Reading), In-App Purchase, Face ID
- Add `NFCReaderUsageDescription` and `NSFaceIDUsageDescription` to Info.plist

**Android (Android Studio):**
- Set applicationId: `com.omnitap.app`
- Add NFC permission to AndroidManifest.xml
- Add `com.android.vending.BILLING` permission

### 7. Build & Test
- iOS: Run on device → TestFlight → App Store
- Android: Build APK/AAB → Internal testing → Production

## What's already wired
- ✅ Native IAP for Pro/Premium/token packs (native-bridge.js)
- ✅ Restore Purchases button
- ✅ NFC tap-to-share
- ✅ Save to phone contacts
- ✅ Native share sheet
- ✅ Face ID / Touch ID / fingerprint unlock
- ✅ Haptic feedback
- ✅ Server-side receipt verification endpoint (/api/iap/verify)

## App Store Review Notes
- Guideline 4.2 (Minimum Functionality): Native NFC, contacts, biometrics, and share sheet provide native value beyond a web wrapper
- Guideline 3.1.1 (IAP): All digital purchases use StoreKit/Play Billing, not Stripe
- Privacy: Privacy policy at https://omni-tap.com/privacy.html
- Account deletion: Available in app (Data controls → Delete account)
