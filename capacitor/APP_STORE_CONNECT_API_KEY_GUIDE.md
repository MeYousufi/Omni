# App Store Connect API Key — 5-Step Guide

Codemagic needs this key to sign your app and upload to TestFlight automatically. It takes about 5 minutes.

## Step 1: Enroll in Apple Developer Program ($99/year)

1. Go to [developer.apple.com/programs](https://developer.apple.com/programs/)
2. Click **Enroll** and sign in with your Apple ID
3. Complete enrollment as an **Individual** (simplest for now)
4. Pay $99 — your account activates within 24–48 hours

> You cannot create the API key until enrollment is active.

## Step 2: Create the API Key

1. Go to [App Store Connect](https://appstoreconnect.apple.com/) → sign in
2. Click **Users and Access** (top nav)
3. Click the **Integrations** tab → **App Store Connect API**
4. Click the **+** button to create a new key
5. Name it `Codemagic OMNI` and set access to **App Manager**
6. Click **Generate**

## Step 3: Download the Key File (do this NOW)

1. After generating, click **Download API Key** — you get a `.p8` file
2. **Apple shows this file exactly once.** Save it somewhere safe.
3. Note the three values on screen:
   - **Issuer ID** (a UUID like `57246542-96fe-1a63-e053-0824d011072a`)
   - **Key ID** (like `2X9R4HXF34`)
   - The `.p8` file contents (starts with `-----BEGIN PRIVATE KEY-----`)

## Step 4: Add the Key to Codemagic

1. Go to [codemagic.io](https://codemagic.io) → sign up with GitHub → add the `MeYousufi/Omni` repo
2. In your Codemagic team settings → **Integrations** → **Apple Developer Portal** → **App Store Connect API**
3. Fill in:
   - **Issuer ID**: paste from Step 3
   - **Key ID**: paste from Step 3
   - **Private key**: paste the full `.p8` file contents
4. Save

## Step 5: Add the Encrypted Variables to codemagic.yaml

Codemagic encrypts sensitive values. In your Codemagic dashboard:

1. Open your app → **Environment variables**
2. Add these three as **secure** variables:
   - `APP_STORE_CONNECT_ISSUER_ID` → your Issuer ID
   - `APP_STORE_CONNECT_KEY_IDENTIFIER` → your Key ID
   - `APP_STORE_CONNECT_PRIVATE_KEY` → the `.p8` contents
3. Also add:
   - `CERTIFICATE_PRIVATE_KEY` → generate a random password (Codemagic uses this for its temporary keychain). Any long random string works — save it in your password manager.

The `codemagic.yaml` in this repo already references these variable names, so once they're set in the dashboard, builds will sign automatically.

## What happens on first build

1. Codemagic pulls your repo
2. Installs npm deps, copies web assets into `capacitor/www/`
3. Runs `npx cap add ios` + `npx cap sync`
4. Fetches/creates the distribution certificate + provisioning profile via your API key
5. Builds the `.ipa` and uploads straight to TestFlight
6. You get an email from Apple when the build is ready to test

## Troubleshooting

- **"No signing certificate found"**: The API key needs **App Manager** access (not just Developer). Recreate with the right role.
- **"Bundle ID not found"**: Register `com.omnitap.app` in App Store Connect → My Apps → + → New App before the first build.
- **Build minutes**: Free Codemagic accounts get 500 macOS minutes/month. An iOS build takes ~8–12 minutes, so that's ~40+ builds/month — plenty for TestFlight iterations.
