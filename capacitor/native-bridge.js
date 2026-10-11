// OMNI Native Bridge — Capacitor plugin integrations
// This file is loaded by index.html when running as a native app.
// Provides: NFC, Contacts, Share, Biometrics, Haptics, In-App Purchase

(function(){
  'use strict';
  if (!window.Capacitor || !Capacitor.isNativePlatform()) return;
  console.log('[OMNI Native] Bridge initializing...');

  const { Nfc, Contacts, Share, Haptics } = Capacitor.Plugins;

  // ============ NATIVE DETECTION ============
  window.OMNI_NATIVE = {
    platform: Capacitor.getPlatform(), // 'ios' or 'android'
    isNative: true,
  };

  // ============ HAPTICS ============
  window.omniHaptic = async function(style){
    try { await Haptics.impact({style: style || 'MEDIUM'}); } catch(e){}
  };
  window.omniNotify = async function(){
    try { await Haptics.notification({type: 'SUCCESS'}); } catch(e){}
  };

  // ============ NFC ============
  // Write card URL to NFC tag (for tap-to-share with physical tags)
  window.omniNfcWrite = async function(url){
    try {
      if (Capacitor.getPlatform() === 'ios') {
        // iOS: Core NFC — write NDEF record
        await Nfc.write({ records: [{ type: 'U', payload: url }] });
      } else {
        await Nfc.write({ records: [{ type: 'U', payload: url }] });
      }
      return {ok: true};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // ============ CONTACTS ============
  // Save a received card directly to phone contacts
  window.omniSaveContact = async function(card){
    try {
      const permission = await Contacts.requestPermissions();
      if (permission.contacts !== 'granted') return {ok: false, error: 'Permission denied'};

      await Contacts.createContact({
        contact: {
          name: { given: card.name?.split(' ')[0] || '', family: card.name?.split(' ').slice(1).join(' ') || '' },
          phones: card.phone ? [{ label: 'mobile', number: card.phone }] : [],
          emails: card.email ? [{ label: 'work', address: card.email }] : [],
          organization: card.company ? { name: card.company, title: card.title || '' } : undefined,
          note: card.bio || '',
          urls: card.website ? [{ label: 'website', url: card.website }] : [],
        }
      });
      return {ok: true};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // ============ SHARE SHEET ============
  window.omniNativeShare = async function(title, text, url){
    try {
      await Share.share({ title, text, url, dialogTitle: 'Share your OMNI card' });
      return {ok: true};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // ============ BIOMETRICS ============
  // Check if biometric unlock is available
  window.omniBiometricAvailable = async function(){
    try {
      const { BiometricAuth } = Capacitor.Plugins;
      const result = await BiometricAuth.checkBiometry();
      return result.isAvailable;
    } catch(e) { return false; }
  };

  // Authenticate with Face ID / Touch ID / fingerprint
  window.omniBiometricAuth = async function(){
    try {
      const { BiometricAuth } = Capacitor.Plugins;
      await BiometricAuth.authenticate({
        reason: 'Unlock your OMNI vault',
        title: 'OMNI',
        subtitle: 'Biometric unlock',
        negativeButtonText: 'Use PIN',
      });
      return {ok: true};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // ============ IN-APP PURCHASE ============
  const IAP_PRODUCTS = {
    pro: Capacitor.getPlatform() === 'ios' ? 'com.omnitap.pro.monthly' : 'com.omnitap.pro.monthly',
    premium: Capacitor.getPlatform() === 'ios' ? 'com.omnitap.premium.monthly' : 'com.omnitap.premium.monthly',
    tokens_1700: 'com.omnitap.tokens.1700',
    tokens_3500: 'com.omnitap.tokens.3500',
    tokens_9000: 'com.omnitap.tokens.9000',
  };
  window.OMNI_IAP_PRODUCTS = IAP_PRODUCTS;

  // Purchase a subscription (Pro/Premium)
  window.omniPurchaseSubscription = async function(tier){
    try {
      const { InAppPurchase } = Capacitor.Plugins;
      const productId = IAP_PRODUCTS[tier];
      if (!productId) throw new Error('Invalid tier');

      // Get product info
      const { products } = await InAppPurchase.getProducts({ productIds: [productId] });
      if (!products.length) throw new Error('Product not found in store');

      // Initiate purchase
      const result = await InAppPurchase.purchase({ productId });

      // Verify receipt with our server
      const syncId = localStorage.getItem('omni_sync_id') || '';
      const verifyResp = await fetch('https://omni-stats.mny2199wellness.workers.dev/api/iap/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          platform: Capacitor.getPlatform(),
          productId,
          receipt: result.receipt,
          transactionId: result.transactionId,
          syncId, tier,
        }),
      });
      const verify = await verifyResp.json();
      if (!verify.ok) throw new Error(verify.error || 'Receipt verification failed');

      // Finish transaction
      await InAppPurchase.finishTransaction({ productId });

      return {ok: true, tier};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // Purchase token pack (consumable)
  window.omniPurchaseTokens = async function(packIndex){
    try {
      const { InAppPurchase } = Capacitor.Plugins;
      const keys = ['tokens_1700', 'tokens_3500', 'tokens_9000'];
      const productId = IAP_PRODUCTS[keys[packIndex]];
      if (!productId) throw new Error('Invalid pack');

      const result = await InAppPurchase.purchase({ productId });

      const syncId = localStorage.getItem('omni_sync_id') || '';
      const verifyResp = await fetch('https://omni-stats.mny2199wellness.workers.dev/api/iap/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          platform: Capacitor.getPlatform(),
          productId,
          receipt: result.receipt,
          transactionId: result.transactionId,
          syncId, tokens: [1700, 3500, 9000][packIndex],
        }),
      });
      const verify = await verifyResp.json();
      if (!verify.ok) throw new Error(verify.error || 'Receipt verification failed');

      await InAppPurchase.finishTransaction({ productId });
      return {ok: true, tokens: [1700, 3500, 9000][packIndex]};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  // Restore previous purchases
  window.omniRestorePurchases = async function(){
    try {
      const { InAppPurchase } = Capacitor.Plugins;
      const { purchases } = await InAppPurchase.restorePurchases();

      const syncId = localStorage.getItem('omni_sync_id') || '';
      const results = [];
      for (const p of purchases) {
        const verifyResp = await fetch('https://omni-stats.mny2199wellness.workers.dev/api/iap/verify', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            platform: Capacitor.getPlatform(),
            productId: p.productId,
            receipt: p.receipt,
            transactionId: p.transactionId,
            syncId, restore: true,
          }),
        });
        const verify = await verifyResp.json();
        if (verify.ok) results.push(p.productId);
      }
      return {ok: true, restored: results};
    } catch(e) {
      return {ok: false, error: e.message};
    }
  };

  console.log('[OMNI Native] Bridge ready on', Capacitor.getPlatform());
})();
