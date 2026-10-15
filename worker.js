/* ============================================================
 * omni-stats worker — Cloudflare Worker for the OMNI PWA
 *
 * KV binding (must exist):  OMNI_STATS  (namespace: omni_stats)
 *
 * Environment variables to set in the Cloudflare dashboard
 * (Workers & Pages -> omni-stats -> Settings -> Variables):
 *
 *   OWNER_KEY         string   REQUIRED. Must match the OWNER_KEY baked
 *                              into the app (currently "omni-owner-9f3k7x2m").
 *                              Guards /api/stats, /api/flags (POST), /api/grant.
 *   STRIPE_SECRET_KEY string   REQUIRED only for Buy Shares. Your Stripe
 *                              secret key (use sk_test_... while testing,
 *                              sk_live_... for real charges). The Buy Shares
 *                              toggle returns 503 until this is set.
 *   PUBLIC_URL        string   Optional. Defaults to https://omni-tap.com/
 *                              Used for Stripe success/cancel return URLs.
 *   PASS_KEY_PEM      secret   REQUIRED for Apple Wallet. The Pass Type ID
 *                              private key PEM (-----BEGIN PRIVATE KEY-----).
 *   PASS_CERT_PEM     secret   REQUIRED for Apple Wallet. The Pass Type ID
 *                              certificate PEM (-----BEGIN CERTIFICATE-----).
 *   WWDR_CERT_PEM     secret   REQUIRED for Apple Wallet. Apple WWDR G4
 *                              intermediate cert PEM (AppleWWDRCAG4).
 *
 * HOW TO DEPLOY:
 *   1. Copy this file's contents into the Cloudflare dashboard:
 *      Workers & Pages -> omni-stats -> Code -> Edit code -> paste -> Deploy.
 *      (Or: npx wrangler deploy --name omni-stats  with the KV binding set.)
 *   2. Add the env vars above under Settings -> Variables -> Add variable.
 *   3. Verify:  GET https://omni-stats.mny2199wellness.workers.dev/api/flags
 *      should return {"shareLimits":false,"invites":false,"buyShares":false}
 *
 * VAULT SYNC (2026-10-09): /api/vault/save|load|delete — zero-knowledge
 * encrypted vault sync so cards follow the user across browsers/devices.
 *
 * NOTE: this file re-implements the original analytics + short-link
 * endpoints, so deploying it REPLACES the old worker. Historical
 * analytics counters restart from zero (fresh KV keys). Card short-links
 * created before this deploy will stop resolving.
 * ============================================================ */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });

const dayStr = (d = new Date()) => d.toISOString().slice(0, 10);

function genId(n = 12) {
  const c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const r = crypto.getRandomValues(new Uint8Array(n));
  let s = "";
  for (let i = 0; i < n; i++) s += c[r[i] % c.length];
  return s;
}

async function sha256hex(s){
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(h)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

// PBKDF2 password hashing (100k iterations, SHA-256)
async function hashPassword(password, salt){
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return [...new Uint8Array(bits)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function verifyPassword(password, salt, expectedHash){
  const h = await hashPassword(password, salt);
  return timingSafeEqual(h, expectedHash);
}

// Constant-time string comparison (prevents timing attacks on codes/tokens)
function timingSafeEqual(a, b){
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Send a password-reset email via Resend (fire-and-forget; never throws)
// Requires RESEND_API_KEY in worker env. RESET_EMAIL_FROM optional (default noreply@omni-tap.com).
async function sendResetEmail(env, toEmail, code){
  try{
    const apiKey = env.RESEND_API_KEY;
    if (!apiKey) return; // not configured — caller returns generic ok
    const from = env.RESET_EMAIL_FROM || "noreply@omni-tap.com";
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": "Bearer " + apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "OMNI <" + from + ">",
        to: [toEmail],
        subject: "Your OMNI password reset code",
        text: "Your OMNI password reset code is: " + code +
          "\n\nThis code expires in 15 minutes and can only be used once." +
          "\nIf you didn't request this, just ignore this email — your password stays the same.",
      }),
    });
  }catch(e){ /* fire-and-forget: never break the reset flow on email failure */ }
}

// Owner auth: password-based token. The password hash lives in KV;
// the raw password/owner key is never in client code.
async function ownerTokenValid(req, kv){
  try{
    const u = new URL(req.url);
    let tok = u.searchParams.get("owner_token") || "";
    if(req.method === "POST"){
      try{ const b = await req.clone().json(); tok = b.owner_token || tok; }catch(e){}
    }
    if(tok && tok.length >= 16){
      // Retry once for KV propagation delay (login write may not be visible yet)
      for(let attempt=0; attempt<2; attempt++){
        const v = await kv.get("owner:token:" + tok);
        // Token stores the generation; must match current generation
        // (password change bumps generation, invalidating old tokens)
        if(v){
          const gen = (await kv.get("owner:gen")) || "0";
          // Legacy tokens stored "1" — treat as gen 0
          if(v === "1") return gen === "0";
          if(v === gen) return true;
        }
        if(attempt===0) await new Promise(r=>setTimeout(r,500));
      }
    }
  }catch(e){}
  return false;
}

// Fire-and-forget webhook POST (never blocks the response)
async function fireWebhook(env, kv, payload){
  try{
    const whUrl = await kv.get("webhook:url");
    if(!whUrl) return;
    await fetch(whUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "omni", ...payload }),
    });
  }catch(e){ /* webhook failures are silent */ }
}

const DEFAULT_FLAGS = { shareLimits: false, invites: true, buyShares: false, faceIdUnlock: false, glassLevel: 60 };
async function getFlags(env) {
  try {
    const f = await env.OMNI_STATS.get("flags", "json");
    if (f) return { ...DEFAULT_FLAGS, ...f };
  } catch (e) {}
  return { ...DEFAULT_FLAGS };
}

/* ============================================================
 * APPLE WALLET .pkpass — signing library + placeholder images
 * (inlined from wallet/pkpass-lib.js and wallet/pass-images.js)
 * Secrets required: PASS_KEY_PEM, PASS_CERT_PEM, WWDR_CERT_PEM
 * ============================================================ */
/* ============================================================
 * OMNI Apple Wallet .pkpass library (Cloudflare Worker compatible)
 *
 * Self-contained: no imports, no npm. Uses only WebCrypto
 * (crypto.subtle), TextEncoder, and atob — all available in
 * Cloudflare Workers and modern browsers/Node.
 *
 * Produces a fully valid PKCS#7/CMS SignedData (detached)
 * signature over manifest.json, as required by Apple Wallet.
 *
 * ESM: import { buildPkpass, createPKCS7 } from './pkpass-lib.js'
 * For worker.js (single-file deploy): inline this file's body with
 * the leading `export ` keywords stripped.
 * ============================================================ */

// ---------- byte helpers ----------
function pkConcat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function pkDerLen(len) {
  if (len < 128) return new Uint8Array([len]);
  const bytes = [];
  let l = len;
  while (l > 0) { bytes.unshift(l & 0xff); l >>>= 8; }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function pkTLV(tag, value) {
  const v = value instanceof Uint8Array ? value : new TextEncoder().encode(value);
  const len = pkDerLen(v.length);
  const out = new Uint8Array(1 + len.length + v.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(v, 1 + len.length);
  return out;
}

const pkSeq = (...items) => pkTLV(0x30, pkConcat(...items));
const pkSet = (...items) => pkTLV(0x31, pkConcat(...items));
const pkInt = (n) => pkTLV(0x02, new Uint8Array([n])); // small positive ints only
const pkNull = () => new Uint8Array([0x05, 0x00]);
const pkOctet = (b) => pkTLV(0x04, b);

function pkOid(oidStr) {
  const parts = oidStr.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v >>>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>>= 7; }
    bytes.push(...stack);
  }
  return pkTLV(0x06, new Uint8Array(bytes));
}

function pkUTCTime(date) {
  const p = (n) => String(n).padStart(2, '0');
  const s = p(date.getUTCFullYear() % 100) + p(date.getUTCMonth() + 1) +
            p(date.getUTCDate()) + p(date.getUTCHours()) +
            p(date.getUTCMinutes()) + p(date.getUTCSeconds()) + 'Z';
  return pkTLV(0x17, s);
}

function pkPemToDer(pem, label) {
  const b64 = pem
    .replace('-----BEGIN ' + label + '-----', '')
    .replace('-----END ' + label + '-----', '')
    .replace(/\s/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function pkHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function pkSha1(subtle, data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await subtle.digest('SHA-1', buf));
}
async function pkSha256(subtle, data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await subtle.digest('SHA-256', buf));
}

// ---------- minimal DER reader (for X.509 cert parsing) ----------
function pkReadTLV(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let hlen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i];
    hlen = 2 + n;
  }
  return { tag, len, headerLen: hlen, start: off + hlen, totalLen: hlen + len };
}

function pkChildren(buf, tlv) {
  // tlv: parsed TLV of a constructed type; returns array of child TLVs
  const kids = [];
  let off = tlv.start;
  const end = tlv.start + tlv.len;
  while (off < end) {
    const c = pkReadTLV(buf, off);
    kids.push(c);
    off += c.totalLen;
  }
  return kids;
}

/* Extract the raw DER (tag+length+value) of the issuer Name and the
 * serialNumber INTEGER from a DER-encoded X.509 certificate. */
function pkCertIssuerAndSerial(certDer) {
  const outer = pkReadTLV(certDer, 0);
  if (outer.tag !== 0x30) throw new Error('not a DER certificate');
  const tbs = pkChildren(certDer, outer)[0];
  const f = pkChildren(certDer, tbs);
  // f[0] = [0] version, f[1] = serialNumber, f[2] = signature, f[3] = issuer
  const serial = f[1];
  const issuer = f[3];
  if (serial.tag !== 0x02) throw new Error('unexpected cert layout (serial)');
  if (issuer.tag !== 0x30) throw new Error('unexpected cert layout (issuer)');
  return {
    issuerDer: certDer.slice(issuer.start - issuer.headerLen, issuer.start + issuer.len),
    serialDer: certDer.slice(serial.start - serial.headerLen, serial.start + serial.len),
  };
}

// ---------- PKCS#7 / CMS SignedData (detached) ----------
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_ATTR_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

function pkLexLess(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}

/* Build the DER-encoded PKCS#7 SignedData for `content` (the raw
 * manifest.json bytes). Returns a Uint8Array of the DER signature. */
async function createPKCS7(content, secrets, subtle) {
  subtle = subtle || globalThis.crypto.subtle;
  const keyDer = pkPemToDer(secrets.keyPem, 'PRIVATE KEY');
  const certDer = pkPemToDer(secrets.certPem, 'CERTIFICATE');
  const wwdrDer = pkPemToDer(secrets.wwdrPem, 'CERTIFICATE');

  const key = await subtle.importKey(
    'pkcs8', keyDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const { issuerDer, serialDer } = pkCertIssuerAndSerial(certDer);

  const digestAlgo = pkSeq(pkOid(OID_SHA256), pkNull());
  const sigAlgo = pkSeq(pkOid(OID_RSA_SHA256), pkNull());

  // Signed attributes (DER SET OF — must be sorted by encoding)
  const messageDigest = await pkSha256(subtle, content);
  const attrContentType = pkSeq(pkOid(OID_ATTR_CONTENT_TYPE), pkSet(pkOid(OID_DATA)));
  const attrSigningTime = pkSeq(pkOid(OID_ATTR_SIGNING_TIME), pkSet(pkUTCTime(new Date())));
  const attrMessageDigest = pkSeq(pkOid(OID_ATTR_MESSAGE_DIGEST), pkSet(pkOctet(messageDigest)));
  const attrs = [attrContentType, attrSigningTime, attrMessageDigest]
    .sort(pkLexLess); // DER SET OF ordering
  const attrsContent = pkConcat(...attrs);
  const signedAttrsField = pkConcat(new Uint8Array([0xa0]), pkDerLen(attrsContent.length), attrsContent);
  // The data actually signed: same bytes re-tagged as SET OF
  const dataToSign = pkConcat(new Uint8Array([0x31]), pkDerLen(attrsContent.length), attrsContent);
  const sig = new Uint8Array(await subtle.sign('RSASSA-PKCS1-v1_5', key, dataToSign));

  const signerInfo = pkSeq(
    pkInt(1),
    pkSeq(issuerDer, serialDer), // issuerAndSerialNumber
    digestAlgo,
    signedAttrsField,            // [0] IMPLICIT
    sigAlgo,
    pkOctet(sig)
  );

  const certsField = pkConcat(
    new Uint8Array([0xa0]),
    pkDerLen(certDer.length + wwdrDer.length),
    certDer, wwdrDer
  );

  const signedData = pkSeq(
    pkInt(1),
    pkSet(digestAlgo),
    pkSeq(pkOid(OID_DATA)),      // encapContentInfo (detached: no eContent)
    certsField,                  // [0] IMPLICIT certificates
    pkSet(signerInfo)
  );

  return pkSeq(
    pkOid(OID_SIGNED_DATA),
    pkConcat(new Uint8Array([0xa0]), pkDerLen(signedData.length), signedData)
  );
}

// ---------- minimal ZIP writer (stored entries) ----------
function pkCrc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createZip(files) {
  const enc = new TextEncoder();
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const [name, data] of Object.entries(files)) {
    const nb = enc.encode(name);
    const db = data instanceof Uint8Array ? data : enc.encode(String(data));
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true);
    lh.setUint16(4, 20, true);
    lh.setUint16(6, 0x0800, true);
    lh.setUint16(8, 0, true);
    lh.setUint32(14, pkCrc32(db), true);
    lh.setUint32(18, db.length, true);
    lh.setUint32(22, db.length, true);
    lh.setUint16(26, nb.length, true);
    chunks.push(new Uint8Array(lh.buffer), nb, db);
    central.push({ nb, size: db.length, crc: pkCrc32(db), offset });
    offset += 30 + nb.length + db.length;
  }
  const cdStart = offset;
  const cdChunks = [];
  for (const f of central) {
    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true);
    ch.setUint16(4, 20, true);
    ch.setUint16(6, 20, true);
    ch.setUint16(8, 0x0800, true);
    ch.setUint32(16, f.crc, true);
    ch.setUint32(20, f.size, true);
    ch.setUint32(24, f.size, true);
    ch.setUint16(28, f.nb.length, true);
    ch.setUint32(42, f.offset, true);
    cdChunks.push(new Uint8Array(ch.buffer), f.nb);
    offset += 46 + f.nb.length;
  }
  const eocd = new DataView(new ArrayBuffer(22));
  eocd.setUint32(0, 0x06054b50, true);
  eocd.setUint16(8, central.length, true);
  eocd.setUint16(10, central.length, true);
  eocd.setUint32(12, offset - cdStart, true);
  eocd.setUint32(16, cdStart, true);
  return pkConcat(...chunks, ...cdChunks, new Uint8Array(eocd.buffer));
}

// ---------- pass.json builder ----------
const PASS_TYPE_ID = 'pass.com.omnitap.card';
const TEAM_ID = '7R43JAU47W';

function str(v, n) {
  return String(v == null ? '' : v).slice(0, n || 120);
}

/* card: { id, name, title, org, phones[], emails[], address, notes, urls[] }
 * images: { "icon.png": Uint8Array, "logo.png": ..., ... } (filenames incl. @2x/@3x) */
function buildPassJson(card) {
  const phone = (card.phones && card.phones[0]) || '';
  const passJson = {
    formatVersion: 1,
    passTypeIdentifier: PASS_TYPE_ID,
    serialNumber: str(card.id || ('omni-' + Date.now()), 64),
    teamIdentifier: TEAM_ID,
    organizationName: 'OMNI',
    description: str((card.name || 'Contact') + ' — OMNI Card', 200),
    logoText: 'OMNI',
    foregroundColor: 'rgb(255, 255, 255)',
    backgroundColor: 'rgb(27, 28, 49)',
    labelColor: 'rgb(45, 212, 191)',
    generic: {
      primaryFields: [
        { key: 'name', label: 'NAME', value: str(card.name) },
      ],
      secondaryFields: [
        { key: 'title', label: 'TITLE', value: str(card.title) },
        { key: 'org', label: 'ORG', value: str(card.org) },
      ],
      auxiliaryFields: [
        { key: 'phone', label: 'PHONE', value: str(phone, 40) },
        { key: 'email', label: 'EMAIL', value: str((card.emails && card.emails[0]) || '') },
      ],
      backFields: [
        { key: 'address', label: 'ADDRESS', value: str(card.address, 300) },
        { key: 'website', label: 'WEBSITE', value: str((card.urls && card.urls[0]) || '') },
        { key: 'notes', label: 'NOTES', value: str(card.notes, 500) },
      ],
    },
  };
  if (phone) {
    passJson.barcodes = [{
      format: 'PKBarcodeFormatQR',
      message: 'tel:' + phone.replace(/\D/g, ''),
      messageEncoding: 'iso-8859-1',
    }];
  }
  return passJson;
}

/* Full pipeline: pass.json -> manifest.json -> signature -> .pkpass zip.
 * secrets: { keyPem, certPem, wwdrPem } (PEM strings)
 * images: { filename: Uint8Array } e.g. icon.png, icon@2x.png, logo.png...
 * subtle: WebCrypto subtle (defaults to globalThis.crypto.subtle) */
async function buildPkpass(card, images, secrets, subtle) {
  subtle = subtle || globalThis.crypto.subtle;
  if (!secrets.keyPem || !secrets.certPem || !secrets.wwdrPem)
    throw new Error('missing wallet signing secrets');

  const files = {};
  files['pass.json'] = new TextEncoder().encode(JSON.stringify(buildPassJson(card)));
  for (const [name, data] of Object.entries(images || {})) files[name] = data;

  const manifest = {};
  for (const [name, data] of Object.entries(files))
    manifest[name] = pkHex(await pkSha1(subtle, data));
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  files['manifest.json'] = manifestBytes;

  files['signature'] = await createPKCS7(manifestBytes, secrets, subtle);
  return createZip(files);
}

/* Placeholder pass images (base64). Replace with final art. */
const PKPASS_IMAGES_B64 = {
  "icon.png": "iVBORw0KGgoAAAANSUhEUgAAAB0AAAAdCAYAAABWk2cPAAAA0UlEQVR4nOWWzQ3CMAyFHasTcIUl2IJ5OgjzsEWXaK9dAU6RIquO3xNyhKhPrZ28T46dnyLGrrf72/q+tW1dSvuv2cAjXfUCmWAdAbTgMgrYmsZD/gQ6sRMur+ehf3/MsAaVqQeMYtagRrKCNqsobo1aXk+s+tFsw+WtQkjNUHgXytSJmQs1EtOZyNjzHA6/C2UaChnbhTINxMwNM2U2PrqnqRPJE2X3M3WJR+JoOaju7Yky9T/Rc8U+hLNtW5ei9WMUUKRZ3mxwq69eIAsoIvIBHA5aCna8jlkAAAAASUVORK5CYII=",
  "icon@2x.png": "iVBORw0KGgoAAAANSUhEUgAAADoAAAA6CAYAAADhu0ooAAABcUlEQVR4nO2awRHCIBBFgbECr9qEXViPhViPXaSJ5GoLemImQ1iC5C+yC+8YEPbNhpWQWJPJ5Xr75PatyTJPNqdfslOrchQpaUc1SJM0Jh1zVFSipIeKfSMqWdITc3B7HaQSujiqQQNrJxde0IZ3I6uuNroRtZpv2zXdZHSIauNUa6Lz60m2ve8P9vlZi1FKjoJLmkW0RDAELQxfowhJ5DgeaEZL12GN9QsTpYL9JVDEGBQQ0ViAR4JDj2cMYI1yBBX7/dE1Cy9GqDXVVNVFV0bO+aAZRWcBOV43e91i0fA24tq6heOW3r4jo9oYotoYotooFkWV/T1Qf2MjoyWgs4oc75BojdM71HzdnBkdFuV4SOZ4mB9nRiV0cQroQa6tph+8Wz0zGu9e0Kh+m9YSY6+rDZf7vatklnmy/WT03wHUwhmT/7m2RLybCy9oYu3kqAbphC6bNapBNuYQLUaSZanYyaorUTYVc7ZMq3vi3IR8AccGsm7vB5cNAAAAAElFTkSuQmCC",
  "icon@3x.png": "iVBORw0KGgoAAAANSUhEUgAAAFcAAABXCAYAAABxyNlsAAACUUlEQVR4nO2dwXXCMBBEZb9UkGvSRLpIPSkk9aQLmoArLSQn54FtiZWl2Vnj+VdsJH2GlQT285AaeHv/+G05fw9czqdh67nVJx5BaI5a0eaDjyx1jlXyaDlIYu+x+ih+ApL6mFKKs8mVWBslT6tyJbaOnK+FXIndxpo304QmtnEnV6ltY+5vzL0gtnHrUWUByJiSUtubyaeSC0RygQwqCTiUXCCSC0RygUguEMkF8sLuQInXn2/TcdfPL3BPthFuKWYVmiOS6DByW6XOiSCZLre31DlMydQJDS3Wq40clOSyBuydYne5tWIfCen9fj1xlYteWkVburnJtQy816A92yoRZofWc7ARlmEpOSW3lCS0CGbb8OQyB/eoDfSqJUxZeEagctmptbSFTC8luYwJh9EmTC5z21kLqq/uyWUuk7zb1oQGBCJ3TyVhAtFn1+RG2Dl59kFlAYjkApFcIJILRHKBSC4QyQXiKjfC5sKzDxC5ETYLtSD6rLIAxF0uszR4tw2Tu6fSgOorpSww0stoEyqX+c+rtS3kN0wTGhC4XHZ6mf9Ah7lWrPdAvdtbI0xZ6JniCDvBlHQJKRRd/AxEl+0Dod7N4yWZtVukTmjsS0jR0O9Dm9BNfg7o9lQnoi2tagktd++E2aE9I5ILRHKBSC6QseU5CCLP5XwalFwgkgtkTKntESliyeRTyQXyL1fp7cOtxzH3gqhn7k9lAchCrtK7jTVvq8mV4DpyvrJlQYJtlDyZBOo33yWW8JkmNKX4HqsPPYOyAtgzKNc4guiWb+0fhTb9CNzcm/0AAAAASUVORK5CYII=",
  "logo.png": "iVBORw0KGgoAAAANSUhEUgAAAKAAAAAyCAYAAADbYdBlAAAB5klEQVR4nO3dy22EMBRAUYNSQbaZFJFUkXpSSOpJFaGIgW1aSFYgPv49+4HNcM92AI3kK2MQMzRG2cvt7U/7mKjH0HeN5vFUDkZ016QRY/IBiA5zqTGKdyI8+EhDbCUbEx9CpI1EB0h8iCVpJThdEh5yhE7J3hmQ+JAr1JAzQOKDFl9LoosQQJs1QGY/aHM1tQmQ+LAXW1ttaANA07ox1oAoagqQ2Q9Hmbf2FLPD8/eX87Pfj0+Fr4Sr8gboC2+9DSEiRWuM/fQbE1/O9ri2sTnrRUhqTEQIqU2AuRERISSa+elXMx6NNWF//1H4JjjC7fU9ab9q7wMS37mkjtcUoPapM+d4xHdOKeNW3QxIfOcmHb/qAsS1ECCKIkAURYAoqroAU+8noQ7S8ZsC1H6YIOd4RHhOKePWav/bkRYiPJeU8Rr6rmmMWT4No3FDmkezEGPou2azBsyNh/gg0Rqz/fuE1IiID7HG5pxXwdKYiA8pvI/kj1HxmxDsZXHq5ZdxOMJ8yVfdjWhcyyLAWu8J4nGsG9vMgESIvdjasp6CiRDaXE2xBkRRzgCZBaHF15J3BiRC5Ao1FB0Y9wghETt5Ra8BmQ0RS9KK6CKECBEibYSXFULFYS8rtCHGayr6ulYXYnxs2suwf188tMZzJGbYAAAAAElFTkSuQmCC",
  "logo@2x.png": "iVBORw0KGgoAAAANSUhEUgAAAUAAAABkCAYAAAD32uk+AAAD/0lEQVR4nO3dzXHUMBiAYW+GCrgCRUAV1EMh1EMVpAiSKy3AIbOZzcY/si3pk63nOe+sdfE7n2yv9zIcyKfPX/9FrwGY9/z0eIleQ6pmFyp2cB6tRrGZRQke9KOVIIYvQvigX9EhDDm46AH3ImJY9YDCByypGcIqBxI+YK0aIXwofQDxA7ao0Y5ihRU+IJdS02CRCVD8gJxKNSV7AMUPKKFEW7KNlcIH1JJrS5xlAhQ/oKZczdkdQPEDIuRoz64Aih8QaW+DNgdQ/IAW7GnRpgCKH9CSrU1aHUDxA1q0pU2rAih+QMvWNqr4b4EBWpUcQNMfcARrWpUUQPEDjiS1WYsBFD/giFLa5Rog0K3ZAJr+gCNbathkAMUPOIO5ltkCA90aDaDpDziTqaaZAIFuvQug6Q84o7G2fShxoI+/fi5+5u/3HyUODZAsWwBTojf1eTEEIrz5Y5Et29+14ZsjhEBpt3+otHkCzBm+++8UQqCG15sga6a/EvGr+f1Av25bt/oxmFpxEkGgtFUBrB0lEQRKSg5gVIxEECjlYRiWr/9FRyj6+MC5XJu3OAG2Ep9W1gGcR5FfgpzZ05/f0UuAU/n85VvYsS/DML0FbnHqinpGUPigrNohfH56vHgbTALxg/IizrPLkaa/q5pToPhBXTUnQRPgDPGD+mqedwI4QfwgTq3zbzSALW9/h6H99QHHYAIcYfqDeDXOQwEEuiWAQLcEEOiWAALdEkCgWwIIdEsAR0S+nQJ4UeM8HA1g6//K1vr6gGMwAU4wBUKcWuffw+2fBPOWCEJ9tc672fcBtrrNrL0uEYR6ap9vtsAJRBDKizjPZl+JPwxtvXmlhanUixIgr6gB4/np8eJPkVYyDcJ5PAzDSwmnPtDC1DUM7awDOL5r85KuAUbHJ/r4wDkl3wSJipD4AaWsugtcO0biB5T0GsDUB6JrRUn8gBJuW7fpOcDScRI/oIZ3U9/cM4Fjcj4nKHxASfc73d3PAV6jtSeEwgdEyPYg9G3EUmIoekC00Rsfa7fBAK0bu9HrZQhAt0YD6B2BwJlMNc0ECHRrMoCmQOAM5lo2OwGKIHBkSw2zBQa6tRhAUyBwRCntSpoARRA4ktRmJW+BRRA4gjWtcg0Q6NaqAJoCgZatbdTqCVAEgRZtadOmLbAIAi3Z2qTN1wBFEGjBnhbtugkigkCkvQ3afRdYBIEIOdqT5TEYEQRqytWc7OHyNmmglNzDVvYHoU2DQAkl2lLklyAiCORUqinFQ2VLDGxVepgq/ltg0yCwRY12VI2TaRBYUnNoCpnOhBC4F7FbDN+eiiH0K/oSWXgAr4QQ+hEdvqsmFjFGEOE8WgnevSYXNUUUoX2txm7Mf3DCaMcUFofcAAAAAElFTkSuQmCC",
  "logo@3x.png": "iVBORw0KGgoAAAANSUhEUgAAAeAAAACWCAYAAAAG2Fv9AAAGfElEQVR4nO3d3XHbRhSAUdDjCvxqpQinitSTQlyPq4iKMPWaFpwHDx1Kpkj8Le69u+e8xhktOBx8ugsIOE1M0zRNn5++/IheA8AIXs7Pp+g1ZDDchyC0ADmNFubuD1ZwAWrqPcjdHZzgAvSptyB3czDCCzCGXkJc+iBEF2BslWNccuHCC8C1iiEus2DRBWCOKjFOv0jhBWCN7CH+EL2Ae8QXgLWyNyTlbwfZPzQAask4DadakPAC0FKmEKfZghZfAFrL1Jrw3wQyfRgAjCN6Gg6dgMUXgCjRDQoLcPSBA0Bkiw4fv4UXgIyO3pI+dAIWXwCyOrpRhwVYfAHI7shWHRJg8QWgiqOa1TzA4gtANUe0q2mAxReAqlo3rFmAxReA6lq2rEmAxReAXrRq2u4BFl8AetOibbsGWHwB6NXejdstwOILQO/2bN0uARZfAEaxV/M2B1h8ARjNHu0LfR0hAIxqU4BNvwCMamsDVwdYfAEY3ZYWrgqw+ALAT2ub6BowAARYHGDTLwC8tqaNiwIsvgBw29JG2oIGgACzA2z6BYD7lrTSBAwAAWYF2PQLAPPMbebDAIsvACwzp522oAEgwN0Am34BYJ1HDTUBA0AAAQaAAKf3/sNR28+fvn2d/W///evvhisBgP29nJ9vtvbj0QtZEtxH/68gA1DVzSq3mH63hPcRIQYgs1tTcNMJuGV03/s5YgxABc1uwjoqvll+LgAs8dtIvHX7OVMATcMAZPF2G3rXCThTfKcp33oA4OJVgLdMv1ljl3VdAIzlbWN3mYCzRy77+gAYz+YAV4lblXUCMIZNAa4WtWrrBaBfvwK89Ppv1ZhVXTcA9V23dtUEXD1i1dcPQH2LA9xLvHo5DgBq8jpCAAhwmqb51397nBp7eFrW+fs/0UsAONzTH39GL2G1l/PzaXaAe4zvRcUIiy7A/6rF+OX8fDr8fcBsI7wAv7ucGyuF2DXgQsQX4L5K58lZAe55+3maahxfpS8VQKQq50sTcAFVvkwAWVQ4b54e3YBVYTrcS8absSp8iQCyynxN2AScmPgCbJP5PCrAABBAgJPK/FsbQCVZz6d3AzzS9d9pGu94AYhjAgaAAAKcUNbtEoCqMp5XBRgAAggwAAQQYAAIIMAAEECAASCAAANAAAFOKPPDwwEqynheFWAACHA3wBlfz9fSaMcLQBwTcFIZt0sAKsp6PhVgAAjw4eX8fIpeBLdl/a0NoIqs59GX8/Pp4QQ8ynXRrMeZ9csDkF3286ct6AKyf4kAsqlw3pwV4KzT4V4qHF+FLxNABlXOlybgQqp8qQCiVDpPfoxeAMtcvlwZXy4NEKVSeC9+3QH9+enLj0f/+NO3r21XE6DC9vMjYgyMqGJ0p+nnHdDTtDDA09RXhHuILwC1XALsGjAABFgc4F6mxl6OA4CafgV4yROxqser+voBqOm6tau3oKtGrOq6AejLpmvA1WJWbb0A9GvzTVhVolZlnQCM4VWA174ZKXvcsq8PgP69bexuf4aUNXJZ1wXA2H4L8Jb3A2eLXbb1ADCmW23d/VnQl+hFPjFLeAHIrtmTsKIiKL4AVPDudvPcZ0PP1XIiFl0Asnrv0u5hryNssTUtvABUdfeGq72n4FuWBFlwAajk3o3Nh03A7xFVAEbkdYQAEOBugLf8TTAAjOxRQ03AABDgYYBNwQCwzJx2zpqARRgA5pnbTFvQABBgdoBNwQBw35JWmoABIMCiAJuCAeC2pY1cPAGLMAC8tqaNtqABIMCqAJuCAeCntU1cPQGLMACj29LCTVvQIgzAqLY20DVgAAiwOcCmYABGs0f7dpmARRiAUezVvN22oEUYgN7t2bpdrwGLMAC92rtxu9+EJcIA9KZF25rcBS3CAPSiVdOa/RmSCANQXcuWNf07YBEGoKrWDWv+IA4RBqCaI9p1yJOwRBiAKo5q1mGPohRhALI7slWHPgtahAHI6uhGhQXx89OXH1E/GwAuoobDsLchmYYBiBbZotDXEYowAFGiG5QmgLakAThCdHgvQifga1k+EAD6lak1aRZyzTQMwJ4yhfci3YKuCTEAW2QM70WaLehbMn9wAOSWvSGpF3fNNAzAHNnDe1FikW+JMQDXqkT3WrkFXxNigLFVDO9F2YW/JcYAY6gc3WtdHMQ1IQboUy/hvejqYG4RZICaegvuW10f3C2CDJBT78F9a6iDvUeYAY4xWmjf8x/YAh3PEWrzAQAAAABJRU5ErkJggg==",
};
function pkLoadPassImages() {
  const out = {};
  for (const [name, b64] of Object.entries(PKPASS_IMAGES_B64)) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    out[name] = bytes;
  }
  return out;
}

function pkSanitizeCard(c) {
  const s = (v, n) => String(v == null ? '' : v).slice(0, n);
  const arr = (v, n) => Array.isArray(v) ? v.slice(0, 4).map(x => s(x, n)) : [];
  return {
    id: s(c.id, 64),
    name: s(c.name, 120),
    title: s(c.title, 120),
    org: s(c.org, 120),
    phones: arr(c.phones, 40),
    emails: arr(c.emails, 120),
    address: s(c.address, 300),
    notes: s(c.notes, 500),
    urls: arr(c.urls, 200),
  };
}
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    const kv = env.OMNI_STATS;

    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (!kv) return json({ error: "KV binding OMNI_STATS missing" }, 500);

    try {
      /* ---------------- analytics (original behavior) ---------------- */
      if (p === "/api/ping" && req.method === "POST") {
        let ev = "unknown", cardId = "";
        try { const b = await req.json(); ev = b.event || "unknown"; cardId = String(b.card_id || "").slice(0, 32); } catch (e) {}
        const tk = "st:total";
        let t = {};
        try { t = (await kv.get(tk, "json")) || {}; } catch (e) {}
        t[ev] = (t[ev] || 0) + 1;
        await kv.put(tk, JSON.stringify(t));
        const dk = "st:daily:" + dayStr();
        let d = {};
        try { d = (await kv.get(dk, "json")) || {}; } catch (e) {}
        d[ev] = (d[ev] || 0) + 1;
        await kv.put(dk, JSON.stringify(d), { expirationTtl: 60 * 86400 });
        // Per-card tap tracking (for analytics dashboard)
        if (cardId && /^[A-Za-z0-9_-]{1,32}$/.test(cardId)) {
          const ck = "tap:" + cardId + ":" + dayStr();
          const cnt = parseInt((await kv.get(ck)) || "0", 10) || 0;
          await kv.put(ck, String(cnt + 1), { expirationTtl: 90 * 86400 });
          // Fire webhook if configured
          fireWebhook(env, kv, { type: "tap", card_id: cardId, event: ev, at: new Date().toISOString() }).catch(()=>{});
        }
        return json({ ok: true });
      }

      /* Per-card tap analytics (owner only) */
      if (p === "/api/taps" && req.method === "GET") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        const cardId = String(url.searchParams.get("card_id") || "").slice(0, 32);
        if (!cardId) return json({ error: "card_id required" }, 400);
        const days = [];
        let total = 0;
        for (let i = 13; i >= 0; i--) {
          const dt = new Date(Date.now() - i * 86400000);
          const k = "tap:" + cardId + ":" + dayStr(dt);
          const c = parseInt((await kv.get(k)) || "0", 10) || 0;
          total += c;
          days.push({ day: dayStr(dt), taps: c });
        }
        return json({ card_id: cardId, total, days });
      }

      if (p === "/api/stats" && req.method === "GET") {
        if (!(await ownerTokenValid(req, kv)) && url.searchParams.get("key") !== env.OWNER_KEY)
          return json({ error: "forbidden" }, 403);
        let t = {};
        try { t = (await kv.get("st:total", "json")) || {}; } catch (e) {}
        const daily = [];
        for (let i = 6; i >= 0; i--) {
          const dt = new Date(Date.now() - i * 86400000);
          const k = "st:daily:" + dayStr(dt);
          let dd = {};
          try { dd = (await kv.get(k, "json")) || {}; } catch (e) {}
          daily.push({ day: dayStr(dt), opens: dd.opens || 0 });
        }
        return json({
          opens: t.opens || 0,
          cards: t.cards || 0,
          share: t.share || 0,
          vcf: t.vcf || 0,
          nfc: t.nfc || 0,
          daily,
        });
      }

      /* ---------------- short card links (original behavior) ---------------- */
      if (p === "/api/card" && req.method === "POST") {
        let d = null;
        try { d = (await req.json()).d; } catch (e) {}
        if (!d || typeof d !== "string" || d.length > 200000)
          return json({ error: "bad payload" }, 400);
        const id = genId(12);
        await kv.put("card:" + id, JSON.stringify({ d }), {
          expirationTtl: 365 * 86400,
        });
        return json({ id });
      }
      const mCard = p.match(/^\/api\/card\/([A-Za-z0-9]{1,32})$/);
      if (mCard && req.method === "GET") {
        const v = await kv.get("card:" + mCard[1], "json");
        if (!v) return json({ error: "not found" }, 404);
        return json(v);
      }

      /* ---------------- feature flags ---------------- */
      if (p === "/api/flags" && req.method === "GET") {
        return json(await getFlags(env));
      }
      if (p === "/api/flags" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        if (!(await ownerTokenValid(req, kv)) && b.key !== env.OWNER_KEY) return json({ error: "forbidden" }, 403);
        const cur = await getFlags(env);
        const upd = {};
        for (const k of ["shareLimits", "invites", "buyShares", "faceIdUnlock"])
          if (b.flags && typeof b.flags[k] === "boolean") upd[k] = b.flags[k];
        if (b.flags && typeof b.flags.glassLevel === "number")
          upd.glassLevel = Math.max(0, Math.min(100, Math.round(b.flags.glassLevel)));
        const next = { ...cur, ...upd };
        await kv.put("flags", JSON.stringify(next));
        return json({ ok: true, flags: next });
      }

      /* ---------------- user accounts ---------------- */
      // Check if email/phone is available (hashes only, privacy-safe)
      if (p === "/api/users/check" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        const phone = String(b.phone || "").replace(/\D/g, "");
        const result = { available: true };
        if (email) {
          const eh = await sha256hex(email);
          if (await kv.get("user:email:" + eh)) {
            result.available = false; result.field = "email";
            return json(result);
          }
        }
        if (phone) {
          const ph = await sha256hex(phone);
          if (await kv.get("user:phone:" + ph)) {
            result.available = false; result.field = "phone";
            return json(result);
          }
        }
        return json(result);
      }
      // Register a new user account (stores hashes only)
      if (p === "/api/users/register" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        const phone = String(b.phone || "").replace(/\D/g, "");
        const deviceId = String(b.deviceId || "").slice(0, 64);
        if (!email || !phone || !deviceId)
          return json({ ok: false, error: "email, phone, and deviceId required" }, 400);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
          return json({ ok: false, error: "invalid email" }, 400);
        if (phone.length < 7)
          return json({ ok: false, error: "invalid phone" }, 400);
        const eh = await sha256hex(email);
        const ph = await sha256hex(phone);
        if (await kv.get("user:email:" + eh))
          return json({ ok: false, error: "email_taken" }, 409);
        if (await kv.get("user:phone:" + ph))
          return json({ ok: false, error: "phone_taken" }, 409);
        const uid = "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
        const rec = { uid, deviceId, created_at: new Date().toISOString() };
        await kv.put("user:email:" + eh, JSON.stringify(rec));
        await kv.put("user:phone:" + ph, JSON.stringify(rec));
        await kv.put("user:id:" + uid, JSON.stringify({ email_hash: eh, phone_hash: ph }));
        return json({ ok: true, uid });
      }
      /* ---------------- user authentication (2026-10-12) ----------------
       * Full login system: email + password -> session token.
       * The PIN remains the local vault encryption key (never sent to server).
       * The password is only for server authentication (never decrypts vault).
       * ------------------------------------------------------------------------ */
      // Register: create account with password
      if (p === "/api/auth/register" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const name = String(b.name || "").slice(0, 100).trim();
        const email = String(b.email || "").toLowerCase().trim();
        const phone = String(b.phone || "").replace(/\D/g, "");
        const password = String(b.password || "");
        const deviceId = String(b.deviceId || "").slice(0, 64);
        if (!name || !email || !phone || !password || !deviceId)
          return json({ ok: false, error: "name, email, phone, password, deviceId required" }, 400);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
          return json({ ok: false, error: "invalid email" }, 400);
        if (phone.length < 7)
          return json({ ok: false, error: "invalid phone" }, 400);
        if (password.length < 6)
          return json({ ok: false, error: "password_min_6" }, 400);
        const eh = await sha256hex("auth:" + email);
        const ph = await sha256hex("auth:" + phone);
        // Atomic-ish check: if either exists, reject
        if (await kv.get("auth:user:" + eh))
          return json({ ok: false, error: "email_taken" }, 409);
        if (await kv.get("auth:phone:" + ph))
          return json({ ok: false, error: "phone_taken" }, 409);
        const uid = "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
        const salt = genId(32);
        const pwdHash = await hashPassword(password, salt);
        const userRec = {
          uid, name, email_hash: eh, phone_hash: ph,
          pwd_hash: pwdHash, salt,
          deviceId, created_at: new Date().toISOString()
        };
        await kv.put("auth:user:" + eh, JSON.stringify(userRec));
        await kv.put("auth:phone:" + ph, eh); // phone -> email_hash lookup
        await kv.put("auth:id:" + uid, JSON.stringify({ email_hash: eh }));
        // Also register in the legacy duplicate-check system for compatibility
        try {
          const leh = await sha256hex(email);
          const lph = await sha256hex(phone);
          const legRec = { uid, deviceId, created_at: new Date().toISOString() };
          await kv.put("user:email:" + leh, JSON.stringify(legRec));
          await kv.put("user:phone:" + lph, JSON.stringify(legRec));
        } catch (e) {}
        // Create session
        const token = genId(48);
        const expires = Date.now() + 30 * 86400000; // 30 days
        await kv.put("auth:session:" + token, JSON.stringify({ uid, expires }), { expirationTtl: 30 * 86400 });
        return json({ ok: true, uid, token, name });
      }

      // Login: email + password -> session token
      if (p === "/api/auth/login" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        const password = String(b.password || "");
        if (!email || !password)
          return json({ ok: false, error: "email and password required" }, 400);
        const eh = await sha256hex("auth:" + email);
        const userRec = await kv.get("auth:user:" + eh, "json");
        // Generic error to avoid user enumeration
        if (!userRec)
          return json({ ok: false, error: "invalid_credentials" }, 401);
        const valid = await verifyPassword(password, userRec.salt, userRec.pwd_hash);
        if (!valid)
          return json({ ok: false, error: "invalid_credentials" }, 401);
        const token = genId(48);
        const expires = Date.now() + 30 * 86400000;
        await kv.put("auth:session:" + token, JSON.stringify({ uid: userRec.uid, expires }), { expirationTtl: 30 * 86400 });
        return json({ ok: true, uid: userRec.uid, token, name: userRec.name });
      }

      // Logout: invalidate session
      if (p === "/api/auth/logout" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        if (token) await kv.delete("auth:session:" + token);
        return json({ ok: true });
      }

      // Me: validate session, return user info
      if (p === "/api/auth/me" && req.method === "GET") {
        const token = String(url.searchParams.get("token") || "").slice(0, 64);
        if (!token) return json({ ok: false, error: "no token" }, 401);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now()) {
          if (sess) await kv.delete("auth:session:" + token);
          return json({ ok: false, error: "invalid_session" }, 401);
        }
        const idRec = await kv.get("auth:id:" + sess.uid, "json");
        if (!idRec) return json({ ok: false, error: "user_not_found" }, 404);
        const userRec = await kv.get("auth:user:" + idRec.email_hash, "json");
        if (!userRec) return json({ ok: false, error: "user_not_found" }, 404);
        return json({ ok: true, uid: userRec.uid, name: userRec.name });
      }

      // Set password: for existing users migrating to full auth (one-time)
      if (p === "/api/auth/set-password" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        const phone = String(b.phone || "").replace(/\D/g, "");
        const password = String(b.password || "");
        const name = String(b.name || "").slice(0, 100).trim();
        if (!email || !phone || !password)
          return json({ ok: false, error: "email, phone, password required" }, 400);
        if (password.length < 6)
          return json({ ok: false, error: "password_min_6" }, 400);
        const eh = await sha256hex("auth:" + email);
        // Must not already have auth account
        if (await kv.get("auth:user:" + eh))
          return json({ ok: false, error: "already_has_password" }, 409);
        // Must exist in legacy system (proves they had an account)
        const leh = await sha256hex(email);
        const legacy = await kv.get("user:email:" + leh, "json");
        if (!legacy)
          return json({ ok: false, error: "no_existing_account" }, 404);
        const ph = await sha256hex("auth:" + phone);
        const uid = legacy.uid || ("u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 10));
        const salt = genId(32);
        const pwdHash = await hashPassword(password, salt);
        const userRec = {
          uid, name: name || "User", email_hash: eh, phone_hash: ph,
          pwd_hash: pwdHash, salt,
          deviceId: legacy.deviceId || "", created_at: new Date().toISOString(),
          migrated: true
        };
        await kv.put("auth:user:" + eh, JSON.stringify(userRec));
        await kv.put("auth:phone:" + ph, eh);
        await kv.put("auth:id:" + uid, JSON.stringify({ email_hash: eh }));
        const token = genId(48);
        const expires = Date.now() + 30 * 86400000;
        await kv.put("auth:session:" + token, JSON.stringify({ uid, expires }), { expirationTtl: 30 * 86400 });
        return json({ ok: true, uid, token, name: userRec.name });
      }

      // Authenticated vault save: ties encrypted vault to user account (cloud-only storage)
      // v2 format: {v:2, blob (VK-encrypted), wkey_pin, wkey_pwd} — all opaque to server.
      // v1 format: {blob (PIN-encrypted)} — migrated client-side on next unlock.
      if (p === "/api/auth/vault/save" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        const blob = String(b.blob || "");
        const updatedAt = parseInt(b.updated_at, 10) || Date.now();
        const vkey = String(b.vkey || "main").slice(0, 32);
        const v = parseInt(b.v, 10) === 2 ? 2 : 1;
        const wkey_pin = typeof b.wkey_pin === "string" ? b.wkey_pin.slice(0, 2000) : null;
        const wkey_pwd = typeof b.wkey_pwd === "string" ? b.wkey_pwd.slice(0, 2000) : null;
        if (!token || !blob || blob.length > 500000)
          return json({ error: "bad request" }, 400);
        if ((wkey_pin && wkey_pin.length > 2000) || (wkey_pwd && wkey_pwd.length > 2000))
          return json({ error: "bad request" }, 400);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        const key = "auth:vault:" + sess.uid + ":" + vkey;
        const existing = await kv.get(key, "json");
        if (existing && existing.updated_at > updatedAt)
          return json({ ok: false, conflict: true, server_updated_at: existing.updated_at }, 409);
        const rec = { blob, updated_at: updatedAt, v };
        if (wkey_pin) rec.wkey_pin = wkey_pin;
        if (wkey_pwd) rec.wkey_pwd = wkey_pwd;
        await kv.put(key, JSON.stringify(rec));
        return json({ ok: true, updated_at: updatedAt });
      }

      // Authenticated vault delete: wipe cloud vault (for PIN reset)
      if (p === "/api/auth/vault/delete" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        const vkey = String(b.vkey || "main").slice(0, 32);
        if (!token) return json({ error: "no token" }, 401);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        await kv.delete("auth:vault:" + sess.uid + ":" + vkey);
        return json({ ok: true });
      }
      // Authenticated vault load: download vault by session (cloud-only storage)
      // Returns v2 wrapped fields (wkey_pin, wkey_pwd) when present — all opaque to server.
      if (p === "/api/auth/vault/load" && req.method === "GET") {
        const token = String(url.searchParams.get("token") || "").slice(0, 64);
        const vkey = String(url.searchParams.get("vkey") || "main").slice(0, 32);
        if (!token) return json({ error: "no token" }, 401);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        const v = await kv.get("auth:vault:" + sess.uid + ":" + vkey, "json");
        if (!v) return json({ error: "not found" }, 404);
        const out = { ok: true, blob: v.blob, updated_at: v.updated_at, v: v.v || 1 };
        if (v.wkey_pin) out.wkey_pin = v.wkey_pin;
        if (v.wkey_pwd) out.wkey_pwd = v.wkey_pwd;
        return json(out);
      }

      /* ---------------- password recovery (2026-10-15) ----------------
       * Forgot password: 6-digit code emailed to the account address.
       * - Codes are SHA256-hashed before KV storage, 15-min TTL, single-use.
       * - Rate limit: 5 codes per email per hour.
       * - Generic {ok:true} on forgot-password to avoid user enumeration.
       * - Requires RESEND_API_KEY in worker env to actually send email.
       * ------------------------------------------------------------------------ */
      // Step 1: request a reset code
      if (p === "/api/auth/forgot-password" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        // Always return ok:true — never reveal whether the email has an account.
        if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) return json({ ok: true });
        const eh = await sha256hex("auth:" + email);
        const userRec = await kv.get("auth:user:" + eh, "json");
        if (!userRec) return json({ ok: true });
        // Rate limit: 5 codes per email per hour (silent — still returns ok:true)
        const rlKey = "auth:pwreset:rl:" + eh;
        let rl = await kv.get(rlKey, "json");
        const now = Date.now();
        if (!rl || now > rl.reset) rl = { count: 0, reset: now + 3600000 };
        if (rl.count >= 5) return json({ ok: true });
        rl.count++;
        await kv.put(rlKey, JSON.stringify(rl), { expirationTtl: 3600 });
        // Cryptographically random 6-digit code
        const rb = crypto.getRandomValues(new Uint8Array(4));
        const code = String((new DataView(rb.buffer).getUint32(0) % 900000) + 100000);
        const codeHash = await sha256hex("pwreset:" + eh + ":" + code);
        await kv.put("auth:pwreset:" + eh, JSON.stringify({ h: codeHash }), { expirationTtl: 900 });
        // Fire-and-forget email (never blocks, never leaks failure to client)
        sendResetEmail(env, email, code).catch(() => {});
        return json({ ok: true });
      }

      // Step 2: verify code + set new password
      if (p === "/api/auth/reset-password" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").toLowerCase().trim();
        const code = String(b.code || "").replace(/\\D/g, "").slice(0, 6);
        const newPassword = String(b.newPassword || "");
        if (newPassword.length < 6)
          return json({ ok: false, error: "password_min_6" }, 400);
        if (code.length !== 6)
          return json({ ok: false, error: "invalid_code" }, 400);
        const eh = await sha256hex("auth:" + email);
        const stored = await kv.get("auth:pwreset:" + eh, "json");
        // Generic error — don't reveal whether a code was ever issued
        if (!stored || !stored.h)
          return json({ ok: false, error: "invalid_code" }, 400);
        const codeHash = await sha256hex("pwreset:" + eh + ":" + code);
        if (!timingSafeEqual(codeHash, stored.h))
          return json({ ok: false, error: "invalid_code" }, 400);
        const userRec = await kv.get("auth:user:" + eh, "json");
        if (!userRec)
          return json({ ok: false, error: "invalid_code" }, 400);
        // Code valid: update password, then single-use invalidate the code
        const salt = genId(32);
        userRec.pwd_hash = await hashPassword(newPassword, salt);
        userRec.salt = salt;
        await kv.put("auth:user:" + eh, JSON.stringify(userRec));
        await kv.delete("auth:pwreset:" + eh);
        return json({ ok: true });
      }

      /* ---------------- invites ---------------- */
      if (p === "/api/invite/register" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const code = String(b.code || "").toUpperCase().slice(0, 16);
        const deviceId = String(b.deviceId || "").slice(0, 64);
        const syncId = String(b.syncId || "").toUpperCase().slice(0, 16);
        const invitedBy = String(b.invitedBy || "").toUpperCase().slice(0, 16);
        const token = String(b.token || "").slice(0, 64);
        if (!/^[A-Z2-9]{4,16}$/.test(code) || !deviceId)
          return json({ error: "bad request" }, 400);
        // TIE TO ACCOUNT: if session token provided, link code to auth UID
        let uid = "";
        if (token) {
          const sess = await kv.get("auth:session:" + token, "json");
          if (sess && sess.expires > Date.now()) uid = sess.uid;
        }
        const ck = "invite:code:" + code;
        const existing = await kv.get(ck, "json");
        if (!existing) {
          // New user record — never deleted, only status changes (audit trail)
          const rec = { code, deviceId, syncId: (/^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId)?syncId:""),
            invitedBy: (/^[A-Z2-9]{4,16}$/.test(invitedBy)?invitedBy:""),
            uid: uid,
            created_at: new Date().toISOString(), status: "active" };
          await kv.put(ck, JSON.stringify(rec));
          // Also index by syncId so the code follows the user across browsers
          if (rec.syncId) await kv.put("invite:sync:" + rec.syncId, code);
          // Index by UID so the code follows the account across devices (cloud-only)
          if (uid) await kv.put("invite:uid:" + uid, code);
          // Bump user counter
          const uc = parseInt((await kv.get("users:count")) || "0", 10) || 0;
          await kv.put("users:count", String(uc + 1));
          // Track invite relationship
          if (rec.invitedBy) {
            const ik = "invite:children:" + rec.invitedBy;
            let ch = [];
            try { ch = (await kv.get(ik, "json")) || []; } catch (e) {}
            if (!ch.includes(code)) { ch.push(code); await kv.put(ik, JSON.stringify(ch)); }
          }
        } else if (syncId && /^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId) && !existing.syncId) {
          // Existing user enabling sync — link their code to the sync ID
          existing.syncId = syncId;
          await kv.put(ck, JSON.stringify(existing));
          await kv.put("invite:sync:" + syncId, code);
        }
        // TIE TO ACCOUNT: link existing code to UID if not already linked
        if (uid && existing && !existing.uid) {
          existing.uid = uid;
          await kv.put(ck, JSON.stringify(existing));
          await kv.put("invite:uid:" + uid, code);
        }
        return json({ ok: true, code });
      }

      /* Get the invite code for an account (cloud-only: by session token) */
      if (p === "/api/invite/my-code" && req.method === "GET") {
        const token = String(url.searchParams.get("token") || "").slice(0, 64);
        if (!token) return json({ code: null });
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now()) return json({ code: null });
        const code = await kv.get("invite:uid:" + sess.uid);
        return json({ code: code || null });
      }

      /* Get the invite code for a Sync ID (so it's consistent across browsers) */
      if (p === "/api/invite/code-for-sync" && req.method === "GET") {
        const syncId = String(url.searchParams.get("sync_id") || "").toUpperCase().slice(0, 16);
        if (!/^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId))
          return json({ error: "bad sync_id" }, 400);
        const code = await kv.get("invite:sync:" + syncId);
        return json({ code: code || null });
      }

      /* Delete account — invalidates the invite code but preserves the record */
      if (p === "/api/account/delete" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const code = String(b.code || "").toUpperCase().slice(0, 16);
        const deviceId = String(b.deviceId || "").slice(0, 64);
        if (!code || !deviceId) return json({ error: "bad request" }, 400);
        const ck = "invite:code:" + code;
        const rec = await kv.get(ck, "json");
        // Only the owning device can delete
        if (!rec || rec.deviceId !== deviceId)
          return json({ error: "not found" }, 404);
        rec.status = "deleted";
        rec.deleted_at = new Date().toISOString();
        await kv.put(ck, JSON.stringify(rec));
        // Remove sync mapping so the code can't be re-linked
        if (rec.syncId) await kv.delete("invite:sync:" + rec.syncId);
        return json({ ok: true });
      }

      if (p === "/api/invite/claim" && req.method === "POST") {
        const flags = await getFlags(env);
        if (!flags.invites) return json({ ok: false, error: "invites_disabled" });
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const inviterCode = String(b.inviterCode || "").toUpperCase().slice(0, 16);
        const deviceId = String(b.deviceId || "").slice(0, 64);
        if (!inviterCode || !deviceId)
          return json({ ok: false, error: "bad request" });
        if (await kv.get("invite:claimed:" + deviceId))
          return json({ ok: false, error: "already_claimed" });
        const inviterRec = await kv.get("invite:code:" + inviterCode, "json");
        const ownerDevice = inviterRec ? inviterRec.deviceId : await kv.get("invite:code:" + inviterCode);
        if (!inviterRec && !ownerDevice)
          return json({ ok: false, error: "invalid_code" });
        if (inviterRec && inviterRec.status === "deleted")
          return json({ ok: false, error: "code_invalid_account_deleted" });
        if (ownerDevice && ownerDevice === deviceId)
          return json({ ok: false, error: "self_invite" });
        await kv.put("invite:claimed:" + deviceId, inviterCode);
        const pk = "invite:pending:" + inviterCode;
        const cur = parseInt((await kv.get(pk)) || "0", 10) || 0;
        await kv.put(pk, String(cur + 100));
        return json({ ok: true, bonus: 100 });
      }

      if (p === "/api/invite/pending" && req.method === "GET") {
        const code = String(url.searchParams.get("code") || "")
          .toUpperCase()
          .slice(0, 16);
        if (!code) return json({ pending: 0 });
        const pk = "invite:pending:" + code;
        const cur = parseInt((await kv.get(pk)) || "0", 10) || 0;
        if (cur > 0) await kv.put(pk, "0");
        return json({ pending: cur });
      }

      /* ---------------- owner grant ---------------- */
      if (p === "/api/grant" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        if (!(await ownerTokenValid(req, kv)) && b.key !== env.OWNER_KEY) return json({ error: "forbidden" }, 403);
        const code = String(b.code || "").toUpperCase().slice(0, 16);
        const amount = Math.max(1, Math.min(10000, parseInt(b.amount, 10) || 0));
        if (!code || !amount) return json({ error: "bad request" }, 400);
        const pk = "invite:pending:" + code;
        const cur = parseInt((await kv.get(pk)) || "0", 10) || 0;
        await kv.put(pk, String(cur + amount));
        return json({ ok: true, granted: amount, code });
      }

      /* ---------------- Stripe: buy shares ---------------- */
      if (p === "/api/checkout/shares" && req.method === "POST") {
        const flags = await getFlags(env);
        if (!flags.buyShares)
          return json({ error: "Share purchases are not enabled" }, 403);
        if (!env.STRIPE_SECRET_KEY)
          return json({ error: "Payments not configured yet" }, 503);
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const deviceCode =
          String(b.deviceCode || "").toUpperCase().slice(0, 16) || "unknown";
        const publicUrl = (
          env.PUBLIC_URL || "https://omni-tap.com/"
        ).replace(/\/$/, "") + "/";
        const params = new URLSearchParams({
          mode: "payment",
          success_url: publicUrl + "?purchase=ok&session_id={CHECKOUT_SESSION_ID}",
          cancel_url: publicUrl,
          "line_items[0][price_data][currency]": "usd",
          "line_items[0][price_data][product_data][name]":
            "OMNI share credits — 100 shares",
          "line_items[0][price_data][unit_amount]": "399",
          "line_items[0][quantity]": "1",
          "metadata[deviceCode]": deviceCode,
          "metadata[shares]": "100",
        });
        const sr = await fetch("https://api.stripe.com/v1/checkout/sessions", {
          method: "POST",
          headers: {
            Authorization: "Bearer " + env.STRIPE_SECRET_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });
        const sj = await sr.json();
        if (!sr.ok || !sj.url)
          return json({ error: (sj.error && sj.error.message) || "Stripe error" }, 502);
        return json({ url: sj.url });
      }

      if (p === "/api/purchase/verify" && req.method === "GET") {
        const sid = String(url.searchParams.get("session_id") || "").slice(0, 128);
        if (!sid || !env.STRIPE_SECRET_KEY) return json({ credited: false });
        if (await kv.get("purchase:credited:" + sid))
          return json({ credited: false, already: true });
        const sr = await fetch(
          "https://api.stripe.com/v1/checkout/sessions/" + encodeURIComponent(sid),
          { headers: { Authorization: "Bearer " + env.STRIPE_SECRET_KEY } }
        );
        const sj = await sr.json();
        if (sr.ok && sj.payment_status === "paid") {
          await kv.put("purchase:credited:" + sid, "1", {
            expirationTtl: 90 * 86400,
          });
          const shares = parseInt((sj.metadata && sj.metadata.shares) || "100", 10) || 100;
          return json({ credited: true, shares });
        }
        return json({ credited: false });
      }



      /* ---------------- owner authentication ----------------
       * Password-based owner login. First use creates the password
       * (one-time setup); afterwards login returns a 30-day token.
       * The token guards /api/flags (POST), /api/grant, /api/stats.
       * -------------------------------------------------------- */
      if (p === "/api/owner/setup" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        if (await kv.get("owner:hash"))
          return json({ error: "owner already set" }, 403);
        const pw = String(b.password || "");
        if (pw.length < 8)
          return json({ error: "password must be 8+ characters" }, 400);
        await kv.put("owner:hash", await sha256hex("omni-owner:" + pw));
        const token = genId(32);
        const curGen = (await kv.get("owner:gen")) || "0";
        await kv.put("owner:token:" + token, curGen, { expirationTtl: 2592000 });
        return json({ ok: true, token });
      }

      if (p === "/api/owner/login" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const hash = await kv.get("owner:hash");
        if (!hash) return json({ ok: false, needSetup: true });
        const pwHash = await sha256hex("omni-owner:" + String(b.password || ""));
        // constant-time-ish compare
        if (pwHash.length !== hash.length || pwHash !== hash)
          return json({ ok: false });
        const token = genId(32);
        const curGen = (await kv.get("owner:gen")) || "0";
        await kv.put("owner:token:" + token, curGen, { expirationTtl: 2592000 });
        return json({ ok: true, token });
      }

      if (p === "/api/owner/status" && req.method === "GET") {
        return json({ hasOwner: !!(await kv.get("owner:hash")) });
      }
      /* Client reports its plan tier (for owner stats) */
      if (p === "/api/plan/report" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        const tier = String(b.tier || "free").toLowerCase().slice(0, 16);
        if (!token || !["free","pro","premium"].includes(tier))
          return json({ error: "bad request" }, 400);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        await kv.put("plan:" + sess.uid, tier);
        return json({ ok: true, tier });
      }
      /* Owner: wipe all accounts except the one tied to keepCode (fresh start) */
      if (p === "/api/admin/wipe-accounts" && req.method === "POST") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const keepCode = String(b.keepCode || "").toUpperCase().slice(0, 16);
        const confirm = String(b.confirm || "");
        if (!keepCode || confirm !== "WIPE-ALL-OTHERS")
          return json({ error: "confirmation required" }, 400);
        // Find the UID tied to keepCode
        const keepRec = await kv.get("invite:code:" + keepCode, "json");
        const keepUid = keepRec && keepRec.uid ? keepRec.uid : null;
        if (!keepUid)
          return json({ error: "keepCode not linked to any account yet — open the app first" }, 400);
        const deleted = [];
        // 1. Delete all auth users except keepUid
        let cursor = undefined;
        const uidsToDelete = [];
        do {
          const res = await kv.list({ prefix: "auth:user:", cursor });
          for (const k of res.keys) {
            const uid = k.name.slice(10); // strip "auth:user:"
            if (uid !== keepUid) uidsToDelete.push(uid);
          }
          cursor = res.cursor;
          if (res.list_complete) break;
        } while (cursor);
        for (const uid of uidsToDelete) {
          const urec = await kv.get("auth:user:" + uid, "json");
          // Delete user record
          await kv.delete("auth:user:" + uid);
          // Delete email index
          if (urec && urec.email) {
            await kv.delete("auth:email:" + urec.email.toLowerCase());
            const digits = String(urec.phone || "").replace(/\D/g, "");
            if (digits) await kv.delete("auth:phone:" + digits);
          }
          // Delete vaults (all vkeys)
          let vcur = undefined;
          do {
            const vres = await kv.list({ prefix: "auth:vault:" + uid + ":", cursor: vcur });
            for (const vk of vres.keys) await kv.delete(vk.name);
            vcur = vres.cursor;
            if (vres.list_complete) break;
          } while (vcur);
          // Delete plan record
          await kv.delete("plan:" + uid);
          // Delete invite uid index
          await kv.delete("invite:uid:" + uid);
          deleted.push(uid);
        }
        // 2. Delete all sessions except keepUid's
        let scur = undefined;
        do {
          const sres = await kv.list({ prefix: "auth:session:", cursor: scur });
          for (const sk of sres.keys) {
            const srec = await kv.get(sk.name, "json");
            if (!srec || srec.uid !== keepUid) await kv.delete(sk.name);
          }
          scur = sres.cursor;
          if (sres.list_complete) break;
        } while (scur);
        // 3. Delete invite codes not tied to keepUid
        let icur = undefined;
        do {
          const ires = await kv.list({ prefix: "invite:code:", cursor: icur });
          for (const ik of ires.keys) {
            const irec = await kv.get(ik.name, "json");
            if (!irec || irec.uid !== keepUid) {
              await kv.delete(ik.name);
              // Also clean pending rewards for deleted codes
              const code = ik.name.slice(12);
              await kv.delete("invite:pending:" + code);
            }
          }
          icur = ires.cursor;
          if (ires.list_complete) break;
        } while (icur);
        return json({ ok: true, keptUid: keepUid, keptCode: keepCode, deletedCount: deleted.length, deleted });
      }
      /* Owner: real-time user stats with plan breakdown */
      if (p === "/api/users/stats" && req.method === "GET") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        const total = parseInt((await kv.get("users:count")) || "0", 10) || 0;
        // Count by plan tier
        const plans = { free: 0, pro: 0, premium: 0 };
        try {
          let cursor = undefined;
          do {
            const res = await kv.list({ prefix: "plan:", cursor });
            for (const k of res.keys) {
              const t = await kv.get(k.name);
              if (t === "pro") plans.pro++;
              else if (t === "premium") plans.premium++;
              else plans.free++;
            }
            cursor = res.cursor;
            if (res.list_complete) break;
          } while (cursor);
        } catch (e) {}
        return json({ total, plans, at: new Date().toISOString() });
      }
      if (p === "/api/owner/change" && req.method === "POST") {
        // Must have a valid owner token (proves current ownership)
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const cur = String(b.current_password || "");
        const nw = String(b.new_password || "");
        // 1. Verify current password against the server hash
        const hash = await kv.get("owner:hash");
        if (!hash) return json({ error: "no owner set" }, 400);
        const curHash = await sha256hex("omni-owner:" + cur);
        if (curHash.length !== hash.length || curHash !== hash)
          return json({ ok: false, error: "current password incorrect" }, 401);
        // 2. Validate and hash the new password
        if (nw.length < 8)
          return json({ ok: false, error: "new password must be 8+ characters" }, 400);
        // 3. Write the new hash to the server record
        await kv.put("owner:hash", await sha256hex("omni-owner:" + nw));
        // 4. Invalidate ALL existing tokens (force re-login everywhere)
        // Note: KV can't list keys, so we bump a generation counter instead
        const gen = (parseInt((await kv.get("owner:gen")) || "0", 10) || 0) + 1;
        await kv.put("owner:gen", String(gen));
        // 5. Issue a fresh token for this session
        const token = genId(32);
        await kv.put("owner:token:" + token, String(gen), { expirationTtl: 2592000 });
        return json({ ok: true, token });
      }


      /* ---------------- lead capture ----------------
       * Recipients of a shared link can send their contact back.
       * Leads are stored per-card; the card owner views them
       * in the dashboard (owner token required).
       * -------------------------------------------------------- */
      if (p === "/api/lead" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const cardId = String(b.card_id || "").slice(0, 32);
        const name = String(b.name || "").slice(0, 100);
        const email = String(b.email || "").slice(0, 100);
        const phone = String(b.phone || "").slice(0, 30);
        const note = String(b.note || "").slice(0, 500);
        if (!cardId || !/^[A-Za-z0-9_-]{1,32}$/.test(cardId))
          return json({ error: "bad card_id" }, 400);
        if (!name && !email && !phone)
          return json({ error: "name, email, or phone required" }, 400);
        // Basic spam guard: simple rate limit per card
        const rk = "lead:ratelimit:" + cardId;
        const rc = parseInt((await kv.get(rk)) || "0", 10) || 0;
        if (rc >= 50) return json({ error: "too many leads" }, 429);
        await kv.put(rk, String(rc + 1), { expirationTtl: 3600 });
        const lid = Date.now().toString(36) + genId(6);
        const lead = { id: lid, card_id: cardId, name, email, phone, note, at: new Date().toISOString() };
        await kv.put("lead:" + cardId + ":" + lid, JSON.stringify(lead), { expirationTtl: 365 * 86400 });
        // Also push to an index list for the card
        const ik = "leads:" + cardId;
        let idx = [];
        try { idx = (await kv.get(ik, "json")) || []; } catch (e) {}
        idx.unshift(lid);
        if (idx.length > 500) idx = idx.slice(0, 500);
        await kv.put(ik, JSON.stringify(idx), { expirationTtl: 365 * 86400 });
        fireWebhook(env, kv, { type: "lead", card_id: cardId, lead }).catch(()=>{});
        return json({ ok: true, id: lid });
      }

      if (p === "/api/leads" && req.method === "GET") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        const cardId = String(url.searchParams.get("card_id") || "").slice(0, 32);
        let out = [];
        if (cardId) {
          let idx = [];
          try { idx = (await kv.get("leads:" + cardId, "json")) || []; } catch (e) {}
          for (const lid of idx.slice(0, 100)) {
            try { const l = await kv.get("lead:" + cardId + ":" + lid, "json"); if (l) out.push(l); } catch (e) {}
          }
        }
        return json({ leads: out });
      }

      /* ---------------- outbound webhooks (Zapier-ready) ---------------- */
      if (p === "/api/webhook" && req.method === "POST") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const whUrl = String(b.url || "").slice(0, 500);
        if (whUrl && !/^https:\/\/[^\s]+$/.test(whUrl))
          return json({ error: "must be an https URL" }, 400);
        if (whUrl) await kv.put("webhook:url", whUrl);
        else await kv.delete("webhook:url");
        return json({ ok: true, url: whUrl || null });
      }
      if (p === "/api/webhook" && req.method === "GET") {
        if (!(await ownerTokenValid(req, kv))) return json({ error: "forbidden" }, 403);
        return json({ url: (await kv.get("webhook:url")) || null });
      }

      /* ---------------- encrypted vault sync ----------------
       * Zero-knowledge: the server only stores the AES-GCM ciphertext
       * blob that the app already keeps in localStorage (omni_vault).
       * The sync_id is a capability key (OMNI-XXXX-XXXX). Anyone with
       * the sync_id can download the blob, but only the PIN decrypts it.
       * -------------------------------------------------------- */
      if (p === "/api/vault/save" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const syncId = String(b.sync_id || "").toUpperCase().slice(0, 16);
        const blob = String(b.blob || "");
        const updatedAt = parseInt(b.updated_at, 10) || Date.now();
        if (!/^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId))
          return json({ error: "bad sync_id" }, 400);
        if (!blob || blob.length > 500000)
          return json({ error: "bad blob" }, 400);
        const key = "vault:" + syncId;
        const existing = await kv.get(key, "json");
        // last-write-wins: reject stale writes
        if (existing && existing.updated_at > updatedAt)
          return json({ ok: false, conflict: true, server_updated_at: existing.updated_at }, 409);
        await kv.put(key, JSON.stringify({ blob, updated_at: updatedAt }));
        return json({ ok: true, updated_at: updatedAt });
      }

      if (p === "/api/vault/load" && req.method === "GET") {
        const syncId = String(url.searchParams.get("sync_id") || "").toUpperCase().slice(0, 16);
        if (!/^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId))
          return json({ error: "bad sync_id" }, 400);
        const v = await kv.get("vault:" + syncId, "json");
        if (!v) return json({ error: "not found" }, 404);
        return json({ ok: true, blob: v.blob, updated_at: v.updated_at });
      }

      if (p === "/api/vault/delete" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const syncId = String(b.sync_id || "").toUpperCase().slice(0, 16);
        if (!/^OMNI-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(syncId))
          return json({ error: "bad sync_id" }, 400);
        await kv.delete("vault:" + syncId);
        return json({ ok: true });
      }

      /* ============ SUBSCRIPTIONS & PAYMENTS (2026-10-11) ============ */
      if (p === "/api/checkout/subscription" && req.method === "POST") {
        const {tier, deviceCode, syncId} = await req.json().catch(()=>({}));
        if (!["pro","premium"].includes(tier)) return json({error:"Invalid tier"},400);
        if (!syncId) return json({error:"Sync ID required"},400);
        const priceId = tier==="pro" ? env.STRIPE_PRO_PRICE_ID : env.STRIPE_PREMIUM_PRICE_ID;
        if (!priceId) return json({error:"Price not configured"},500);
        const params = new URLSearchParams({
          "mode":"subscription","line_items[0][price]":priceId,"line_items[0][quantity]":"1",
          "success_url":"https://omni-tap.com/?sub=ok","cancel_url":"https://omni-tap.com/?sub=cancelled",
          "metadata[tier]":tier,"metadata[syncId]":syncId,"metadata[deviceCode]":deviceCode||"",
        });
        const sr = await fetch("https://api.stripe.com/v1/checkout/sessions",{method:"POST",
          headers:{"Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`,"Content-Type":"application/x-www-form-urlencoded"},body:params.toString()});
        const sj = await sr.json();
        if (!sr.ok) return json({error:sj.error?.message||"Stripe error"},500);
        return json({url:sj.url});
      }
      if (p === "/api/checkout/tokens" && req.method === "POST") {
        const {pack, syncId} = await req.json().catch(()=>({}));
        const packs=[{t:1700,e:"STRIPE_TOKENS_1700_PRICE_ID"},{t:3500,e:"STRIPE_TOKENS_3500_PRICE_ID"},{t:9000,e:"STRIPE_TOKENS_9000_PRICE_ID"}];
        if (pack<0||pack>2||!syncId) return json({error:"Invalid request"},400);
        const priceId=env[packs[pack].e];
        if (!priceId) return json({error:"Price not configured"},500);
        const params=new URLSearchParams({
          "mode":"payment","line_items[0][price]":priceId,"line_items[0][quantity]":"1",
          "success_url":"https://omni-tap.com/?tokens=ok","cancel_url":"https://omni-tap.com/?tokens=cancelled",
          "metadata[syncId]":syncId,"metadata[tokens]":String(packs[pack].t),
        });
        const sr=await fetch("https://api.stripe.com/v1/checkout/sessions",{method:"POST",
          headers:{"Authorization":`Bearer ${env.STRIPE_SECRET_KEY}`,"Content-Type":"application/x-www-form-urlencoded"},body:params.toString()});
        const sj=await sr.json();
        if(!sr.ok) return json({error:sj.error?.message||"Stripe error"},500);
        return json({url:sj.url});
      }
      if (p === "/api/stripe/webhook" && req.method === "POST") {
        const sig=req.headers.get("stripe-signature");
        if(!sig) return json({error:"No signature"},400);
        const event=await req.json().catch(()=>null);
        if(!event) return json({error:"Invalid JSON"},400);
        if(event.type==="checkout.session.completed"){
          const s=event.data.object, md=s.metadata||{};
          if(md.tier&&md.syncId){
            await kv.put(`sub:${md.syncId}`,JSON.stringify({tier:md.tier,status:"active",
              stripeSubId:s.subscription,stripeCustomerId:s.customer,
              currentPeriodEnd:Date.now()+30*86400000,updatedAt:Date.now()}));
          }else if(md.tokens&&md.syncId){
            const k=`tokens:${md.syncId}`,cur=parseInt(await kv.get(k)||"0");
            await kv.put(k,String(cur+parseInt(md.tokens)));
          }
        }
        return json({received:true});
      }
      if (p === "/api/subscription/status" && req.method === "GET") {
        const syncId=url.searchParams.get("syncId");
        if(!syncId) return json({error:"Sync ID required"},400);
        const tokens=parseInt(await kv.get(`tokens:${syncId}`)||"0");
        const subData=await kv.get(`sub:${syncId}`);
        if(!subData){
          const trialData=await kv.get(`trial:${syncId}`);
          let trial=null;
          if(trialData){const t=JSON.parse(trialData);
            const dl=Math.max(0,7-Math.floor((Date.now()-t.startedAt)/86400000));
            trial={active:dl>0,daysLeft:dl};}
          return json({tier:"free",status:"none",tokens,trial});
        }
        const sub=JSON.parse(subData);
        if(sub.currentPeriodEnd&&Date.now()>sub.currentPeriodEnd&&sub.status==="active")sub.status="expired";
        return json({...sub,tokens});
      }
      if (p === "/api/trial/start" && req.method === "POST") {
        const {syncId}=await req.json().catch(()=>({}));
        if(!syncId) return json({error:"Sync ID required"},400);
        if(await kv.get(`trial:${syncId}`)) return json({error:"Trial already used"},400);
        const sub=await kv.get(`sub:${syncId}`);
        if(sub&&JSON.parse(sub).status==="active") return json({error:"Already subscribed"},400);
        await kv.put(`trial:${syncId}`,JSON.stringify({startedAt:Date.now()}));
        return json({started:true,daysLeft:7});
      }
      if (p === "/api/referral/redeem" && req.method === "POST") {
        const {code,syncId,deviceId}=await req.json().catch(()=>({}));
        if(!code||!syncId) return json({error:"Code and Sync ID required"},400);
        if(await kv.get(`redeemed:${syncId}`)) return json({error:"Already redeemed a code"},400);
        const inviterData=await kv.get(`invite:${code}`);
        if(!inviterData) return json({error:"Invalid code"},400);
        const inviter=JSON.parse(inviterData);
        if(inviter.syncId===syncId) return json({error:"Cannot use your own code"},400);
        const today=dayStr(),rk=`ratelimit:${deviceId}:${today}`;
        const cnt=parseInt(await kv.get(rk)||"0");
        if(cnt>=5) return json({error:"Too many attempts today"},429);
        await kv.put(rk,String(cnt+1),{expirationTtl:86400});
        await kv.put(`redeemed:${syncId}`,JSON.stringify({code,at:Date.now()}));
        const ic=parseInt(await kv.get(`invites:${inviter.syncId}`)||"0");
        await kv.put(`invites:${inviter.syncId}`,String(ic+1));
        let reward;
        if(ic===0){reward={type:"cards",amount:7};}
        else{const tk=parseInt(await kv.get(`tokens:${inviter.syncId}`)||"0");
          await kv.put(`tokens:${inviter.syncId}`,String(tk+100));reward={type:"tokens",amount:100};}
        return json({success:true,reward});
      }
      /* ============ NATIVE IAP VERIFICATION ============ */
      if (p === "/api/iap/verify" && req.method === "POST") {
        const {platform, productId, receipt, transactionId, syncId, tier, tokens, restore} = await req.json().catch(()=>({}));
        if(!productId||!syncId) return json({error:"Missing fields"},400);
        if(transactionId){
          const seen=await kv.get(`iap_txn:${transactionId}`);
          if(seen&&!restore) return json({ok:true,duplicate:true});
        }
        // NOTE: Verify receipt with Apple/Google servers in production
        if(tier&&["pro","premium"].includes(tier)){
          await kv.put(`sub:${syncId}`,JSON.stringify({tier,status:"active",platform,productId,transactionId,
            currentPeriodEnd:Date.now()+30*86400000,updatedAt:Date.now()}));
        }else if(tokens){
          const k=`tokens:${syncId}`,cur=parseInt(await kv.get(k)||"0");
          await kv.put(k,String(cur+parseInt(tokens)));
        }
        if(transactionId) await kv.put(`iap_txn:${transactionId}`,JSON.stringify({syncId,at:Date.now()}),{expirationTtl:90*86400});
        return json({ok:true});
      }


      /* ============ APPLE WALLET PASS (.pkpass) ============
       * POST /api/wallet/pass  { token, card }
       * Authenticated: verifies the session token, then builds a signed
       * .pkpass for the caller's own card data (decrypted client-side;
       * the server never sees the vault key). Returns the .pkpass file.
       * Requires secrets: PASS_KEY_PEM, PASS_CERT_PEM, WWDR_CERT_PEM.
       * ======================================================= */
      if (p === "/api/wallet/pass" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        const cardIn = (b.card && typeof b.card === "object") ? b.card : null;
        if (!token || !cardIn) return json({ error: "bad request" }, 400);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "unauthorized" }, 401);
        if (!env.PASS_KEY_PEM || !env.PASS_CERT_PEM || !env.WWDR_CERT_PEM)
          return json({ error: "wallet not configured" }, 503);
        try {
          const card = pkSanitizeCard(cardIn);
          const images = pkLoadPassImages();
          const pkpass = await buildPkpass(card, images, {
            keyPem: env.PASS_KEY_PEM,
            certPem: env.PASS_CERT_PEM,
            wwdrPem: env.WWDR_CERT_PEM,
          });
          return new Response(pkpass, {
            headers: {
              "Content-Type": "application/vnd.apple.pkpass",
              "Content-Disposition": 'attachment; filename="omni-card.pkpass"',
              ...CORS,
            },
          });
        } catch (e) {
          return json({ error: "pass generation failed" }, 500);
        }
      }
      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: "server error" }, 500);
    }
  },
};
