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
  if (h.length !== expectedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  return diff === 0;
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
      const v = await kv.get("owner:token:" + tok);
      // Token stores the generation; must match current generation
      // (password change bumps generation, invalidating old tokens)
      if(v){
        const gen = (await kv.get("owner:gen")) || "0";
        // Legacy tokens stored "1" — treat as gen 0
        if(v === "1") return gen === "0";
        if(v === gen) return true;
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
      if (p === "/api/auth/vault/save" && req.method === "POST") {
        let b = {};
        try { b = await req.json(); } catch (e) {}
        const token = String(b.token || "").slice(0, 64);
        const blob = String(b.blob || "");
        const updatedAt = parseInt(b.updated_at, 10) || Date.now();
        const vkey = String(b.vkey || "main").slice(0, 32);
        if (!token || !blob || blob.length > 500000)
          return json({ error: "bad request" }, 400);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        const key = "auth:vault:" + sess.uid + ":" + vkey;
        const existing = await kv.get(key, "json");
        if (existing && existing.updated_at > updatedAt)
          return json({ ok: false, conflict: true, server_updated_at: existing.updated_at }, 409);
        await kv.put(key, JSON.stringify({ blob, updated_at: updatedAt }));
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
      if (p === "/api/auth/vault/load" && req.method === "GET") {
        const token = String(url.searchParams.get("token") || "").slice(0, 64);
        const vkey = String(url.searchParams.get("vkey") || "main").slice(0, 32);
        if (!token) return json({ error: "no token" }, 401);
        const sess = await kv.get("auth:session:" + token, "json");
        if (!sess || sess.expires < Date.now())
          return json({ error: "invalid_session" }, 401);
        const v = await kv.get("auth:vault:" + sess.uid + ":" + vkey, "json");
        if (!v) return json({ error: "not found" }, 404);
        return json({ ok: true, blob: v.blob, updated_at: v.updated_at });
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
       * (one-time setup); afterwards login returns a 24h token.
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
        await kv.put("owner:token:" + token, "1", { expirationTtl: 86400 });
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
        await kv.put("owner:token:" + token, "1", { expirationTtl: 86400 });
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
        await kv.put("owner:token:" + token, String(gen), { expirationTtl: 86400 });
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

      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: "server error" }, 500);
    }
  },
};
