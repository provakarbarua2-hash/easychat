'use strict';

/* =====================================================================
 * Easy Chat — পুশ নোটিফিকেশন পাঠানোর Netlify Function
 * ঠিকানা:  /.netlify/functions/push
 *
 * POST  { idToken, chatId, kind: 'message' | 'call', senderName, chatName, body, callType }
 *   1. কলারের Firebase ID token যাচাই করে (Google-এর পাবলিক কী দিয়ে, এখানেই)
 *   2. কলার ওই চ্যাটের সদস্য কিনা Realtime Database থেকে দেখে
 *   3. বাকি সদস্যদের সেভ করা ডিভাইস-টোকেনে FCM (HTTP v1) দিয়ে পুশ পাঠায়
 *   4. মরে যাওয়া (UNREGISTERED) টোকেন ডাটাবেস থেকে মুছে দেয়
 * GET   স্বাস্থ্য পরীক্ষা — কী ঠিক আছে / কোথায় সমস্যা, JSON-এ দেখায়
 *
 * Netlify-তে মাত্র একটি Environment variable লাগে:
 *   FIREBASE_SERVICE_ACCOUNT = Firebase থেকে নামানো service-account JSON ফাইলের পুরো লেখা
 * কোনো npm প্যাকেজ লাগে না (Node 18+)।
 * ===================================================================== */

const crypto = require('crypto');

const DEFAULT_PROJECT_ID = 'easychat-2856c';
const DEFAULT_DATABASE_URL = 'https://easychat-2856c-default-rtdb.firebaseio.com';
const DB_ROOT = 'easychat';
const OAUTH_URL = 'https://oauth2.googleapis.com/token';
const CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const OAUTH_SCOPE = [
  'https://www.googleapis.com/auth/firebase.messaging',
  'https://www.googleapis.com/auth/firebase.database',
  'https://www.googleapis.com/auth/userinfo.email'
].join(' ');
const MAX_TARGETS = 40;
const CALL_TTL_SECONDS = 45;        // কল-ইনভাইট ৪৫ সেকেন্ডের বেশি পুরোনো হলে অ্যাপ নিজেই বাদ দেয়
const MESSAGE_TTL_SECONDS = 172800; // ফোন বন্ধ থাকলে ২ দিন পর্যন্ত জমা থাকবে

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code || 'error';
  }
}

/* ---------------------------- ছোট হেল্পার ---------------------------- */

function json(status, obj) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    body: JSON.stringify(obj)
  };
}

function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function clip(value, max) {
  const s = String(value == null ? '' : value).replace(/\s+/g, ' ').trim();
  const chars = Array.from(s);
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : s;
}

// অ্যাপের কোডের সাথে হুবহু এক নিয়ম: ইমেইল -> ডাটাবেস কী
function emailKey(email) {
  return String(email).toLowerCase().replace(/[.#$\[\]\/]/g, ',');
}

/* ------------------------- সার্ভিস অ্যাকাউন্ট ------------------------- */

let saCache = { raw: null, value: null };

function parseServiceAccount(rawValue) {
  let text = String(rawValue || '').trim();
  if (!text) return null;
  if (text[0] !== '{') { // পুরো JSON ফাইলের base64 দিলেও চলবে
    const decoded = Buffer.from(text, 'base64').toString('utf8').trim();
    if (decoded[0] === '{') text = decoded;
  }
  try { return JSON.parse(text); } catch (e) { /* নিচে ঢিলেঢালা পদ্ধতি */ }
  // পেস্ট করার সময় লাইন ভেঙে গেলেও দরকারি তিনটা ঘর তুলে নেওয়া
  const pick = function (key) {
    const m = new RegExp('"' + key + '"\\s*:\\s*"([^"]*)"').exec(text);
    return m ? m[1] : undefined;
  };
  return { client_email: pick('client_email'), private_key: pick('private_key'), project_id: pick('project_id') };
}

function getServiceAccount() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw || !raw.trim()) {
    throw new HttpError(500, 'FIREBASE_SERVICE_ACCOUNT environment variable is missing', 'no_service_account');
  }
  if (saCache.raw === raw) return saCache.value;
  const sa = parseServiceAccount(raw);
  if (!sa || !sa.client_email || !sa.private_key) {
    throw new HttpError(500, 'FIREBASE_SERVICE_ACCOUNT is not a valid service-account key (paste the whole JSON file)', 'bad_service_account');
  }
  sa.private_key = String(sa.private_key).replace(/\\n/g, '\n');
  sa.project_id = String(sa.project_id || process.env.FIREBASE_PROJECT_ID || DEFAULT_PROJECT_ID);
  saCache = { raw: raw, value: sa };
  return sa;
}

let tokenCache = { value: null, exp: 0 };
let tokenInFlight = null;

// একই সময়ে কয়েকটা কাজ টোকেন চাইলেও Google-এ যাবে মাত্র একবার
function getAccessToken() {
  const nowS = Math.floor(Date.now() / 1000);
  if (tokenCache.value && tokenCache.exp - 120 > nowS) return Promise.resolve(tokenCache.value);
  if (!tokenInFlight) {
    tokenInFlight = fetchAccessToken().then(
      function (t) { tokenInFlight = null; return t; },
      function (e) { tokenInFlight = null; throw e; }
    );
  }
  return tokenInFlight;
}

async function fetchAccessToken() {
  const nowS = Math.floor(Date.now() / 1000);
  const sa = getServiceAccount();
  const unsigned =
    b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' +
    b64url(JSON.stringify({ iss: sa.client_email, scope: OAUTH_SCOPE, aud: OAUTH_URL, iat: nowS, exp: nowS + 3600 }));

  let signature;
  try {
    signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(sa.private_key);
  } catch (e) {
    throw new HttpError(500, 'The private_key inside FIREBASE_SERVICE_ACCOUNT is unreadable: ' + e.message, 'bad_private_key');
  }

  const res = await fetch(OAUTH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: unsigned + '.' + b64url(signature)
    }).toString()
  });
  const data = await res.json().catch(function () { return {}; });
  if (!res.ok || !data.access_token) {
    throw new HttpError(500, 'Google rejected the service account: ' + (data.error_description || data.error || res.status), 'oauth_failed');
  }
  tokenCache = { value: data.access_token, exp: nowS + (Number(data.expires_in) || 3600) };
  return tokenCache.value;
}

/* ------------------------ Realtime Database (REST) ------------------------ */

function dbUrl(pathSegments, accessToken, query) {
  const base = (process.env.FIREBASE_DATABASE_URL || DEFAULT_DATABASE_URL).replace(/\/+$/, '');
  const p = [DB_ROOT].concat(pathSegments).map(encodeURIComponent).join('/');
  return base + '/' + p + '.json?access_token=' + encodeURIComponent(accessToken) + (query ? '&' + query : '');
}

async function dbGet(pathSegments) {
  const token = await getAccessToken();
  const res = await fetch(dbUrl(pathSegments, token));
  if (!res.ok) throw new HttpError(502, 'Database read failed (' + res.status + ') at ' + pathSegments.join('/'), 'db_read_failed');
  return res.json();
}

async function dbDelete(pathSegments) {
  const token = await getAccessToken();
  const res = await fetch(dbUrl(pathSegments, token), { method: 'DELETE' });
  return res.ok;
}

/* --------------------------- ID token যাচাই --------------------------- */

let certCache = { certs: null, exp: 0, fetchedAt: 0 };

async function getGoogleCerts(forceRefresh) {
  const now = Date.now();
  const fresh = certCache.certs && now < certCache.exp;
  if (fresh && !(forceRefresh && now - certCache.fetchedAt > 60000)) return certCache.certs;

  const res = await fetch(CERTS_URL);
  if (!res.ok) throw new HttpError(502, 'Could not download Google public keys (' + res.status + ')', 'certs_failed');
  const certs = await res.json();
  const m = /max-age=(\d+)/.exec(res.headers.get('cache-control') || '');
  const ttl = Math.min(m ? Number(m[1]) : 3600, 6 * 3600);
  certCache = { certs: certs, exp: now + ttl * 1000, fetchedAt: now };
  return certs;
}

async function verifyIdToken(idToken, projectId) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new HttpError(401, 'Invalid ID token', 'bad_token');

  let header, payload;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
    payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  } catch (e) {
    throw new HttpError(401, 'Invalid ID token', 'bad_token');
  }
  if (!header || header.alg !== 'RS256' || !header.kid) throw new HttpError(401, 'Invalid ID token header', 'bad_token');

  let certs = await getGoogleCerts(false);
  let pem = certs[header.kid];
  if (!pem) { certs = await getGoogleCerts(true); pem = certs[header.kid]; } // কী ঘুরে গেলে (rotation)
  if (!pem) throw new HttpError(401, 'ID token signed with an unknown key', 'bad_token');

  let valid = false;
  try {
    valid = crypto.createVerify('RSA-SHA256').update(parts[0] + '.' + parts[1]).verify(pem, b64urlDecode(parts[2]));
  } catch (e) { valid = false; }
  if (!valid) throw new HttpError(401, 'ID token signature is invalid', 'bad_token');

  const nowS = Math.floor(Date.now() / 1000);
  const skew = 300;
  if (payload.aud !== projectId || payload.iss !== 'https://securetoken.google.com/' + projectId) {
    throw new HttpError(401, 'ID token belongs to a different Firebase project', 'bad_token');
  }
  if (typeof payload.sub !== 'string' || !payload.sub) throw new HttpError(401, 'ID token has no user', 'bad_token');
  if (!(payload.exp > nowS)) throw new HttpError(401, 'ID token expired — reload the app and try again', 'token_expired');
  if (payload.iat > nowS + skew) throw new HttpError(401, 'ID token issued in the future', 'bad_token');

  return { uid: payload.sub, email: String(payload.email || '').toLowerCase() };
}

/* ----------------------------- FCM পাঠানো ----------------------------- */

function fcmUrl(projectId) {
  return 'https://fcm.googleapis.com/v1/projects/' + encodeURIComponent(projectId) + '/messages:send';
}

async function sendOne(accessToken, projectId, token, data, ttl) {
  const res = await fetch(fcmUrl(projectId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
    body: JSON.stringify({
      message: {
        token: token,
        data: data, // শুধু data — দেখানোর কাজটা firebase-messaging-sw.js করে
        webpush: { headers: { Urgency: 'high', TTL: String(ttl) } }
      }
    })
  });
  if (res.ok) return { ok: true };

  const body = await res.json().catch(function () { return {}; });
  const err = body.error || {};
  const detail = (err.details || []).find(function (d) { return d && d.errorCode; }) || {};
  const code = detail.errorCode || err.status || '';
  const message = err.message || '';
  const dead =
    code === 'UNREGISTERED' ||
    code === 'SENDER_ID_MISMATCH' ||
    (res.status === 400 && /not a valid FCM registration token/i.test(message));
  return { ok: false, dead: dead, status: res.status, code: code, message: message };
}

/* ------------------------------ মূল কাজ ------------------------------ */

function buildNotification(kind, ctx) {
  const isGroup = ctx.isGroup;
  if (kind === 'call') {
    const video = ctx.callType === 'Video';
    return {
      title: (video ? '📹' : '📞') + ' ইনকামিং ' + (video ? 'Video' : 'Audio') + ' কল',
      text: isGroup
        ? ctx.senderName + ' (' + ctx.groupName + ') আপনাকে কল দিচ্ছেন...'
        : ctx.senderName + ' আপনাকে কল দিচ্ছেন...',
      tag: 'easychat-call'
    };
  }
  let msg = clip(ctx.body, 140)
    .replace(/^\[Photo\]$/, '📷 ছবি')
    .replace(/^\[GIF\]$/, 'GIF')
    .replace(/^\[Sticker\]$/, 'স্টিকার');
  if (!msg) msg = 'নতুন মেসেজ';
  return {
    title: isGroup ? ctx.groupName : ctx.senderName,
    text: isGroup ? ctx.senderName + ': ' + msg : msg,
    tag: 'easychat-chat-' + ctx.chatId.slice(0, 80)
  };
}

async function handlePush(event) {
  if (typeof fetch !== 'function') {
    throw new HttpError(500, 'This Node version has no fetch(). Set NODE_VERSION=20 in Netlify environment variables.', 'no_fetch');
  }

  let body;
  try {
    const raw = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString('utf8') : (event.body || '');
    body = JSON.parse(raw || '{}');
  } catch (e) {
    throw new HttpError(400, 'Request body must be JSON', 'bad_json');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'Request body must be a JSON object', 'bad_json');

  const kind = body.kind;
  if (kind !== 'message' && kind !== 'call') throw new HttpError(400, 'kind must be "message" or "call"', 'bad_kind');
  const chatId = String(body.chatId || '');
  if (!/^[A-Za-z0-9_-]{1,500}$/.test(chatId)) throw new HttpError(400, 'Invalid chatId', 'bad_chat');

  const sa = getServiceAccount();
  const caller = await verifyIdToken(body.idToken, sa.project_id);
  if (!caller.email) throw new HttpError(401, 'ID token has no email', 'bad_token');

  const results = await Promise.all([
    dbGet(['chats', chatId, 'participants']),
    dbGet(['chats', chatId, 'muted']),
    dbGet(['chats', chatId, 'type']),
    dbGet(['chats', chatId, 'name']),
    dbGet(['users', caller.uid, 'name'])
  ]);
  const participantsRaw = results[0], mutedRaw = results[1], typeRaw = results[2], nameRaw = results[3], callerNameRaw = results[4];

  const participants = (Array.isArray(participantsRaw) ? participantsRaw : Object.values(participantsRaw || {}))
    .filter(function (e) { return typeof e === 'string' && e; })
    .map(function (e) { return e.toLowerCase(); });
  if (!participants.includes(caller.email)) throw new HttpError(403, 'You are not a member of this chat', 'not_member');

  const recipients = Array.from(new Set(participants.filter(function (e) { return e !== caller.email; })));
  if (!recipients.length) return json(200, { ok: true, sent: 0, failed: 0, removed: 0, note: 'no other members' });

  const muted = mutedRaw && typeof mutedRaw === 'object' ? mutedRaw : {};
  const tokenSets = await Promise.all(recipients.map(function (email) {
    const key = emailKey(email);
    return dbGet(['fcmTokens', key]).then(function (value) { return { key: key, value: value }; });
  }));

  let targets = [];
  tokenSets.forEach(function (set) {
    Object.keys(set.value || {}).forEach(function (tid) {
      const rec = set.value[tid];
      if (!rec || typeof rec.token !== 'string' || rec.token.length < 20) return;
      if (kind === 'message' && rec.uid && muted[rec.uid] === true) return; // মিউট করা চ্যাটে মেসেজ-পুশ নয়, কল যাবে
      targets.push({ key: set.key, tid: tid, token: rec.token });
    });
  });
  targets = targets.slice(0, MAX_TARGETS);
  if (!targets.length) return json(200, { ok: true, sent: 0, failed: 0, removed: 0, note: 'no device tokens' });

  const note = buildNotification(kind, {
    isGroup: typeRaw === 'group',
    senderName: clip(callerNameRaw || body.senderName || caller.email.split('@')[0], 60),
    groupName: clip(nameRaw || body.chatName || 'Group', 60),
    chatId: chatId,
    body: body.body,
    callType: body.callType
  });
  const data = { kind: kind, chatId: chatId, title: note.title, body: note.text, tag: note.tag };
  const ttl = kind === 'call' ? CALL_TTL_SECONDS : MESSAGE_TTL_SECONDS;

  const accessToken = await getAccessToken();
  const sends = await Promise.all(targets.map(function (t) {
    return sendOne(accessToken, sa.project_id, t.token, data, ttl).catch(function (e) {
      return { ok: false, dead: false, status: 0, code: 'NETWORK', message: String(e && e.message || e) };
    });
  }));

  const sent = sends.filter(function (r) { return r.ok; }).length;
  const deadTargets = targets.filter(function (t, i) { return sends[i].dead; });
  const hard = sends.filter(function (r) { return !r.ok && !r.dead; });

  await Promise.all(deadTargets.map(function (t) {
    return dbDelete(['fcmTokens', t.key, t.tid]).catch(function () {});
  }));

  console.log('[push] kind=' + kind + ' recipients=' + recipients.length + ' sent=' + sent + ' removed=' + deadTargets.length + ' failed=' + hard.length);
  if (hard.length) console.error('[push] FCM error: ' + hard[0].status + ' ' + hard[0].code + ' ' + hard[0].message);

  if (sent === 0 && hard.length) {
    throw new HttpError(502, 'FCM rejected the message: ' + hard[0].status + ' ' + hard[0].code + ' ' + hard[0].message, 'fcm_failed');
  }
  return json(200, { ok: true, sent: sent, failed: hard.length, removed: deadTargets.length });
}

/* ------------------------- স্বাস্থ্য পরীক্ষা (GET) ------------------------- */

let healthCache = { at: 0, out: null };

async function health() {
  if (healthCache.out && Date.now() - healthCache.at < 30000) return json(200, healthCache.out);

  const out = {
    ok: false,
    function: 'push',
    node: process.version,
    serviceAccount: 'not checked',
    database: 'not checked',
    fcm: 'not checked'
  };
  try {
    const sa = getServiceAccount();
    out.projectId = sa.project_id;
    const token = await getAccessToken();
    out.serviceAccount = 'ok';

    const dbRes = await fetch(dbUrl([], token, 'shallow=true'));
    out.database = dbRes.ok ? 'ok' : 'error ' + dbRes.status + ' (FIREBASE_DATABASE_URL ঠিক আছে?)';

    const fcmRes = await fetch(fcmUrl(sa.project_id), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ validate_only: true, message: { token: 'easychat-health-check', data: { ping: '1' } } })
    });
    const fcmBody = await fcmRes.json().catch(function () { return {}; });
    const fcmErr = fcmBody.error || {};
    // ভুয়া টোকেন নিয়ে 400 মানে: FCM পর্যন্ত পৌঁছানো গেছে এবং অনুমতি আছে
    out.fcm = (fcmRes.ok || fcmRes.status === 400)
      ? 'ok'
      : 'error ' + fcmRes.status + ': ' + (fcmErr.message || fcmErr.status || '') + ' (Firebase Console → Project settings → Cloud Messaging-এ FCM API (V1) চালু আছে?)';

    out.ok = out.serviceAccount === 'ok' && out.database === 'ok' && out.fcm === 'ok';
  } catch (e) {
    out.serviceAccount = e.message || String(e);
  }
  healthCache = { at: Date.now(), out: out };
  return json(200, out);
}

/* ------------------------------ এন্ট্রি পয়েন্ট ------------------------------ */

exports.handler = async function (event) {
  try {
    if (event.httpMethod === 'GET') return await health();
    if (event.httpMethod !== 'POST') return json(405, { ok: false, error: 'Use POST', code: 'method' });
    return await handlePush(event);
  } catch (err) {
    console.error('[push] ' + (err && err.stack || err));
    if (err instanceof HttpError) return json(err.status, { ok: false, error: err.message, code: err.code });
    return json(500, { ok: false, error: 'Internal error', code: 'internal' });
  }
};
