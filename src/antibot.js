/**
 * antibot.js — JS port of Qwen-Reverse anti-bot primitives
 * (fingerprint.py + cookies.py + bxua.py) for Cloudflare Workers.
 * Pure JS + WebCrypto. No dependencies.
 */

const UA_TEMPLATE = {
  deviceId: "84985177a19a010dea49",
  sdkVersion: "websdk-2.3.15d",
  initTimestamp: "1765348410850",
  field3: "91",
  field4: "1|15",
  language: "zh-CN",
  timezoneOffset: "-480",
  colorDepth: "16705151|12791",
  screenInfo: "1470|956|283|797|158|0|1470|956|1470|798|0|0",
  field9: "5",
  platform: "MacIntel",
  field11: "10",
  webglRenderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M4, Unspecified Version)|Google Inc. (Apple)",
  field13: "30|30",
  field14: "0",
  field15: "28",
  pluginCount: "5",
  vendor: "Google Inc.",
  field29: "8",
  touchInfo: "-1|0|0|0|0",
  field32: "11",
  field35: "0",
  mode: "P",
};

const CUSTOM_B64 = "DGi0YA7BemWnQjCl4_bR3f8SKIF9tUz/xhr2oEOgPpac=61ZqwTudLkM5vHyNXsVJ";
const HASH_FIELDS = { 16: "split", 17: "full", 18: "full", 31: "full", 34: "full", 36: "full" };

const rand32 = () => Math.floor(Math.random() * 0x100000000);
const hex20 = () => Array.from({ length: 20 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");

export function generateFingerprint() {
  const c = UA_TEMPLATE;
  const deviceId = hex20();
  const now = Date.now();
  const fields = [
    deviceId, c.sdkVersion, c.initTimestamp, c.field3, c.field4, c.language,
    c.timezoneOffset, c.colorDepth, c.screenInfo, c.field9, c.platform, c.field11,
    c.webglRenderer, c.field13, c.field14, c.field15,
    `${c.pluginCount}|${rand32()}`, rand32(), rand32(),
    "1", "0", "1", "0", c.mode, "0", "0", "0", "416",
    c.vendor, c.field29, c.touchInfo, rand32(),
    c.field32, now, rand32(), c.field35, 10 + Math.floor(Math.random() * 91),
  ];
  return fields.join("^");
}

function lzwCompress(data, bits, charFunc) {
  if (data == null) return "";
  const dictionary = new Map();
  const dictToCreate = new Set();
  let enlargeIn = 2, dictSize = 3, numBits = 2;
  const result = [];
  let value = 0, position = 0;
  const emit = (v) => result.push(charFunc(v));
  const pushBits = (code, n) => {
    for (let i = 0; i < n; i++) {
      value = (value << 1) | (code & 1);
      if (position === bits - 1) { position = 0; emit(value); value = 0; }
      else position++;
      code >>= 1;
    }
  };
  const pushRaw8 = (ch) => {
    for (let i = 0; i < numBits; i++) {
      value = value << 1;
      if (position === bits - 1) { position = 0; emit(value); value = 0; }
      else position++;
    }
    let cc = ch.charCodeAt(0) & 0xff;
    for (let i = 0; i < 8; i++) {
      value = (value << 1) | (cc & 1);
      if (position === bits - 1) { position = 0; emit(value); value = 0; }
      else position++;
      cc >>= 1;
    }
  };
  const pushRaw16 = (ch) => {
    let cc = 1;
    for (let i = 0; i < numBits; i++) {
      value = (value << 1) | cc;
      if (position === bits - 1) { position = 0; emit(value); value = 0; }
      else position++;
      cc = 0;
    }
    cc = ch.charCodeAt(0) & 0xffff;
    for (let i = 0; i < 16; i++) {
      value = (value << 1) | (cc & 1);
      if (position === bits - 1) { position = 0; emit(value); value = 0; }
      else position++;
      cc >>= 1;
    }
  };
  let w = "";
  for (const ch of data) {
    if (!dictionary.has(ch)) { dictionary.set(ch, dictSize++); dictToCreate.add(ch); }
    const wc = w + ch;
    if (dictionary.has(wc)) { w = wc; }
    else {
      if (dictToCreate.has(w)) {
        if (w.charCodeAt(0) < 256) pushRaw8(w); else pushRaw16(w);
        enlargeIn--;
        if (enlargeIn === 0) { enlargeIn = 2 ** numBits; numBits++; }
        dictToCreate.delete(w);
      } else {
        pushBits(dictionary.get(w), numBits);
      }
      enlargeIn--;
      if (enlargeIn === 0) { enlargeIn = 2 ** numBits; numBits++; }
      dictionary.set(wc, dictSize++);
      w = ch;
    }
  }
  if (w !== "") {
    if (dictToCreate.has(w)) {
      if (w.charCodeAt(0) < 256) pushRaw8(w); else pushRaw16(w);
      enlargeIn--;
      if (enlargeIn === 0) { enlargeIn = 2 ** numBits; numBits++; }
      dictToCreate.delete(w);
    } else {
      pushBits(dictionary.get(w), numBits);
    }
    enlargeIn--;
    if (enlargeIn === 0) { enlargeIn = 2 ** numBits; numBits++; }
  }
  pushBits(2, numBits);
  while (true) {
    value = value << 1;
    if (position === bits - 1) { emit(value); break; }
    position++;
  }
  return result.join("");
}

const customEncode = (data) => lzwCompress(data, 6, (i) => CUSTOM_B64[i]);

export function generateCookies() {
  const fp = generateFingerprint();
  const fields = fp.split("^");
  const processed = [...fields];
  const now = Date.now();
  for (const [idxStr, typ] of Object.entries(HASH_FIELDS)) {
    const idx = Number(idxStr);
    if (idx >= processed.length) continue;
    if (typ === "split") {
      const parts = String(processed[idx]).split("|");
      if (parts.length === 2) processed[idx] = `${parts[0]}|${rand32()}`;
    } else if (typ === "full") {
      processed[idx] = idx === 36 ? 10 + Math.floor(Math.random() * 91) : rand32();
    }
  }
  if (33 < processed.length) processed[33] = now;
  const raw1 = processed.join("^");
  const raw2 = [processed[0], processed[1], processed[23], 0, "", 0, "", "", 0, 0, 0,
    processed[32], processed[33], 0, 0, 0, 0, 0].join("^");
  return { ssxmod_itna: "1-" + customEncode(raw1), ssxmod_itna2: "1-" + customEncode(raw2) };
}

/* Minimal MD5 (for bx-ua checksum only) */
function md5hex(str) {
  const bytes = new TextEncoder().encode(str);
  const origLen = bytes.length;
  const bitLen = origLen * 8;
  const withOne = origLen + 1;
  const padLen = (64 - ((withOne + 8) % 64)) % 64;
  const total = withOne + padLen + 8;
  const msg = new Uint8Array(total);
  msg.set(bytes); msg[origLen] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(total - 8, bitLen >>> 0, true);
  dv.setUint32(total - 4, Math.floor(bitLen / 4294967296), true);
  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const S = [7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22, 5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20, 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23, 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const M = new Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let [A, B, C, D] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const hex = (x) => [0, 8, 16, 24].map((s) => ((x >>> s) & 0xff).toString(16).padStart(2, "0")).join("");
  return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}

function b64encodeBytes(u8) {
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode(...u8.subarray(i, i + CH));
  return btoa(s);
}

async function sha256Bytes(data) {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? new TextEncoder().encode(data) : data);
  return new Uint8Array(buf);
}

export async function generateBxUa() {
  const fp = generateFingerprint();
  const ts = Date.now();
  const fields = fp.split("^");
  const payload = {
    v: "231", ts, fp,
    d: {
      deviceId: fields[0], sdkVer: fields[1], lang: fields[5], tz: fields[6],
      platform: fields[10], renderer: fields[12], mode: fields[23], vendor: fields[28],
    },
    rnd: 1000 + Math.floor(Math.random() * 9000), seq: 1,
  };
  payload.cs = md5hex(`${fp}${ts}${payload.rnd}`).slice(0, 8);
  const jsonBytes = new TextEncoder().encode(JSON.stringify(payload));
  const seedHash = await sha256Bytes(fp);
  const key = seedHash.slice(0, 16), iv = seedHash.slice(16, 32);
  const padded = new Uint8Array(jsonBytes.length + (16 - (jsonBytes.length % 16)));
  padded.set(jsonBytes);
  padded.fill(16 - (jsonBytes.length % 16), jsonBytes.length);
  const enc = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, await crypto.subtle.importKey("raw", key, "AES-CBC", false, ["encrypt"]), padded);
  return `231!${b64encodeBytes(new Uint8Array(enc))}`;
}

let midToken = null;
let midTokenUses = 0;
let midTokenAt = 0;

async function fetchMidToken() {
  const r = await fetch("https://sg-wum.alibaba.com/w/wu.json", { headers: { "User-Agent": "Mozilla/5.0" } });
  const text = await r.text();
  const m = text.match(/(?:umx\.wu|__fycb)\('([^']+)'\)/);
  if (!m) throw new Error("midtoken extract failed");
  return m[1];
}

/** Full browser-like header set for chat.qwen.ai, incl. anti-bot headers. */
export async function upstreamHeaders(token) {
  const ck = generateCookies();
  const h = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    Origin: "https://chat.qwen.ai",
    Referer: "https://chat.qwen.ai/",
    "Content-Type": "application/json",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "X-Requested-With": "XMLHttpRequest",
    source: "web",
    version: "0.2.84",
    "X-Accel-Buffering": "no",
    Cookie: `ssxmod_itna=${ck.ssxmod_itna};ssxmod_itna2=${ck.ssxmod_itna2}`,
    "bx-v": "2.5.37",
    "x-request-id": crypto.randomUUID(),
    "bx-ua": await generateBxUa(),
  };
  if (token) h.Authorization = `Bearer ${token}`;
  try {
    if (!midToken || midTokenUses >= 100 || Date.now() - midTokenAt > 30 * 60 * 1000) {
      midToken = await fetchMidToken();
      midTokenUses = 0; midTokenAt = Date.now();
    }
    midTokenUses++;
    h["bx-umidtoken"] = midToken;
  } catch { /* proceed without midtoken */ }
  return h;
}
