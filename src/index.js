/**
 * qwen-code-proxy — Cloudflare Worker, OpenAI-compatible gateway for chat.qwen.ai
 * (unofficial; same idea as encryptarun/qwen-api, but self-hosted with your own tokens).
 *
 * Secrets:
 *   QWEN_TOKENS — one or more chat.qwen.ai JWTs, comma or newline separated.
 *                 Requests rotate through them (random order) with automatic
 *                 failover when a token is dead/quota-hit. Spreads the load.
 *   QWEN_TOKEN  — legacy single-token fallback (optional).
 *   PROXY_KEY   — your own API key. When set, ALL private routes require
 *                 `Authorization: Bearer <PROXY_KEY>`.
 *
 * Per-request override: `X-Qwen-Token: <jwt>` uses that token instead of the pool.
 */

import { upstreamHeaders } from "./antibot.js";

const UPSTREAM = "https://chat.qwen.ai";
const AUTH_UPSTREAM = "https://auth.qwen.ai";

/** In-memory cache (per isolate): latest minted access token + latest cookie jar. */
let authCache = { access: "", accessExp: 0, jar: "" };

/** All known session jars: cached freshest-first, then QWEN_AUTH (one jar per line). */
function authJars(env) {
  const out = [];
  const push = (j) => { j = (j || "").trim(); if (j.length > 20 && !out.includes(j)) out.push(j); };
  push(authCache.jar);
  for (const j of String(env.QWEN_AUTH || "").replace(/\\n/g, "\n").split(/[\r\n;|]+/)) push(j);
  return out;
}

/** Mint a fresh access token the same way the Qwen web app does:
 *  GET auth.qwen.ai/api/v2/auths/refresh with the session cookie jar.
 *  Returns {access_token, expires_at, refresh_token?, jar} or null. */
async function mintViaAuth(jar) {
  if (!jar || jar.length < 20) return null;
  const h = await upstreamHeaders(null);
  delete h.Cookie;
  delete h.Authorization;
  const res = await fetch(`${AUTH_UPSTREAM}/api/v2/auths/refresh`, {
    headers: {
      ...h,
      Cookie: jar,
      "x-request-origin": "https://chat.qwen.ai",
      Timezone: new Date().toString(),
      Referer: "https://chat.qwen.ai/",
      Origin: "https://chat.qwen.ai",
    },
  });
  const text = await res.text();
  if (!res.ok || res.status === 401 || res.status === 403) return null;
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  if (j.success === false) return null;
  const d = j.data || {};
  const at = d.access_token || d.token || j.access_token;
  if (typeof at !== "string" || at.length < 20) return null;
  const exp = d.expires_at ?? d.expiresAt ?? d.exp ?? decodeJwtExp(at) ?? null;
  let newJar = jar;
  const nrt = d.refresh_token || d.refreshToken;
  if (typeof nrt === "string" && nrt.length > 20 && !jar.includes(nrt)) {
    newJar = /refresh_token=[^;]*/.test(jar)
      ? jar.replace(/refresh_token=[^;]*/, `refresh_token=${nrt}`)
      : `${jar}; refresh_token=${nrt}`;
  }
  authCache = { access: at, accessExp: exp || 0, jar: newJar };
  return { access_token: at, expires_at: exp, refresh_token: typeof nrt === "string" ? nrt : null, jar: newJar };
}

const TEXT_MODELS = [
  "qwen3.8-max", "qwen3.8-max-preview", "qwen3.8-omni-flash", "qwen3.7-plus", "qwen3.7-max",
  "qwen3.6-plus", "qwen3.6-max-preview", "qwen3.6-27b", "qwen3.5-plus",
  "qwen3.5-omni-plus", "qwen3.5-flash", "qwen3.5-max-2026-03-08",
  "qwen3.5-397b-a17b", "qwen3.5-122b-a10b", "qwen3.5-omni-flash",
  "qwen3-max-2026-01-23", "qwen-plus-2025-07-28", "qwen3-coder-plus",
  "qwen3-vl-plus", "qwen3-omni-flash-2025-12-01",
];

/** model-id -> forced chat_type (specialized endpoints) */
const SPECIAL = {
  "qwen-image": "t2i",
  "qwen-video": "t2v",
  "qwen-deep-research": "deep_research",
  "qwen-web-dev": "web_dev",
  "qwen-full-stack": "web_dev",
  "qwen-slides": "slides",
  "qwen-agent": "agent_mode",
  "qwen-podcast": "aipodcast",
  "qwen-translate": "translate",
};

/** chat_type -> sub_chat_type override (app sends lite for agent mode). */
const SUB_CHAT_TYPE = { agent_mode: "lite" };

/** model-name suffix -> chat_type (mirrors the web app's mode map) */
const SUFFIXES = [
  ["-deep-research", "deep_research"], ["-deepresearch", "deep_research"],
  ["-deep-research-webdev", "deep_research_webdev"],
  ["-deep-thinking", "deep_thinking"],
  ["-full-stack", "web_dev"], ["-fullstack", "web_dev"], ["-web-dev", "web_dev"], ["-webdev", "web_dev"],
  ["-artifacts", "artifacts"], ["-artifact", "artifacts"],
  ["-slides", "slides"], ["-slide", "slides"],
  ["-learn", "learn"], ["-travel", "travel"],
  ["-travel-research", "travel_research"],
  ["-podcast", "aipodcast"],
  ["-translate", "translate"],
  ["-agent", "agent_mode"],
  ["-mcp", "mcp"],
  ["-search", "search"],
  ["-image", "t2i"], ["-t2i", "t2i"],
  ["-video", "t2v"], ["-t2v", "t2v"], ["-i2v", "t2v"],
];

/* ---------------- generic helpers ---------------- */

const cors = () => ({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Qwen-Token",
  "Access-Control-Max-Age": "86400",
});
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...cors() } });
const oerr = (message, code = "server_error", status = 500) =>
  json({ error: { message, type: code, param: null, code } }, status);

function decodeJwtExp(token) {
  try {
    const p = token.split(".");
    if (p.length < 2) return null;
    const payload = JSON.parse(atob(p[1].replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.exp === "number" ? payload.exp : null;
  } catch { return null; }
}
const expInfo = (exp) => exp
  ? { epoch: exp, utc: new Date(exp * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" }
  : null;

function poolTokens(env) {
  const raw = [env.QWEN_TOKENS || "", env.QWEN_TOKEN || ""].join("\n");
  const seen = new Set(), out = [];
  for (const t of raw.split(/[\s,;]+/)) {
    const s = t.trim().replace(/^["']|["']$/g, "");
    if (s.length > 20 && !seen.has(s)) { seen.add(s); out.push(s); }
  }
  return out;
}
const shuffled = (n) => {
  const a = [...Array(n).keys()];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1));[a[i], a[j]] = [a[j], a[i]]; }
  return a;
};

function checkGate(req, env) {
  if (!env.PROXY_KEY) return { bearer: (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "") };
  const b = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (b !== env.PROXY_KEY) return { gateError: true };
  return { bearer: "" };
}

/* ---------------- upstream core ---------------- */

class UpstreamError extends Error {
  constructor(message, httpStatus = 502, retryable = true) { super(message); this.httpStatus = httpStatus; this.retryable = retryable; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Minimum gap between upstream calls (per isolate): bursts trip the WAF. */
let lastUpstreamAt = 0;
async function pace(gapMs = 1200) {
  const wait = lastUpstreamAt + gapMs - Date.now();
  if (wait > 0) await sleep(wait);
  lastUpstreamAt = Date.now();
}

/** Fetch with WAF/429/5xx retries (jittered backoff). HTML bodies mean WAF.
 *  Final WAF failure is non-retryable across sessions (same egress IP). */
async function upstreamFetch(url, opts, retries = 3) {
  const waits = [4000, 10000, 25000];
  for (let i = 0; ; i++) {
    await pace();
    let res;
    try {
      res = await fetch(url, opts);
    } catch (e) {
      if (i >= retries) throw new UpstreamError(`Upstream fetch failed: ${e.message}`, 502, true);
      await sleep(waits[Math.min(i, 2)] + Math.random() * 2000);
      continue;
    }
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("html")) {
      try { if (res.body) await res.body.cancel(); } catch { /* ignore */ }
      if (i >= retries) throw new UpstreamError("Upstream WAF throttled this IP (cools down in a few minutes)", 429, false);
      await sleep(waits[Math.min(i, 2)] + Math.random() * 2000);
      continue;
    }
    if ((res.status === 429 || res.status >= 500) && i < retries) {
      await sleep(waits[Math.min(i, 2)] + Math.random() * 2000);
      continue;
    }
    return res;
  }
}

async function apiNewChat(token, model, chatType, title) {
  const now = Date.now();
  const res = await upstreamFetch(`${UPSTREAM}/api/v2/chats/new`, {
    method: "POST",
    headers: await upstreamHeaders(token),
    body: JSON.stringify({
      title: (title || "worker chat").slice(0, 80),
      models: [model], chat_mode: token ? "normal" : "guest",
      chat_type: chatType, timestamp: now, project_id: "",
    }),
  });
  const text = await res.text();
  if (text.trimStart().startsWith("<"))
    throw new UpstreamError("Upstream WAF throttled this IP (cools down in a few minutes)", 429, false);
  let data;
  try { data = JSON.parse(text); }
  catch { throw new UpstreamError(`Chat init failed (${res.status}): ${text.slice(0, 160)}`, res.status === 401 || res.status === 403 ? 401 : 502, res.status !== 400); }
  if (!res.ok || !(data.success && data.data?.id)) {
    const msg = data?.data?.details || data?.message || text.slice(0, 160);
    const s = res.status === 401 || res.status === 403 ? 401 : res.status === 429 ? 429 : 502;
    throw new UpstreamError(`Chat init: ${msg}`, s, true);
  }
  return data.data.id;
}

function featureConfig(effort) {
  if (!effort || effort === "none")
    return { thinking_enabled: false, output_schema: "phase", thinking_format: "summary", thinking_budget: 81920 };
  const mode = effort === "low" ? "Fast" : "Auto";
  const budget = { low: 40960, medium: 81920, high: 163840 }[effort] ?? 81920;
  return {
    auto_thinking: mode === "Auto", thinking_mode: mode, thinking_enabled: true,
    output_schema: "phase", thinking_format: "summary", research_mode: "normal",
    auto_search: true, thinking_budget: budget,
  };
}

/** Map OpenAI-ish thinking controls -> none|low|medium|high */
function effortOf(body, forResearch) {
  if (body.thinking_mode) {
    const t = String(body.thinking_mode).toLowerCase();
    if (t === "fast") return forResearch ? "none" : "none";
    if (t === "auto") return forResearch ? "none" : "medium";
    if (t === "thinking") return "high";
  }
  const r = body.reasoning_effort ? String(body.reasoning_effort).toLowerCase() : "";
  if (r) {
    if (["none", "minimal"].includes(r)) return "none";
    if (r === "low") return forResearch ? "none" : "low";
    if (r === "medium") return forResearch ? "high" : "medium";
    if (["high", "xhigh", "max"].includes(r)) return "high";
  }
  if (typeof body.enable_thinking === "boolean")
    return body.enable_thinking ? (forResearch ? "high" : "medium") : "none";
  return "none";
}

/** Resolve (baseModel, chatType) from model id + request hints. */
function resolveModel(body) {
  let name = String(body.model || "qwen3.8-max");
  if (/^claude-/i.test(name)) {
    const lower = name.toLowerCase();
    let suffix = "";
    for (const [suf] of SUFFIXES) {
      if (lower.endsWith(suf)) { suffix = name.slice(-suf.length); break; }
    }
    if (!suffix && lower.endsWith("-thinking")) suffix = "-thinking";
    name = "qwen3.8-max" + suffix;
  }
  if (SPECIAL[name]) return { base: TEXT_MODELS.includes(name) ? name : "qwen3.8-max", chatType: SPECIAL[name], requested: name };
  let base = name, chatType = "t2t";
  const lower = name.toLowerCase();
  for (const [suf, ct] of SUFFIXES) {
    if (lower.endsWith(suf)) { base = name.slice(0, -suf.length); chatType = ct; break; }
  }
  if (lower.endsWith("-thinking")) { base = name.slice(0, -9); }
  if (!TEXT_MODELS.includes(base)) {
    // unknown but qwen-ish: pass through, upstream will judge
    if (!/^qwen/i.test(base)) return { error: `Unknown model '${body.model}'. See GET /v1/models` };
  }
  const wantsSearch = body.web_search_options != null ||
    (Array.isArray(body.tools) && body.tools.some((t) => t.type === "web_search"));
  if (wantsSearch && chatType === "t2t") chatType = "search";
  if (base === "qwen-deep-research" || SPECIAL[body.model] === "deep_research") chatType = "deep_research";
  return { base, chatType, requested: String(body.model) };
}

/** File limits mirroring the documented upstream contract.
 *  Images ≤5 × 20MB; audio ≤1 × 2000MB; video ≤1 × 2000MB; documents ≤5 × 20MB.
 *  Agent-mode aggregate: ≤10 files, ≤20MB each (media streams capped lower),
 *  ≤50MB total. Worker reality: single fetch capped at 50MB. */
const FILE_LIMITS = {
  image: { maxCount: 5, maxBytes: 20 * 1024 * 1024 },
  audio: { maxCount: 1, maxBytes: 2000 * 1024 * 1024 },
  video: { maxCount: 1, maxBytes: 2000 * 1024 * 1024 },
  document: { maxCount: 5, maxBytes: 20 * 1024 * 1024 },
};
const AGENT_LIMITS = { maxFiles: 10, maxBytesEach: 20 * 1024 * 1024, maxBytesTotal: 50 * 1024 * 1024 };
const FETCH_CAP = 55 * 1024 * 1024;

function guessKind(mime, name) {
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("audio/")) return "audio";
  if (mime.startsWith("video/")) return "video";
  return "document";
}

function mimeOfSrc(src, fallbackName) {
  if (typeof src === "string" && src.startsWith("data:")) {
    const m = src.slice(5, src.indexOf(",")).split(";")[0];
    if (m && m.includes("/")) return m;
  }
  const nm = (fallbackName || src || "").split("?")[0].toLowerCase();
  if (/\.jpe?g$/.test(nm)) return "image/jpeg";
  if (/\.png$/.test(nm)) return "image/png";
  if (/\.gif$/.test(nm)) return "image/gif";
  if (/\.webp$/.test(nm)) return "image/webp";
  if (/\.mp3$/.test(nm)) return "audio/mpeg";
  if (/\.wav$/.test(nm)) return "audio/wav";
  if (/\.m4a$/.test(nm)) return "audio/mp4";
  if (/\.mp4$/.test(nm)) return "video/mp4";
  if (/\.webm$/.test(nm)) return "video/webm";
  if (/\.pdf$/.test(nm)) return "application/pdf";
  if (/\.docx?$/.test(nm)) return "application/msword";
  if (/\.pptx?$/.test(nm)) return "application/vnd.ms-powerpoint";
  if (/\.txt$/.test(nm)) return "text/plain";
  return "application/octet-stream";
}

/** Build single-string prompt + collect file inputs from OpenAI messages.
 *  Accepts image_url parts (any file type via URL/base64), file parts
 *  ({type:"file", file:{file_data|url|filename}}), and input_audio parts. */
function buildPrompt(messages) {
  const files = [];
  const lines = [];
  for (const m of messages || []) {
    const role = m.role === "assistant" ? "Assistant" : m.role === "system" ? "System" : "User";
    if (typeof m.content === "string") {
      lines.push(messages.length === 1 && m.role === "user" ? m.content : `${role}: ${m.content}`);
    } else if (Array.isArray(m.content)) {
      const texts = [];
      for (const p of m.content) {
        if (p.type === "text" && p.text) texts.push(p.text);
        else if (p.type === "image_url") {
          const u = p.image_url?.url || p.image_url || "";
          if (u) files.push({ src: u, name: "", presumed: "image" });
        } else if (p.type === "file" && p.file) {
          const f = p.file.file_data || p.file.url || p.file.content || "";
          if (f) files.push({ src: f, name: p.file.filename || p.file.name || "", presumed: "" });
        } else if (p.type === "input_audio" && p.input_audio) {
          const a = p.input_audio.data || "";
          if (a) {
            const fmt = (p.input_audio.format || "mp3").toLowerCase();
            const src = a.startsWith("data:") || /^https?:\/\//i.test(a) ? a : `data:audio/${fmt};base64,${a}`;
            files.push({ src, name: `audio.${fmt}`, presumed: "audio" });
          }
        }
      }
      const t = texts.join("\n");
      lines.push(messages.length === 1 && m.role === "user" ? t : `${role}: ${t}`);
    }
  }
  return { text: lines.join("\n\n") || "", files };
}

/** Validate file combination; returns {ok} or {error}. */
function checkCombo(kinds) {
  const count = (k) => kinds.filter((x) => x === k).length;
  for (const k of Object.keys(FILE_LIMITS)) {
    if (count(k) > FILE_LIMITS[k].maxCount)
      return { error: `Too many ${k} files (max ${FILE_LIMITS[k].maxCount})` };
  }
  const has = (k) => count(k) > 0;
  if ((has("image") && has("audio")) || (has("image") && has("video")) || (has("audio") && has("video")))
    return { error: "Invalid combination: media files cannot be mixed (image+audio, image+video, audio+video). Pair media with documents instead." };
  if (kinds.length > AGENT_LIMITS.maxFiles)
    return { error: `Too many files (max ${AGENT_LIMITS.maxFiles})` };
  return { ok: true };
}

function lastText(messages) {
  const b = buildPrompt(messages);
  return b.text;
}

/* ---------------- file upload (OSS STS, port of Qwen-Reverse) ---------------- */

function detectType(head) {
  const h = (i, s) => head.slice(i, i + s.length).every((b, j) => b === s.charCodeAt(j));
  if (head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return [".jpg", "image/jpeg"];
  if (h(0, "\x89PNG")) return [".png", "image/png"];
  if (h(0, "GIF87a") || h(0, "GIF89a")) return [".gif", "image/gif"];
  if (h(0, "RIFF") && h(8, "WEBP")) return [".webp", "image/webp"];
  if (h(0, "%PDF")) return [".pdf", "application/pdf"];
  if (head[0] === 0x1a && head[1] === 0xe2 && head[2] === 0xdf && head[3] === 0xa3) return [".webm", "video/webm"];
  if (h(4, "ftyp")) return [".mp4", "video/mp4"];
  return [".bin", "application/octet-stream"];
}

const hexOf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmacBytes(key, msg) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
}

async function ossPut(sts, bytes, contentType) {
  const bucket = sts.bucketname || "qwen-webui-prod";
  const filePath = sts.file_path || "";
  const dateStr = new Date().toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
  const headers = {
    "Content-Type": contentType,
    "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
    "x-oss-date": dateStr,
    "x-oss-security-token": sts.security_token,
    "x-oss-user-agent": "aliyun-sdk-js/6.23.0 Chrome 132.0.0.0 on Windows 10 64-bit",
  };
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const required = ["content-md5", "content-type", "x-oss-content-sha256", "x-oss-date", "x-oss-security-token", "x-oss-user-agent"].sort();
  const canon = required.filter((n) => n in lower).map((n) => `${n}:${lower[n]}`).join("\n") + "\n";
  const uri = `/${bucket}/${filePath.split("/").map(encodeURIComponent).join("/")}`;
  const canonReq = `PUT\n${uri}\n\n${canon}\n\nUNSIGNED-PAYLOAD`;
  const scope = `${dateStr.split("T")[0]}/ap-southeast-1/oss/aliyun_v4_request`;
  const sts2 = `OSS4-HMAC-SHA256\n${dateStr}\n${scope}\n${hexOf(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonReq)))}`;
  const enc = (s) => new TextEncoder().encode(s);
  const dateKey = await hmacBytes(enc(`aliyun_v4${sts.access_key_secret}`), enc(dateStr.split("T")[0]));
  const regionKey = await hmacBytes(dateKey, enc("ap-southeast-1"));
  const svcKey = await hmacBytes(regionKey, enc("oss"));
  const signKey = await hmacBytes(svcKey, enc("aliyun_v4_request"));
  const sig = hexOf(await hmacBytes(signKey, enc(sts2)));
  headers.authorization = `OSS4-HMAC-SHA256 Credential=${sts.access_key_id}/${scope},Signature=${sig}`;
  const putUrl = String(sts.file_url).split("?")[0];
  const r = await fetch(putUrl, { method: "PUT", headers, body: bytes });
  if (!r.ok) throw new UpstreamError(`OSS upload failed (${r.status})`, 502, true);
}

async function uploadBytes(token, bytes, filename) {
  const head = bytes.slice(0, 12);
  const [ext, mime] = detectType(head);
  const name = filename || `file-${bytes.length}${ext}`;
  const stsRes = await fetch(`${UPSTREAM}/api/v2/files/getstsToken`, {
    method: "POST",
    headers: await upstreamHeaders(token),
    body: JSON.stringify({ filename: name, filesize: bytes.length, filetype: mime }),
  });
  const stsJson = await stsRes.json().catch(() => ({}));
  if (stsJson.success === false || !stsJson.data)
    throw new UpstreamError(`getstsToken: ${JSON.stringify(stsJson).slice(0, 160)}`, stsRes.status === 401 ? 401 : 502, true);
  await ossPut(stsJson.data, bytes, mime);
  const now = Date.now();
  const kind = mime.startsWith("image/") ? ["vision", "image", "image"]
    : mime.startsWith("video/") ? ["video", "video", "video"]
    : mime.startsWith("audio/") ? ["audio", "audio", "audio"]
    : ["document", "file", "file"];
  return {
    type: kind[1],
    file: { created_at: now, data: {}, filename: name, hash: null, id: stsJson.data.file_id, meta: { name, size: bytes.length, content_type: mime }, update_at: now },
    id: stsJson.data.file_id, url: stsJson.data.file_url, name, collection_name: "",
    progress: 0, status: "uploaded", greenNet: "success", size: bytes.length, error: "",
    itemId: crypto.randomUUID(), file_type: mime, showType: kind[2], file_class: kind[0],
    uploadTaskId: crypto.randomUUID(),
  };
}

async function bytesFromInput(input, filename) {
  if (typeof input !== "string" || !input) throw new Error("empty image input");
  if (input.startsWith("data:")) {
    const b64 = input.slice(input.indexOf(",") + 1);
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return { bytes: u8, filename: filename || "upload.bin" };
  }
  if (/^https?:\/\//i.test(input)) {
    const r = await fetch(input);
    if (!r.ok) throw new Error(`download failed (${r.status})`);
    // Bounded read: never buffer more than FETCH_CAP (Worker memory limits).
    const reader = r.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > FETCH_CAP) { try { reader.cancel(); } catch {} throw new Error(`download exceeds ${FETCH_CAP} bytes worker cap`); }
      chunks.push(value);
    }
    const buf = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    const nm = input.split("?")[0].split("/").pop() || filename || "remote.bin";
    return { bytes: buf, filename: nm };
  }
  // raw base64
  const bin = atob(input);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return { bytes: u8, filename: filename || "upload.bin" };
}

/* ---------------- chat turn ---------------- */

async function* sseEvents(res) {
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "", dataBuf = [];
  const parseBlock = function* () {
    if (!dataBuf.length) return;
    const data = dataBuf.join("\n"); dataBuf = [];
    if (data === "[DONE]") return;
    try { yield JSON.parse(data); } catch { /* ignore */ }
  };
  while (true) {
    const { done, value } = await reader.read();
    if (done) { yield* parseBlock(); return; }
    buf += dec.decode(value, { stream: true });
    const lines = buf.split("\n"); buf = lines.pop() || "";
    for (const line of lines) {
      const t = line.trim();
      if (!t) { yield* parseBlock(); continue; }
      if (t.startsWith(":")) continue;
      if (t.startsWith("data:")) dataBuf.push(t.slice(5).trimStart());
    }
  }
}

/** Run one chat turn; yields normalized events. */
async function* runTurn(token, { model, chatType, prompt, files, effort, size }) {
  const chatId = await apiNewChat(token, model, chatType, prompt.slice(0, 60));
  const now = Date.now();
  const subChat = SUB_CHAT_TYPE[chatType] || chatType;
  const msg = {
    fid: crypto.randomUUID(), parentId: null, childrenIds: [],
    role: "user", content: prompt, user_action: "chat", files: files || [],
    timestamp: now, models: [model], chat_type: chatType,
    feature_config: featureConfig(effort),
    extra: { meta: { subChatType: subChat } }, sub_chat_type: subChat,
  };
  const payload = {
    stream: true, version: "2.1", incremental_output: true, chat_id: chatId,
    chat_mode: token ? "normal" : "guest", model, parent_id: null,
    messages: [msg], timestamp: now,
    thinking_mode: effort === "high" ? "Thinking" : effort === "medium" ? "Auto" : "Fast",
  };
  if (size) payload.size = size;
  const res = await upstreamFetch(`${UPSTREAM}/api/v2/chat/completions?chat_id=${encodeURIComponent(chatId)}`, {
    method: "POST", headers: await upstreamHeaders(token), body: JSON.stringify(payload),
  });
  if (!res.ok || !res.body) {
    const t = await res.text().catch(() => "");
    const s = res.status === 401 || res.status === 403 ? 401 : res.status === 429 ? 429 : 502;
    throw new UpstreamError(`Upstream ${res.status}: ${t.slice(0, 160)}`, s, res.status !== 400);
  }
  // Upstream must answer with SSE. Anything else (e.g. captcha/"punish" JSON
  // served to datacenter IPs) is a hard rejection, not an empty answer.
  const _ct = res.headers.get("content-type") || "";
  if (!_ct.includes("text/event-stream")) {
    const t = await res.text().catch(() => "");
    let detail = t.slice(0, 200);
    try {
      const j = JSON.parse(t);
      detail = `${(j.ret || []).join(",")} ${JSON.stringify(j.data || {}).slice(0, 160)}`;
    } catch { /* keep raw */ }
    throw new UpstreamError(`Upstream rejected request (captcha/WAF?): ${detail}`, 429, false);
  }
  for await (const ev of sseEvents(res)) {
    if (ev.error && (ev.error.code || ev.error.details || ev.error.message))
      throw new UpstreamError(`${ev.error.code || "upstream"}: ${ev.error.details || ev.error.message || ""}`.slice(0, 200), 502, true);
    if (ev.usage) yield { type: "usage", data: ev.usage };
    if (ev.response_id) yield { type: "rid", data: ev.response_id };
    const d = (ev.choices || [{}])[0].delta || {};
    const phase = d.phase, status = d.status;
    if (phase === "image_gen" && status === "typing" && d.content) { yield { type: "media", data: d.content, extra: d.extra }; continue; }
    if (phase === "image_gen" && status === "finished") { yield { type: "media_done" }; continue; }
    if (typeof phase === "string" && phase.endsWith("_gen") && status === "typing" && d.content) { yield { type: "media", data: d.content, extra: d.extra }; continue; }
    if (typeof phase === "string" && phase.endsWith("_gen") && status === "finished") { yield { type: "media_done" }; continue; }
    if (d.reasoning || d.reasoning_content) yield { type: "reasoning", data: d.reasoning || d.reasoning_content };
    else if (typeof d.tts === "string" && d.tts) yield { type: "tts", data: d.tts };
    else if (d.content && phase === "answer") yield { type: "content", data: d.content };
    else if (d.content && phase === "think") yield { type: "reasoning", data: d.content };
    else if (typeof ev.content === "string" && ev.content) yield { type: "content", data: ev.content };
    else if (typeof ev.reasoning_content === "string" && ev.reasoning_content) yield { type: "reasoning", data: ev.reasoning_content };
  }
}

/** Pool tokens in random order with failover.
 *  Explicit per-request tokens do NOT fall back (honest errors).
 *  Empty pool -> one anonymous guest attempt (often captcha-walled from
 *  datacenter IPs, but keeps zero-config mode possible). Dead pool ->
 *  report the real token error, no guest masquerade. */
async function withRotation(env, overrideToken, fn) {
  if (overrideToken) {
    return { result: await fn(overrideToken), tokenIndex: -1 };
  }
  let last = null;
  // 1) freshest known first: in-memory minted token, then shuffled pool
  const nowSec = Math.floor(Date.now() / 1000);
  if (authCache.access && authCache.accessExp - 60 > nowSec) {
    try { return { result: await fn(authCache.access), tokenIndex: -3 }; }
    catch (e) { last = e; }
  }
  const pool = poolTokens(env);
  for (const i of shuffled(pool.length)) {
    try { return { result: await fn(pool[i]), tokenIndex: i }; }
    catch (e) {
      last = e;
      if (e instanceof UpstreamError && !e.retryable) throw e;
      // else try next token
    }
  }
  // 2) last resort: mint a fresh token from the session cookie jars
  const minted = await mintAny(env);
  if (minted) {
    try { return { result: await fn(minted.access_token), tokenIndex: -4 }; }
    catch (e) { throw last || e; }
  }
  throw last || new UpstreamError("No working Qwen tokens and no session (QWEN_AUTH secret) to mint from", 401, false);
}

/* ---------------- OpenAI shaping ---------------- */

const envelope = (model, content, reasoning = null, toolCalls = null) => {
  const msg = toolCalls
    ? { role: "assistant", content: null, tool_calls: toolCalls }
    : { role: "assistant", content };
  if (reasoning && !toolCalls) msg.reasoning_content = reasoning;
  return {
    id: `chatcmpl-${crypto.randomUUID().slice(0, 8)}`,
    object: "chat.completion", created: Math.floor(Date.now() / 1000), model,
    choices: [{ index: 0, message: msg, finish_reason: toolCalls ? "tool_calls" : "stop" }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
};
const chunk = (model, delta, finish = null) =>
  `data: ${JSON.stringify({ id: `chatcmpl-${model}`, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;

function xmlToolCalls(text) {
  const m = typeof text === "string" && text.match(/<tool_calls>([\s\S]*?)<\/tool_calls>/);
  if (!m) return null;
  try {
    const calls = JSON.parse(m[1]);
    if (!Array.isArray(calls)) return null;
    return calls.map(() => ({
      id: `call_${crypto.randomUUID().slice(0, 8)}`, type: "function",
      function: { name: "fn", arguments: "{}" },
    })).map((c, i) => ({ ...c, function: { name: calls[i].name, arguments: JSON.stringify(calls[i].arguments ?? {}) } }));
  } catch { return null; }
}

function sizeToAspect(size, def) {
  if (!size) return def;
  if (/^\d+\s*:\s*\d+$/.test(size)) return size.replace(/\s/g, "");
  const m = String(size).match(/(\d+)\s*[x×]\s*(\d+)/);
  if (!m) return def;
  const r = Number(m[1]) / Number(m[2]);
  if (r >= 1.7) return "16:9";
  if (r >= 1.3) return "4:3";
  if (r >= 0.8) return "1:1";
  if (r >= 0.6) return "3:4";
  return "9:16";
}

async function toB64(url, cap = 15 * 1024 * 1024) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`media fetch ${r.status}`);
  const buf = new Uint8Array(await r.arrayBuffer());
  if (buf.length > cap) throw new Error("media too large for b64_json, use url");
  let s = "";
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(s);
}

/* ---------------- llms.txt (agent docs) ---------------- */

const LLMS_TXT = `# qwen-code-proxy

OpenAI-compatible + Anthropic-compatible gateway for Qwen chat models,
running on Cloudflare Workers. Unofficial; not affiliated with Alibaba/Qwen.

Base URL: https://<worker>/v1
Auth: Authorization: Bearer <PROXY_KEY> (server-gated). Optional per-request
Qwen token override: X-Qwen-Token: <qwen-jwt>.

## Endpoints

- GET /health — status {ok,gated,pool_size,auto_refresh,sessions}
- GET /v1/models — model list (live from upstream when possible)
- GET|POST /v1/validate — validate token (?token=, {"token"}, or pool report)
- GET|POST /v1/refresh — mint a fresh token from sessions (refreshed:true)
- POST /v1/chat/completions — OpenAI chat (stream + non-stream)
- POST /v1/messages — Anthropic Messages API (stream + non-stream)
- POST /v1/images/generations — {prompt,size,response_format:url|b64_json}
- POST /v1/images/edits — one image (multipart file or JSON url/base64) + prompt
- POST /v1/videos/generations — {prompt,image?,size,response_format}
- POST /v1/audio/speech — {input (max 4000 chars)} -> audio/wav bytes (24kHz mono)
- GET /llms.txt — this file

## Chat parameters (OpenAI superset)

- model, messages, stream, temperature (accepted), reasoning_effort
- thinking_mode: fast (default) | auto | thinking (precedence over reasoning_effort)
- reasoning_effort: none|minimal->fast, low|medium->auto, high|xhigh|max->thinking
- web_search_options: {} -> web search mode (legacy tools:[{type:web_search}] ok)
- tools + tool_choice auto|none|{type:function,function:{name}} -> tool_calls via XML bridge
- multimodal content parts: text, image_url (any file URL/base64), file {file_data|url,filename}, input_audio {data,format}

## File rules (agent mode)

- images<=5x20MB, audio<=1, video<=1, documents<=5x20MB; total<=10 files/50MB
- VALID: multi-image, multi-doc, media+document, single media
- INVALID (400): image+audio, image+video, audio+video, multi-video, multi-audio
- Failed downloads/uploads are skipped, request continues text-only

## Model IDs

- Text: qwen3.8-max, qwen3.8-omni-flash, qwen3.7-max, qwen3.7-plus, qwen3.6-plus,
  qwen3.5-plus, qwen3.5-omni-plus, qwen3-coder-plus (plus upstream list)
- Suffix modes (append to any text model): -search -thinking -deep-research
  -artifacts -slides -web-dev -full-stack -learn -travel -travel-research
  -podcast -translate -agent -mcp -deep-thinking -image -video (-t2i/-t2v/-i2v)
- Special: qwen-image qwen-video qwen-deep-research qwen-web-dev qwen-full-stack
  qwen-slides qwen-agent qwen-podcast qwen-translate
- claude-* aliases map to qwen3.8-max (suffix preserved)

## Anthropic mapping (/v1/messages)

- system string|blocks, messages with text|image|tool_use|tool_result blocks
- tools use input_schema; tool_choice auto|none|{type:tool,name}
- Returns message with text|tool_use blocks, stop_reason end_turn|tool_use
- Streaming uses message_start/content_block_delta/message_delta/message_stop

## Notes

- reasoning_content is best-effort (upstream sends summaries when it chooses to).
- Token pool rotates randomly with failover; dead sessions auto-mint replacements.
- Errors are OpenAI-style {error:{message,type,code}} (Anthropic shape on /v1/messages).
`;

/* ---------------- route handlers ---------------- */

async function handleChat(req, env, qwenOverride) {
  let body;
  try { body = await req.json(); }
  catch { return oerr("Invalid JSON body", "invalid_request_error", 400); }
  const r = resolveModel(body);
  if (r.error) return oerr(r.error, "invalid_request_error", 400);
  if (!body.messages?.length) return oerr("`messages` must be a non-empty array", "invalid_request_error", 400);
  const stream = body.stream === true;
  const forResearch = r.chatType === "deep_research";
  let effort = effortOf(body, forResearch);
  if (Array.isArray(body.tools) && body.tools.length && body.tool_choice !== "none") effort = "none";

  let prompt, fileInputs;
  try {
    const b = buildPrompt(body.messages);
    prompt = b.text; fileInputs = b.files;
  } catch (e) { return oerr(e.message, "invalid_request_error", 400); }
  if (!prompt && !fileInputs.length) return oerr("Empty messages", "invalid_request_error", 400);
  // Combination + count rules (400 fast, before burning quota).
  const kindOf = (f) => f.presumed || guessKind(mimeOfSrc(f.src, f.name), f.name);
  const combo = checkCombo(fileInputs.map(kindOf));
  if (combo.error) return oerr(combo.error, "invalid_request_error", 400);

  let fnTools = null;
  if (Array.isArray(body.tools) && body.tools.length && body.tool_choice !== "none")
    fnTools = body.tools.filter((t) => (t.type || "function") === "function");
  const wantsTools = fnTools?.length > 0;
  if (wantsTools && r.chatType === "t2t") {
    prompt += `\n\n[System: functions available: ${JSON.stringify(fnTools.map((t) => t.function || t)).slice(0, 3000)}. If a function is needed, output ONLY this XML on the last line: <tool_calls>[{"name":"<fn>","arguments":{...}}]</tool_calls>]`;
  }

  const run = async (token) => {
    let files = [];
    let totalBytes = 0;
    const realKinds = [];
    for (const f of fileInputs) {
      let raw;
      try {
        raw = await bytesFromInput(f.src, f.name);
      } catch {
        continue; // upload fallback: skip failed attachments, continue text-only
      }
      const [, realMime] = detectType(raw.bytes.slice(0, 12));
      const kind = (realMime !== "application/octet-stream" ? guessKind(realMime, raw.filename) : null)
        || f.presumed
        || guessKind(mimeOfSrc(f.src, raw.filename), raw.filename);
      const lim = FILE_LIMITS[kind];
      if (raw.bytes.length > lim.maxBytes)
        throw new UpstreamError(`${kind} file too large (max ${Math.round(lim.maxBytes / 1048576)}MB)`, 400, false);
      if (raw.bytes.length > AGENT_LIMITS.maxBytesEach)
        throw new UpstreamError(`file too large (agent max ${Math.round(AGENT_LIMITS.maxBytesEach / 1048576)}MB each)`, 400, false);
      totalBytes += raw.bytes.length;
      if (totalBytes > AGENT_LIMITS.maxBytesTotal)
        throw new UpstreamError(`attachments exceed ${Math.round(AGENT_LIMITS.maxBytesTotal / 1048576)}MB total`, 400, false);
      try {
        files.push(await uploadBytes(token, raw.bytes, raw.filename));
        realKinds.push(kind);
      } catch {
        continue; // upload fallback: skip, continue text-only
      }
    }
    // Re-check rules against sniffed real types (extensionless URLs etc.).
    const combo2 = checkCombo(realKinds);
    if (combo2.error) throw new UpstreamError(combo2.error, 400, false);
    return { token, files };
  };

  if (!stream) {
    try {
      const { result } = await withRotation(env, qwenOverride, async (token) => {
        const { files } = await run(token);
        let answer = "", reasoning = "";
        for await (const ev of runTurn(token, { model: r.base, chatType: r.chatType, prompt, files, effort })) {
          if (ev.type === "content") answer += ev.data;
          else if (ev.type === "reasoning") reasoning += ev.data;
        }
        return { answer, reasoning };
      });
      if (wantsTools) {
        const tc = xmlToolCalls(result.answer);
        if (tc) return json(envelope(r.requested, null, null, tc));
      }
      return json(envelope(r.requested, result.answer, result.reasoning || null));
    } catch (e) {
      return oerr(`Upstream error: ${e.message}`, e.httpStatus === 401 ? "authentication_error" : e.httpStatus === 400 ? "invalid_request_error" : "upstream_error", e.httpStatus || 502);
    }
  }

  // streaming — cached fresh token first, then shuffled pool, then cookie-mint
  const _pool = poolTokens(env);
  const _nowSec = Math.floor(Date.now() / 1000);
  const _seed = (authCache.access && authCache.accessExp - 60 > _nowSec) ? [authCache.access] : [];
  const candidates = qwenOverride ? [qwenOverride] : [..._seed, ...shuffled(_pool.length).map((i) => _pool[i])];

  const readable = new ReadableStream({
    async start(controller) {
      const enc = (s) => controller.enqueue(new TextEncoder().encode(s));
      let anyToolCalls = false;
      const attempt = async (token) => {
        const { files } = await run(token);
        let toolBuf = "";
        for await (const ev of runTurn(token, { model: r.base, chatType: r.chatType, prompt, files, effort })) {
          if (ev.type === "content") {
            if (wantsTools) toolBuf += ev.data;
            else enc(chunk(r.requested, { content: ev.data }));
          } else if (ev.type === "reasoning") enc(chunk(r.requested, { reasoning_content: ev.data }));
        }
        if (wantsTools) {
          const tc = xmlToolCalls(toolBuf);
          if (tc) { anyToolCalls = true; enc(chunk(r.requested, { tool_calls: tc })); }
          else if (toolBuf) enc(chunk(r.requested, { content: toolBuf }));
        }
      };
      try {
        let lastErr = null;
        let done = false;
        for (const cand of candidates) {
          try { await attempt(cand); done = true; break; }
          catch (e) {
            if (qwenOverride || !(e instanceof UpstreamError) || !e.retryable) throw e;
            lastErr = e;
          }
        }
        if (!done && !qwenOverride) {
          const minted2 = await mintAny(env);
          if (minted2) {
            try { await attempt(minted2.access_token); done = true; }
            catch (e) { lastErr = e; }
          }
        }
        if (!done) throw lastErr || new UpstreamError("No Qwen tokens and no session to mint from", 401, false);
        enc(chunk(r.requested, {}, anyToolCalls ? "tool_calls" : "stop"));
        enc("data: [DONE]\n\n");
      } catch (e) {
        enc(chunk(r.requested, { content: `\n[upstream error: ${String(e.message).slice(0, 160)}]` }));
      } finally { controller.close(); }
    },
  });
  return new Response(readable, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", ...cors() },
  });
}

async function handleMedia(req, env, qwenOverride, kind) {
  // kind: t2i | image_edit | t2v
  const ctype = req.headers.get("content-type") || "";
  let prompt = "", size = "", responseFormat = "url", imageInput = null, imageCount = 0;
  if (ctype.includes("multipart/form-data")) {
    const form = await req.formData();
    prompt = String(form.get("prompt") || "");
    size = String(form.get("size") || form.get("aspect_ratio") || "");
    responseFormat = String(form.get("response_format") || "url");
    const imgs = form.getAll("image").concat(form.getAll("image[]"));
    imageCount = imgs.filter((v) => v && (typeof v === "string" ? v.length : v.size)).length;
    if (imageCount > 1) return oerr("Only one source image is supported", "invalid_request_error", 400);
    const one = imgs.find((v) => v && (typeof v === "string" ? v.length : v.size));
    if (one) {
      imageInput = typeof one === "string"
        ? one
        : { bytes: new Uint8Array(await one.arrayBuffer()), filename: one.name || "upload.bin" };
    }
  } else {
    let body;
    try { body = await req.json(); }
    catch { return oerr("Invalid JSON body", "invalid_request_error", 400); }
    prompt = String(body.prompt || "");
    size = String(body.size || body.aspect_ratio || "");
    responseFormat = String(body.response_format || "url");
    const im = body.image;
    if (Array.isArray(im)) {
      if (im.length > 1) return oerr("Only one source image is supported", "invalid_request_error", 400);
      imageInput = im[0] || null;
    } else if (im) imageInput = im;
  }
  if (!prompt) return oerr("`prompt` is required", "invalid_request_error", 400);
  if ((kind === "image_edit") && !imageInput) return oerr("`image` is required for edits", "invalid_request_error", 400);

  try {
    const { result } = await withRotation(env, qwenOverride, async (token) => {
      let files = [];
      const needUpload = imageInput || kind === "t2i" || kind === "t2v";
      if (imageInput) {
        const { bytes, filename } = imageInput.bytes
          ? imageInput
          : await bytesFromInput(imageInput);
        files.push(await uploadBytes(token, bytes, filename));
      }
      const urls = [];
      const texts = [];
      for await (const ev of runTurn(token, {
        model: kind === "t2v" ? "qwen3.8-max" : "qwen3.8-max",
        chatType: kind, prompt, files, effort: "none",
        size: sizeToAspect(size, kind === "t2v" ? "16:9" : "1:1"),
      })) {
        if (ev.type === "media" && ev.data) urls.push(ev.data);
        else if (ev.type === "content" && ev.data) texts.push(ev.data);
      }
      // Fallback: media URLs sometimes arrive embedded in answer text.
      const joined = texts.join(" ");
      const m = joined.match(/https?:\/\/[^\s"'<>]+\.(mp4|webm|mov|mp3|wav|m4a|ogg|opus|flac|png|jpe?g|webp|gif)(\?[^\s"'<>]*)?/gi);
      if (m) for (const u of m) if (!urls.includes(u)) urls.push(u);
      void needUpload;
      if (!urls.length) throw new UpstreamError("Upstream returned no media URL", 502, true);
      return { urls };
    });
    if (responseFormat === "b64_json") {
      const b64 = await toB64(result.urls[0]).catch((e) => { throw new UpstreamError(e.message, 502, false); });
      return json(kind === "t2v"
        ? { created: Math.floor(Date.now() / 1000), data: [{ b64_json: b64 }] }
        : { created: Math.floor(Date.now() / 1000), data: [{ b64_json: b64 }] });
    }
    return json({ created: Math.floor(Date.now() / 1000), data: result.urls.map((u) => ({ url: u })) });
  } catch (e) {
    return oerr(`Upstream error: ${e.message}`, e.httpStatus === 400 ? "invalid_request_error" : "upstream_error", e.httpStatus || 502);
  }
}

/** Fetch chat messages (for ids etc.). Returns array (may be empty). */
async function chatMessages(token, chatId) {
  const r = await upstreamFetch(`${UPSTREAM}/api/v2/chats/${encodeURIComponent(chatId)}`, {
    headers: await upstreamHeaders(token),
  });
  const t = await r.text();
  if (!r.ok) throw new UpstreamError(`chat fetch ${r.status}`, r.status === 401 ? 401 : 502, r.status !== 400);
  try {
    const j = JSON.parse(t);
    const msgs = j?.data?.chat?.messages || j?.data?.messages || [];
    return Array.isArray(msgs) ? msgs : [];
  } catch { return []; }
}

/** Wrap raw s16le PCM mono samples in a WAV container. */
function pcmToWav(pcmBytes, sampleRate = 24000) {
  const h = new ArrayBuffer(44);
  const v = new DataView(h);
  const wstr = (o, s) => { for (let i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); };
  wstr(0, "RIFF");
  v.setUint32(4, 36 + pcmBytes.length, true);
  wstr(8, "WAVEfmt ");
  v.setUint32(16, 16, true);
  v.setUint16(20, 1, true);
  v.setUint16(22, 1, true);
  v.setUint32(24, sampleRate, true);
  v.setUint32(28, sampleRate * 2, true);
  v.setUint16(32, 2, true);
  v.setUint16(34, 16, true);
  wstr(36, "data");
  v.setUint32(40, pcmBytes.length, true);
  const out = new Uint8Array(44 + pcmBytes.length);
  out.set(new Uint8Array(h), 0);
  out.set(pcmBytes, 44);
  return out;
}

/** OpenAI-compatible text-to-speech: POST /v1/audio/speech.
 *  Body: {model?, input, voice?, response_format?}.
 *  Upstream streams base64 s16le PCM 24kHz mono in delta.tts chunks;
 *  we wrap it as WAV (universally playable). */
async function handleSpeech(req, env, qwenOverride) {
  let body;
  try { body = await req.json(); }
  catch { return oerr("Invalid JSON body", "invalid_request_error", 400); }
  const input = String(body.input || "");
  if (!input) return oerr("`input` is required", "invalid_request_error", 400);
  if (input.length > 4000) return oerr("`input` too long (max 4000 chars)", "invalid_request_error", 400);
  try {
    const { result } = await withRotation(env, qwenOverride, async (token) => {
      const chatId = await apiNewChat(token, "qwen3.8-max", "t2t", "speech");
      const now = Date.now();
      const msg = {
        fid: crypto.randomUUID(), parentId: null, childrenIds: [],
        role: "user", content: `Repeat the following text EXACTLY, character for character, with no additions or commentary:\n"""${input}"""`,
        user_action: "chat", files: [], timestamp: now, models: ["qwen3.8-max"],
        chat_type: "t2t", feature_config: featureConfig("none"),
        extra: { meta: { subChatType: "t2t" } }, sub_chat_type: "t2t",
      };
      const res = await upstreamFetch(`${UPSTREAM}/api/v2/chat/completions?chat_id=${encodeURIComponent(chatId)}`, {
        method: "POST", headers: await upstreamHeaders(token),
        body: JSON.stringify({
          stream: true, version: "2.1", incremental_output: true, chat_id: chatId,
          chat_mode: token ? "normal" : "guest", model: "qwen3.8-max", parent_id: null,
          messages: [msg], timestamp: now,
        }),
      });
      if (!res.ok || !res.body) throw new UpstreamError(`Upstream ${res.status}`, 502, true);
      for await (const _ev of sseEvents(res)) { /* drain turn */ }
      // Messages materialize shortly after the stream ends; poll briefly.
      // Note: content may lag behind the id — the id alone suffices for TTS.
      let asst = null;
      for (let i = 0; i < 4; i++) {
        const msgs = await chatMessages(token, chatId);
        asst = [...msgs].reverse().find((m) => m.role === "assistant" && m.id);
        if (asst) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      if (!asst) throw new UpstreamError("No assistant message to synthesize", 502, true);
      const tts = await upstreamFetch(`${UPSTREAM}/api/v2/tts/completions?chat_id=${encodeURIComponent(chatId)}`, {
        method: "POST", headers: await upstreamHeaders(token),
        body: JSON.stringify({
          chat_id: chatId, timestamp: Math.floor(Date.now() / 1000),
          messages: [{ id: asst.id, role: "assistant", sub_chat_type: "tts" }],
        }),
      });
      const ct = tts.headers.get("content-type") || "";
      if (!tts.ok) {
        const t = await tts.text().catch(() => "");
        throw new UpstreamError(`TTS ${tts.status}: ${t.slice(0, 160)}`, tts.status === 401 ? 401 : 502, true);
      }
      if (ct.includes("audio/") || ct.includes("octet-stream")) {
        const buf = await tts.arrayBuffer();
        return { audio: new Uint8Array(buf), mime: ct.split(";")[0] };
      }
      const raw = await tts.text();
      // Primary shape: SSE with base64 s16le PCM 24kHz mono in delta.tts
      let pcm = "";
      if (ct.includes("text/event-stream")) {
        for (const line of raw.split("\n")) {
          const t = line.trim();
          if (!t.startsWith("data:")) continue;
          const p = t.slice(5).trim();
          if (p === "[DONE]") continue;
          try { pcm += JSON.parse(p).choices?.[0]?.delta?.tts || ""; } catch { /* ignore */ }
        }
      }
      if (pcm) {
        const bin = atob(pcm);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return { audio: pcmToWav(u8), mime: "audio/wav" };
      }
      // Fallbacks: embedded base64 audio or audio URL
      const b64 = raw.match(/data:audio\/[a-z0-9+.-]+;base64,([A-Za-z0-9+/=]+)/i);
      if (b64) {
        const bin = atob(b64[1]);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return { audio: u8, mime: "audio/mpeg" };
      }
      const um = raw.match(/https?:\/\/[^\s"'<>]+\.(mp3|wav|m4a|ogg|opus|flac)(\?[^\s"'<>]*)?/i);
      if (um) {
        const ar = await fetch(um[0]);
        if (!ar.ok) throw new UpstreamError("audio fetch failed", 502, false);
        return { audio: new Uint8Array(await ar.arrayBuffer()), mime: "audio/mpeg" };
      }
      throw new UpstreamError(`TTS unexpected shape (${ct || "no-ctype"}): ${raw.slice(0, 120)}`, 502, true);
    });
    if (result.audio.length > 25 * 1024 * 1024) throw new UpstreamError("audio too large", 502, false);
    return new Response(result.audio, { headers: { "Content-Type": result.mime || "audio/mpeg", ...cors() } });
  } catch (e) {
    return oerr(`Upstream error: ${e.message}`, e.httpStatus === 400 ? "invalid_request_error" : "upstream_error", e.httpStatus || 502);
  }
}

/** Anthropic Messages API compatibility: POST /v1/messages.
 *  Accepts system/messages/tools in Anthropic shape, runs the same upstream
 *  turn, translates the result back (text + tool_use blocks). */
async function handleAnthropic(req, env, qwenOverride) {
  let body;
  try { body = await req.json(); }
  catch { return json({ type: "error", error: { type: "invalid_request_error", message: "Invalid JSON body" } }, 400); }
  const r = resolveModel({ ...body, model: body.model || "qwen3.8-max" });
  if (r.error) return json({ type: "error", error: { type: "not_found_error", message: r.error } }, 400);
  const msgs = Array.isArray(body.messages) ? body.messages : [];
  if (!msgs.length) return json({ type: "error", error: { type: "invalid_request_error", message: "`messages` must be a non-empty array" } }, 400);
  const stream = body.stream === true;
  const sysText = typeof body.system === "string" ? body.system
    : Array.isArray(body.system) ? body.system.filter((b) => b.type === "text").map((b) => b.text).join("\n") : "";

  // Anthropic blocks -> OpenAI-ish messages + file inputs
  const oaiMsgs = [];
  if (sysText) oaiMsgs.push({ role: "system", content: sysText });
  const fileInputs = [];
  for (const m of msgs) {
    if (typeof m.content === "string") { oaiMsgs.push({ role: m.role, content: m.content }); continue; }
    const texts = [];
    for (const b of m.content || []) {
      if (b.type === "text") texts.push(b.text || "");
      else if (b.type === "image") {
        const s = b.source || {};
        if (s.type === "base64" && s.data) fileInputs.push({ src: `data:${s.media_type || "image/jpeg"};base64,${s.data}`, name: "", presumed: "image" });
        else if (s.type === "url" && (s.url || s.data)) fileInputs.push({ src: s.url || s.data, name: "", presumed: "image" });
      } else if (b.type === "tool_use") texts.push(`[Called ${b.name} with ${JSON.stringify(b.input ?? {})}]`);
      else if (b.type === "tool_result") {
        const c = typeof b.content === "string" ? b.content : (b.content || []).filter((x) => x.type === "text").map((x) => x.text).join("\n");
        texts.push(`[Tool result${b.tool_use_id ? ` for ${b.tool_use_id}` : ""}: ${c}]`);
      }
    }
    oaiMsgs.push({ role: m.role, content: texts.join("\n") });
  }
  const fnTools = Array.isArray(body.tools) ? body.tools.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description || "", parameters: t.input_schema || { type: "object" } },
  })) : [];
  const wantsTools = fnTools.length > 0 && (!body.tool_choice || body.tool_choice.type !== "none");
  const forced = body.tool_choice && body.tool_choice.type === "tool" ? body.tool_choice.name : null;

  const prompt0 = buildPrompt(oaiMsgs).text;
  const prompt = prompt0 + (wantsTools
    ? `\n\n[System: functions available: ${JSON.stringify(fnTools.map((t) => t.function)).slice(0, 3000)}. ${forced ? `You MUST call ${forced}. ` : ""}If a function is needed, output ONLY this XML on the last line: <tool_calls>[{"name":"<fn>","arguments":{...}}]</tool_calls>]`
    : "");

  const run = async (token) => {
    let files = [];
    for (const f of fileInputs) {
      try {
        const { bytes, filename } = await bytesFromInput(f.src, f.name);
        files.push(await uploadBytes(token, bytes, filename));
      } catch { /* skip */ }
    }
    return { token, files };
  };

  const toAnthropic = (answer) => {
    const blocks = [];
    let stop = "end_turn";
    if (wantsTools) {
      const tc = xmlToolCalls(answer);
      if (tc && tc.length) {
        stop = "tool_use";
        for (const c of tc) {
          let args = {};
          try { args = JSON.parse(c.function.arguments); } catch { /* keep {} */ }
          blocks.push({ type: "tool_use", id: c.id, name: c.function.name, input: args });
        }
      }
    }
    const plain = answer.replace(/<tool_calls>[\s\S]*?<\/tool_calls>/g, "").trim();
    if (plain || !blocks.length) blocks.unshift({ type: "text", text: plain || answer });
    return {
      id: `msg_${crypto.randomUUID().slice(0, 8)}`, type: "message", role: "assistant",
      content: blocks, model: r.requested, stop_reason: stop, stop_sequence: null,
      usage: { input_tokens: 0, output_tokens: 0 },
    };
  };

  if (!stream) {
    try {
      const { result } = await withRotation(env, qwenOverride, async (token) => {
        const { files } = await run(token);
        let answer = "";
        for await (const ev of runTurn(token, { model: r.base, chatType: r.chatType, prompt, files, effort: "none" })) {
          if (ev.type === "content") answer += ev.data;
        }
        return { answer };
      });
      return json(toAnthropic(result.answer));
    } catch (e) {
      return json({ type: "error", error: { type: "api_error", message: `Upstream error: ${e.message}` } }, e.httpStatus || 502);
    }
  }

  const pool0 = qwenOverride ? [qwenOverride] : (() => { const p = poolTokens(env); const n = Math.floor(Date.now() / 1000); void n; return p.length ? [p[Math.floor(Math.random() * p.length)]] : []; })();
  const readable = new ReadableStream({
    async start(controller) {
      const enc = (ev, data) => controller.enqueue(new TextEncoder().encode(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`));
      const msgId = `msg_${crypto.randomUUID().slice(0, 8)}`;
      const attempt = async (token) => {
        const { files } = await run(token);
        let toolBuf = "", textBuf = "";
        enc("message_start", { type: "message_start", message: { id: msgId, type: "message", role: "assistant", content: [], model: r.requested, stop_reason: null, usage: { input_tokens: 0, output_tokens: 0 } } });
        enc("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
        for await (const ev of runTurn(token, { model: r.base, chatType: r.chatType, prompt, files, effort: "none" })) {
          if (ev.type !== "content") continue;
          if (wantsTools) toolBuf += ev.data;
          else { textBuf += ev.data; enc("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: ev.data } }); }
        }
        if (wantsTools) {
          const tc = xmlToolCalls(toolBuf);
          if (tc && tc.length) {
            enc("content_block_stop", { type: "content_block_stop", index: 0 });
            tc.forEach((c, i) => {
              let args = {};
              try { args = JSON.parse(c.function.arguments); } catch { /* keep */ }
              const idx = i + 1;
              enc("content_block_start", { type: "content_block_start", index: idx, content_block: { type: "tool_use", id: c.id, name: c.function.name, input: {} } });
              enc("content_block_delta", { type: "content_block_delta", index: idx, delta: { type: "input_json_delta", partial_json: JSON.stringify(args) } });
              enc("content_block_stop", { type: "content_block_stop", index: idx });
            });
            enc("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 0 } });
          } else {
            const plain = toolBuf.replace(/<tool_calls>[\s\S]*?<\/tool_calls>/g, "").trim() || toolBuf;
            if (plain !== textBuf && plain) enc("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: plain } });
            enc("content_block_stop", { type: "content_block_stop", index: 0 });
            enc("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 0 } });
          }
        } else {
          enc("content_block_stop", { type: "content_block_stop", index: 0 });
          enc("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 0 } });
        }
        enc("message_stop", { type: "message_stop" });
      };
      try {
        if (pool0.length) {
          try { await attempt(pool0[0]); }
          catch (e) {
            if (qwenOverride || !(e instanceof UpstreamError) || !e.retryable) throw e;
            const rest = poolTokens(env).filter((t) => t !== pool0[0]);
            if (!rest.length) {
              const minted = await mintAny(env);
              if (!minted) throw e;
              await attempt(minted.access_token);
            } else await attempt(rest[Math.floor(Math.random() * rest.length)]);
          }
        } else {
          const minted = await mintAny(env);
          if (!minted) throw new UpstreamError("No Qwen tokens and no session to mint from", 401, false);
          await attempt(minted.access_token);
        }
      } catch (e) {
        enc("message_stop", { type: "message_stop" });
      } finally { controller.close(); }
    },
  });
  return new Response(readable, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", ...cors() } });
}

async function handleValidate(req, env) {
  let token = new URL(req.url).searchParams.get("token") || "";
  if (req.method === "POST") {
    try { token = (await req.json()).token || token; } catch { /* ignore */ }
  }
  if (!token) token = req.headers.get("X-Qwen-Token") || "";
  // NOTE: Authorization Bearer is the PROXY_KEY when gated — never a Qwen token.
  if (!token) {
    // validate whole pool (masked)
    const pool = poolTokens(env);
    if (!pool.length) return oerr("No token supplied and pool is empty", "invalid_request_error", 400);
    const out = [];
    for (let i = 0; i < pool.length; i++) {
      try { await apiNewChat(pool[i], "qwen3.8-max", "t2t", "validate"); out.push({ index: i, valid: true, expires: expInfo(decodeJwtExp(pool[i])) }); }
      catch (e) { out.push({ index: i, valid: false, expires: expInfo(decodeJwtExp(pool[i])), detail: String(e.message).slice(0, 120) }); }
    }
    return json({ tokens: out });
  }
  const exp = decodeJwtExp(token);
  try {
    await apiNewChat(token, "qwen3.8-max", "t2t", "validate");
    return json({ valid: true, expires_at: exp, expires: expInfo(exp) });
  } catch (e) {
    return json({ valid: false, expires_at: exp, expires: expInfo(exp), detail: String(e.message).slice(0, 160) });
  }
}

/** Try every known jar in order; first successful mint wins. */
async function mintAny(env) {
  for (const jar of authJars(env)) {
    const m = await mintViaAuth(jar);
    if (m) return m;
  }
  return null;
}

/** Try to mint a fresh token via the session cookie jar (the web app's own
 *  mechanism). Returns {access_token, expires_at, ...} or null. */
async function tryUpstreamMint(token, env) {
  return mintAny(env);
}

async function handleRefresh(req, env) {
  // True refresh when upstream allows it (echo + validity report otherwise).
  let token = new URL(req.url).searchParams.get("token") || "";
  if (req.method === "POST") {
    try { token = (await req.json()).token || token; } catch { /* ignore */ }
  }
  if (!token) token = req.headers.get("X-Qwen-Token") || "";
  // NOTE: Authorization Bearer is the PROXY_KEY when gated — never a Qwen token.
  const pool = poolTokens(env);
  if (!token) token = pool[0] || "";
  if (!token) {
    // No token context at all: mint purely from the session jar, if present.
    const minted0 = await mintAny(env);
    if (minted0) {
      return json({
        access_token: minted0.access_token, expires_at: minted0.expires_at,
        expires: expInfo(minted0.expires_at), refreshed: true,
        refresh_cookie_rotated: Boolean(minted0.refresh_token),
        auth_jar: minted0.jar || null,
        note: "Fresh token minted via session refresh.",
      });
    }
    return oerr("No token available", "invalid_request_error", 400);
  }
  const minted = await tryUpstreamMint(token, env);
  if (minted) {
    return json({
      access_token: minted.access_token, expires_at: minted.expires_at,
      expires: expInfo(minted.expires_at), refreshed: true,
      refresh_cookie_rotated: Boolean(minted.refresh_token),
      auth_jar: minted.jar || null,
      note: "Fresh token minted via session refresh. If refresh_cookie_rotated, update QWEN_AUTH with auth_jar (cron).",
    });
  }
  try {
    await apiNewChat(token, "qwen3.8-max", "t2t", "refresh-check");
    const exp = decodeJwtExp(token);
    return json({ access_token: token, expires_at: exp, expires: expInfo(exp), refreshed: false, note: "Token still valid. When it expires, re-extract from chat.qwen.ai (localStorage token) and update QWEN_TOKENS." });
  } catch (e) {
    return oerr(`Token invalid/expired — re-extract from chat.qwen.ai: ${String(e.message).slice(0, 140)}`, "authentication_error", 401);
  }
}

let modelsCache = { at: 0, body: null };

async function handleModels(env) {
  if (modelsCache.body && Date.now() - modelsCache.at < 5 * 60 * 1000) return modelsCache.body.clone();
  const pool = poolTokens(env);
  if (pool.length) {
    for (const i of shuffled(pool.length)) {
      try {
        const r = await upstreamFetch(`${UPSTREAM}/api/models`, { headers: await upstreamHeaders(pool[i]) }, 1);
        const j = await r.json();
        const ids = (j.data || []).map((m) => m.id).filter(Boolean);
        if (ids.length) {
          const variants = new Set(ids);
          for (const m of ids) {
            variants.add(`${m}-search`); variants.add(`${m}-thinking`);
            variants.add(`${m}-deep-research`); variants.add(`${m}-artifacts`); variants.add(`${m}-slides`);
          }
          for (const s of Object.keys(SPECIAL)) variants.add(s);
          const out = json({ object: "list", data: [...variants].map((id) => ({ id, object: "model", created: 0, owned_by: "qwen" })) });
          modelsCache = { at: Date.now(), body: out.clone() };
          return out;
        }
      } catch { /* try next / fallback */ }
    }
  }
  const all = new Set([...TEXT_MODELS, ...Object.keys(SPECIAL)]);
  for (const m of TEXT_MODELS) {
    all.add(`${m}-search`); all.add(`${m}-thinking`);
    all.add(`${m}-deep-research`); all.add(`${m}-artifacts`); all.add(`${m}-slides`);
    all.add(`${m}-agent`); all.add(`${m}-translate`); all.add(`${m}-podcast`);
  }
  const out2 = json({ object: "list", data: [...all].map((id) => ({ id, object: "model", created: 0, owned_by: "qwen" })) });
  modelsCache = { at: Date.now(), body: out2.clone() };
  return out2;
}

/* ---------------- scheduled cron ---------------- */

/** PUT a Worker secret via the Cloudflare API (needs CF_API_TOKEN + CF_ACCOUNT_ID). */
async function cfPutSecret(env, name, text) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.CF_WORKER_NAME) return false;
  const r = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${env.CF_WORKER_NAME}/secrets`,
    {
      method: "PUT",
      headers: { Authorization: `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name, text, type: "secret_text" }),
    },
  );
  return r.ok;
}

/** Every cron tick: mint fresh tokens for ALL sessions, cache them, and
 *  persist back to Worker secrets when API credentials are configured. */
async function scheduledRefresh(env) {
  const minted = [];
  for (const jar of authJars(env)) {
    try {
      const m = await mintViaAuth(jar);
      if (m) minted.push(m);
    } catch { /* next jar */ }
  }
  const okSecrets =
    env.CF_API_TOKEN && env.CF_ACCOUNT_ID && minted.length
      ? (await cfPutSecret(env, "QWEN_TOKENS", minted.map((m) => m.access_token).join(","))) &&
        (await cfPutSecret(env, "QWEN_AUTH", authJars(env).join("\n")))
      : false;
  return { refreshed: minted.length, sessions: authJars(env).length, secretsPersisted: Boolean(okSecrets) };
}

/** List all chat ids for a token. */
async function apiListChats(token) {
  const r = await fetch(`${UPSTREAM}/api/v2/chats/`, { headers: await upstreamHeaders(token) });
  const t = await r.text();
  if (!r.ok) throw new UpstreamError(`chat list ${r.status}`, r.status === 401 ? 401 : 502, true);
  try {
    const j = JSON.parse(t);
    const items = Array.isArray(j.data) ? j.data : j.data?.chats || j.data?.list || [];
    return items.map((c) => c.id || c.chat_id).filter(Boolean);
  } catch { return []; }
}

/** Real delete-all-chats (per session). Destructive: uses pool tokens only. */
async function handleChatsDelete(req, env) {
  const pool = poolTokens(env);
  if (!pool.length) return oerr("No pool tokens configured (refusing cookie-mint delete)", "invalid_request_error", 400);
  const per = [];
  let total = 0;
  for (let i = 0; i < pool.length; i++) {
    try {
      const ids = await apiListChats(pool[i]);
      if (!ids.length) { per.push({ index: i, deleted: 0 }); continue; }
      const r = await fetch(`${UPSTREAM}/api/v2/chats/batch_delete`, {
        method: "POST", headers: await upstreamHeaders(pool[i]),
        body: JSON.stringify({ ids }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && (j.success || j.data?.status)) { total += ids.length; per.push({ index: i, deleted: ids.length }); }
      else per.push({ index: i, deleted: 0, error: JSON.stringify(j).slice(0, 100) });
    } catch (e) { per.push({ index: i, deleted: 0, error: String(e.message).slice(0, 100) }); }
  }
  return json({ deleted: total, sessions: per });
}

/* ---------------- entry ---------------- */

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try { await scheduledRefresh(env); } catch { /* cron must never throw */ }
    })());
  },
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });

    if (path === "/" || path === "/health")
      return json({
        ok: true, service: "qwen-code-proxy", upstream: UPSTREAM,
        gated: Boolean(env.PROXY_KEY), pool_size: poolTokens(env).length,
        auto_refresh: authJars(env).length > 0, sessions: authJars(env).length,
        endpoints: ["/health", "/v1/models", "/v1/validate", "/v1/refresh", "/v1/chat/completions", "/v1/messages", "/v1/images/generations", "/v1/images/edits", "/v1/videos/generations", "/v1/audio/speech", "/llms.txt"],
        time: new Date().toISOString(),
      });

    if (path === "/v1/models") return handleModels(env);
    if (path === "/llms.txt" || path === "/llms-full.txt" || path === "/docs")
      return new Response(LLMS_TXT, { headers: { "Content-Type": "text/plain; charset=utf-8", ...cors() } });

    // everything below is gated when PROXY_KEY is set
    const gate = checkGate(req, env);
    if (gate.gateError) return oerr("Invalid proxy key", "authentication_error", 401);
    const qwenOverride = req.headers.get("X-Qwen-Token") || (env.PROXY_KEY ? "" : gate.bearer);

    if (path === "/v1/validate" || path === "/validate") return handleValidate(req, env);
    if (path === "/v1/refresh" || path === "/refresh") return handleRefresh(req, env);
    if (path === "/v1/chat/completions" && req.method === "POST") return handleChat(req, env, qwenOverride);
    if ((path === "/v1/messages" || path === "/v1/messages/count_tokens") && req.method === "POST") {
      if (path.endsWith("count_tokens")) {
        let b; try { b = await req.json(); } catch { return json({ type: "error", error: { type: "invalid_request_error", message: "Invalid JSON" } }, 400); }
        const n = JSON.stringify(b.messages || []).length;
        return json({ input_tokens: Math.ceil(n / 4) });
      }
      return handleAnthropic(req, env, qwenOverride);
    }
    if (path === "/v1/audio/speech" && req.method === "POST") return handleSpeech(req, env, qwenOverride);
    if (path === "/v1/images/generations" && req.method === "POST") return handleMedia(req, env, qwenOverride, "t2i");
    if (path === "/v1/images/edits" && req.method === "POST") return handleMedia(req, env, qwenOverride, "image_edit");
    if (path === "/v1/videos/generations" && req.method === "POST") return handleMedia(req, env, qwenOverride, "t2v");
    if (path === "/v1/chats/delete")
      return handleChatsDelete(req, env);

    return oerr(`Unknown route ${url.pathname}`, "not_found", 404);
  },
};
