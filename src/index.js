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
  for (const j of String(env.QWEN_AUTH || "").split(/\r?\n/)) push(j);
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
  "qwen3.8-max", "qwen3.8-max-preview", "qwen3.7-plus", "qwen3.7-max",
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
};

/** model-name suffix -> chat_type (mirrors Qwen-Reverse server) */
const SUFFIXES = [
  ["-deep-research", "deep_research"], ["-deepresearch", "deep_research"],
  ["-full-stack", "web_dev"], ["-fullstack", "web_dev"], ["-web-dev", "web_dev"], ["-webdev", "web_dev"],
  ["-artifacts", "artifacts"], ["-artifact", "artifacts"],
  ["-slides", "slides"], ["-slide", "slides"],
  ["-learn", "learn"], ["-travel", "travel"],
  ["-search", "search"],
  ["-image", "t2i"], ["-t2i", "t2i"],
  ["-video", "t2v"], ["-t2v", "t2v"],
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

async function apiNewChat(token, model, chatType, title) {
  const now = Date.now();
  const res = await fetch(`${UPSTREAM}/api/v2/chats/new`, {
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

/** Build single-string prompt + collect image inputs from OpenAI messages. */
function buildPrompt(messages) {
  const images = [];
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
          if (u) images.push(u);
        }
      }
      const t = texts.join("\n");
      lines.push(messages.length === 1 && m.role === "user" ? t : `${role}: ${t}`);
    }
  }
  return { text: lines.join("\n\n") || "", images };
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
    const buf = new Uint8Array(await r.arrayBuffer());
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
  const msg = {
    fid: crypto.randomUUID(), parentId: null, childrenIds: [],
    role: "user", content: prompt, user_action: "chat", files: files || [],
    timestamp: now, models: [model], chat_type: chatType,
    feature_config: featureConfig(effort),
    extra: { meta: { subChatType: chatType } }, sub_chat_type: chatType,
  };
  const payload = {
    stream: true, version: "2.1", incremental_output: true, chat_id: chatId,
    chat_mode: token ? "normal" : "guest", model, parent_id: null,
    messages: [msg], timestamp: now,
    thinking_mode: effort === "high" ? "Thinking" : effort === "medium" ? "Auto" : "Fast",
  };
  if (size) payload.size = size;
  const res = await fetch(`${UPSTREAM}/api/v2/chat/completions?chat_id=${encodeURIComponent(chatId)}`, {
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
    if (d.reasoning) yield { type: "reasoning", data: d.reasoning };
    else if (d.content && phase === "answer") yield { type: "content", data: d.content };
    else if (d.content && phase === "think") yield { type: "reasoning", data: d.content };
    else if (typeof ev.content === "string" && ev.content) yield { type: "content", data: ev.content };
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
  const effort = effortOf(body, forResearch);

  let prompt, images;
  try {
    const b = buildPrompt(body.messages);
    prompt = b.text; images = b.images;
  } catch (e) { return oerr(e.message, "invalid_request_error", 400); }
  if (!prompt && !images.length) return oerr("Empty messages", "invalid_request_error", 400);

  let fnTools = null;
  if (Array.isArray(body.tools) && body.tools.length && body.tool_choice !== "none")
    fnTools = body.tools.filter((t) => (t.type || "function") === "function");
  const wantsTools = fnTools?.length > 0;
  if (wantsTools && r.chatType === "t2t") {
    prompt += `\n\n[System: functions available: ${JSON.stringify(fnTools.map((t) => t.function || t)).slice(0, 3000)}. If a function is needed, output ONLY this XML on the last line: <tool_calls>[{"name":"<fn>","arguments":{...}}]</tool_calls>]`;
  }

  const run = async (token) => {
    let files = [];
    for (const img of images.slice(0, 4)) {
      const { bytes, filename } = await bytesFromInput(img);
      files.push(await uploadBytes(token, bytes, filename));
    }
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
      return oerr(`Upstream error: ${e.message}`, e.httpStatus === 401 ? "authentication_error" : "upstream_error", e.httpStatus || 502);
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
          if (tc) enc(chunk(r.requested, { tool_calls: tc }));
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
          if (minted) {
            try { await attempt(minted2.access_token); done = true; }
            catch (e) { lastErr = e; }
          }
        }
        if (!done) throw lastErr || new UpstreamError("No Qwen tokens and no session to mint from", 401, false);
        enc(chunk(r.requested, {}, "stop"));
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
      // Fallback: video URLs sometimes arrive embedded in answer text.
      const joined = texts.join(" ");
      const m = joined.match(/https?:\/\/[^\s"'<>]+\.(mp4|webm|mov|png|jpe?g|webp|gif)(\?[^\s"'<>]*)?/gi);
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
    return oerr(`Upstream error: ${e.message}`, "upstream_error", e.httpStatus || 502);
  }
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
    const minted0 = await mintViaAuth(authJar(env));
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

async function handleModels(env) {
  const pool = poolTokens(env);
  if (pool.length) {
    for (const i of shuffled(pool.length)) {
      try {
        const r = await fetch(`${UPSTREAM}/api/models`, { headers: await upstreamHeaders(pool[i]) });
        const j = await r.json();
        const ids = (j.data || []).map((m) => m.id).filter(Boolean);
        if (ids.length) {
          const variants = new Set(ids);
          for (const m of ids) {
            variants.add(`${m}-search`); variants.add(`${m}-thinking`);
            variants.add(`${m}-deep-research`); variants.add(`${m}-artifacts`); variants.add(`${m}-slides`);
          }
          for (const s of Object.keys(SPECIAL)) variants.add(s);
          return json({ object: "list", data: [...variants].map((id) => ({ id, object: "model", created: 0, owned_by: "qwen" })) });
        }
      } catch { /* try next / fallback */ }
    }
  }
  const all = new Set([...TEXT_MODELS, ...Object.keys(SPECIAL)]);
  for (const m of TEXT_MODELS) {
    all.add(`${m}-search`); all.add(`${m}-thinking`);
    all.add(`${m}-deep-research`); all.add(`${m}-artifacts`); all.add(`${m}-slides`);
  }
  return json({ object: "list", data: [...all].map((id) => ({ id, object: "model", created: 0, owned_by: "qwen" })) });
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
        endpoints: ["/health", "/v1/models", "/v1/validate", "/v1/refresh", "/v1/chat/completions", "/v1/images/generations", "/v1/images/edits", "/v1/videos/generations"],
        time: new Date().toISOString(),
      });

    if (path === "/v1/models") return handleModels(env);

    // everything below is gated when PROXY_KEY is set
    const gate = checkGate(req, env);
    if (gate.gateError) return oerr("Invalid proxy key", "authentication_error", 401);
    const qwenOverride = req.headers.get("X-Qwen-Token") || (env.PROXY_KEY ? "" : gate.bearer);

    if (path === "/v1/validate" || path === "/validate") return handleValidate(req, env);
    if (path === "/v1/refresh" || path === "/refresh") return handleRefresh(req, env);
    if (path === "/v1/chat/completions" && req.method === "POST") return handleChat(req, env, qwenOverride);
    if (path === "/v1/images/generations" && req.method === "POST") return handleMedia(req, env, qwenOverride, "t2i");
    if (path === "/v1/images/edits" && req.method === "POST") return handleMedia(req, env, qwenOverride, "image_edit");
    if (path === "/v1/videos/generations" && req.method === "POST") return handleMedia(req, env, qwenOverride, "t2v");
    if (path === "/v1/chats/delete")
      return oerr("Chat deletion is not exposed by the upstream web API; manage chats at chat.qwen.ai", "not_supported", 501);

    return oerr(`Unknown route ${url.pathname}`, "not_found", 404);
  },
};
