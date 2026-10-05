#!/usr/bin/env node
/**
 * Keepalive loop: every 10 minutes, ask the worker to mint a fresh token
 * (it uses its QWEN_AUTH session cookies), then persist the fresh values
 * back to Worker secrets via the Cloudflare API when CF credentials exist.
 *
 * Runs ~5.5h (33 iterations); the workflow schedule starts a new run every
 * 5h with cancel-in-progress, so loops overlap and coverage never breaks.
 *
 * Logging rule: metadata only (refreshed / exp / rotated). NEVER print
 * tokens, jars, or response bodies — GitHub masks secrets, but we simply
 * never emit them.
 */
const WORKER_URL = (process.env.WORKER_URL || "").replace(/\/+$/, "");
const PROXY_KEY = process.env.PROXY_KEY || "";
const CF_API_TOKEN = process.env.CF_API_TOKEN || "";
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID || "";
const CF_WORKER_NAME = process.env.CF_WORKER_NAME || "";

const ITERATIONS = 33;
const INTERVAL_MS = 10 * 60 * 1000;

if (!WORKER_URL || !PROXY_KEY) {
  console.error("missing WORKER_URL or PROXY_KEY secrets");
  process.exit(1);
}

async function cfPutSecret(name, text) {
  const r = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts/${CF_WORKER_NAME}/secrets`,
    {
      method: "PUT",
      headers: { Authorization: `Bearer ${CF_API_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name, text, type: "secret_text" }),
    },
  );
  if (!r.ok) throw new Error(`cf secret ${name}: http ${r.status}`);
}

for (let i = 1; i <= ITERATIONS; i++) {
  const tick = new Date().toISOString();
  try {
    const r = await fetch(`${WORKER_URL}/v1/refresh`, {
      headers: { Authorization: `Bearer ${PROXY_KEY}` },
    });
    const j = await r.json();
    console.log(
      `[${tick}] iter=${i} http=${r.status} refreshed=${j.refreshed === true} ` +
      `expires_at=${j.expires_at ?? "-"} rotated=${j.refresh_cookie_rotated === true}`,
    );
    if (j.refreshed === true && CF_API_TOKEN && CF_ACCOUNT_ID && CF_WORKER_NAME) {
      await cfPutSecret("QWEN_TOKENS", j.access_token);
      if (j.refresh_cookie_rotated === true && j.auth_jar) {
        await cfPutSecret("QWEN_AUTH", j.auth_jar);
      }
      console.log(`[${tick}] iter=${i} secrets persisted`);
    } else if (j.refreshed === true) {
      console.log(`[${tick}] iter=${i} no CF credentials; worker cache warmed`);
    } else {
      console.log(`[${tick}] iter=${i} detail=${String(j.error?.message || j.note || "").slice(0, 120)}`);
    }
  } catch (e) {
    console.log(`[${tick}] iter=${i} FAILED ${String(e?.message || e).slice(0, 120)}`);
  }
  if (i < ITERATIONS) await new Promise((res) => setTimeout(res, INTERVAL_MS));
}
console.log("loop complete");
