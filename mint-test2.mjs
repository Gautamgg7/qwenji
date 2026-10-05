import { readFileSync } from "node:fs";
import { upstreamHeaders } from "./src/antibot.js";
const d = readFileSync(".dev.vars", "utf8");
const raw = (d.match(/QWEN_AUTH="([\s\S]*?)"/) || [, ""])[1];
const jars = raw.replace(/\\n/g, "\n").split(/[\r\n;|]+/).filter((j) => j.trim().length > 20);
console.log("JARS_FOUND:", jars.length);
jars.forEach((j, i) => console.log(`  jar${i}: len=${j.length} starts=${j.slice(0, 25)}`));
const h = await upstreamHeaders(null);
delete h.Cookie;
delete h.Authorization;
for (let i = 0; i < Math.min(2, jars.length); i++) {
  const jar = jars[i];
  const res = await fetch("https://auth.qwen.ai/api/v2/auths/refresh", {
    headers: { ...h, Cookie: jar, "x-request-origin": "https://chat.qwen.ai", Timezone: new Date().toString(), Referer: "https://chat.qwen.ai/", Origin: "https://chat.qwen.ai" },
  });
  const body = (await res.text()).slice(0, 200);
  console.log(`JAR${i}_STATUS: ${res.status} BODY: ${body.slice(0, 150)}`);
}
