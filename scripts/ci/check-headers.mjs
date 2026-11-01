#!/usr/bin/env node
// 보안 ③ 응답 헤더 검사 — dybros-app check-headers.mjs(PR #330)를 이 저장소용으로 옮긴 것.
// security/gate.json 의 headers.mode 로 방식을 고른다. 값은 정확히 일치해야 한다(포함 비교 금지).
//   next   : `next start` 를 띄워 경로별 실제 응답 헤더를 본다(빌드 산출물 필요)
//   vercel : 정적 사이트 — vercel.json headers 선언을 본다(빌드·서버가 없다)
//   worker : Cloudflare Pages 고급 모드 — _worker.js 를 가짜 ASSETS 로 불러 응답 헤더를 본다
//   meta   : GitHub Pages — 응답 헤더를 붙일 수 없어 HTML <meta name="referrer"> 만 본다
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const cfg = JSON.parse(readFileSync("security/gate.json", "utf8")).headers;
const must = cfg.must ?? {};
let fails = 0;
const cmp = (where, k, got) => {
  const want = must[k]; const ok = got != null && String(got).trim() === want;
  console.log(`${ok ? "✓" : "✗"} ${where} ${k}: ${got ?? "(없음)"}${ok ? "" : `  ← 기대 정확히: ${want}`}`);
  if (!ok) fails++;
};

if (cfg.mode === "next") {
  const PORT = 3977, BASE = `http://127.0.0.1:${PORT}`;
  const srv = spawn("npx", ["next", "start", "-p", String(PORT)], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NODE_ENV: "production" } });
  let log = ""; srv.stdout.on("data", (d) => (log += d)); srv.stderr.on("data", (d) => (log += d));
  const kill = () => { try { srv.kill("SIGTERM"); } catch {} }; process.on("exit", kill);
  let up = false;
  for (let i = 0; i < 60 && !up; i++) { await sleep(1000); try { const r = await fetch(BASE + "/", { redirect: "manual" }); up = r.status > 0; } catch {} }
  if (!up) { console.error("::error::next start 가 60초 안에 뜨지 않았다\n" + log.slice(-2000)); process.exit(1); }
  for (const p of cfg.paths) {
    let res; try { res = await fetch(BASE + p, { redirect: "manual" }); } catch (e) { console.error(`::error::${p} 요청 실패: ${e.message}`); fails++; continue; }
    for (const k of Object.keys(must)) cmp(`${p} [${res.status}]`, k, res.headers.get(k));
  }
  kill();
} else if (cfg.mode === "vercel") {
  const v = JSON.parse(readFileSync("vercel.json", "utf8"));
  const all = (v.headers ?? []).find((h) => h.source === "/(.*)");
  if (!all) { console.error("::error::vercel.json 에 전 경로(/(.*)) headers 블록이 없다"); process.exit(1); }
  const got = Object.fromEntries(all.headers.map((h) => [h.key.toLowerCase(), h.value]));
  for (const k of Object.keys(must)) cmp("vercel.json /(.*)", k, got[k]);
} else if (cfg.mode === "worker") {
  const w = (await import(pathToFileURL(process.cwd() + "/_worker.js").href)).default;
  const env = { ASSETS: { fetch: async () => new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }) } };
  for (const u of cfg.urls) {
    const r = await w.fetch(new Request(u), env);
    for (const k of Object.keys(must)) cmp(`${u} [${r.status}]`, k, r.headers.get(k));
  }
} else if (cfg.mode === "meta") {
  for (const f of cfg.files) {
    const html = readFileSync(f, "utf8");
    const m = html.match(/<meta\s+name="referrer"\s+content="([^"]*)"/i);
    cmp(f, "referrer-policy", m ? m[1] : null);
  }
} else { console.error(`::error::알 수 없는 headers.mode: ${cfg.mode}`); process.exit(1); }
console.log(fails === 0 ? "✅ 보안 헤더 검사 통과" : `❌ 보안 헤더 불일치 ${fails}건`);
process.exit(fails === 0 ? 0 : 1);
