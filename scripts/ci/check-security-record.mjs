#!/usr/bin/env node
// 보안 ⓪ 검증 기록 게이트 — dybros-app scripts/ci/check-security-record.mjs(PR #330)를 이 저장소용으로 옮긴 것.
// 관련 경로는 security/gate.json 의 recordPaths(정규식)에서 읽는다. 「비어 있음」만 잡고 내용 판정은 사람 몫.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const event = process.env.GITHUB_EVENT_NAME ?? "";
if (event !== "pull_request") { console.log(`::notice::보안 검증 기록 검사 생략 — PR 이벤트가 아님(${event || "로컬"})`); process.exit(0); }
const cfg = JSON.parse(readFileSync("security/gate.json", "utf8"));
const base = process.env.GITHUB_BASE_REF || "main";
let files = [];
try { files = execFileSync("git", ["diff", "--name-only", `origin/${base}...HEAD`], { encoding: "utf8" }).split("\n").filter(Boolean); }
catch (e) { console.error("::error::변경 파일을 구하지 못했다(머지베이스 없음?) — 미검증은 통과가 아니다\n" + e.message); process.exit(1); }
const RELATED = new RegExp(cfg.recordPaths);
const hit = files.filter((f) => RELATED.test(f));

const body = (process.env.PR_BODY ?? "").replace(/\r/g, "");
const m = body.match(/^##\s*보안 검증 기록[^\n]*\n([\s\S]*?)(?=^##\s|(?![\s\S]))/m);
const section = m ? m[1] : "";
const rows = section.split("\n").filter((l) => /^\|/.test(l) && !/^\|\s*-{3,}/.test(l) && !/검사 대상/.test(l));
const filled = rows.filter((l) => { const c = l.split("|").slice(1, -1).map((x) => x.trim()); return c.length >= 4 && c.slice(0, 4).every((x) => x.length > 0); });
const na = /해당 없음[^\n]{2,}/.test(section);
console.log(`관련 변경: ${hit.length ? "예" : "아니오"} (경로 ${hit.length}건) · 기록: 절 ${m ? "있음" : "없음"} · 채워진 행 ${filled.length} · 해당없음+사유 ${na ? "있음" : "없음"}`);
for (const f of hit.slice(0, 20)) console.log(`  - ${f}`);
if (hit.length && !(filled.length || na)) {
  console.error("::error::보안 검증 기록 누락 — 관련 경로를 건드린 PR 은 본문 「## 보안 검증 기록」 표(검사 대상·실행 결과·증거 위치·남은 미확인)를 채우거나 「해당 없음 — 사유」를 적어야 한다.");
  process.exit(1);
}
console.log(hit.length ? "✓ 관련 변경 — 기록 있음(내용 판정은 사람)" : "✓ 관련 변경 아님 — 기록 불요");
