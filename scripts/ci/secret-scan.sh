#!/usr/bin/env bash
# 비밀값 유출 검사 — gitleaks 를 **버전·체크섬 고정**으로 받아 실행한다(서드파티 액션 금지 — dybros-app 규칙과 동일).
#   ① 자가시험: security/secret-fixture/ 의 가짜 토큰을 못 잡으면 도구가 고장난 것 → 실패(통과가 아니라 미검증)
#   ② 본검사: 작업트리 전체(gitleaks dir) — 설정 security/gitleaks.toml (fixture 폴더는 본검사에서 제외)
#   ③ PR 이면 추가로 커밋 범위(gitleaks git)도 본다 — 작업트리에서 지워진 비밀이 이력에 남는 경우
# 종료코드 1 = 게이트 실패.
set -euo pipefail
VER="8.30.1"
SHA_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SHA_ARM="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) F="linux_x64"; SHA="$SHA_X64";; aarch64|arm64) F="linux_arm64"; SHA="$SHA_ARM";; *) echo "::error::지원하지 않는 아키텍처 $ARCH"; exit 1;; esac
DIR="${RUNNER_TEMP:-/tmp}/gitleaks-$VER"; mkdir -p "$DIR"
if [ ! -x "$DIR/gitleaks" ]; then
  curl -sSL --retry 3 -o "$DIR/gl.tgz" "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/gitleaks_${VER}_${F}.tar.gz"
  echo "$SHA  $DIR/gl.tgz" | sha256sum -c - >/dev/null || { echo "::error::gitleaks 체크섬 불일치 — 실행하지 않는다"; exit 1; }
  tar -xzf "$DIR/gl.tgz" -C "$DIR" gitleaks
fi
GL="$DIR/gitleaks"; "$GL" version

# ① 자가시험 — 기본 규칙으로 fixture 를 스캔해 **반드시 1건 이상** 잡혀야 한다
set +e; "$GL" dir security/secret-fixture --no-banner --exit-code 7 --redact >/dev/null 2>&1; RC=$?; set -e
[ "$RC" -eq 7 ] || { echo "::error::자가시험 실패 — fixture 의 가짜 토큰을 잡지 못했다(rc=$RC). 도구 미검증 상태로 통과시키지 않는다"; exit 1; }
echo "✓ 자가시험: fixture 탐지됨"

# ② 본검사(작업트리) — 실패하면 **무엇이 어디서** 걸렸는지(파일·규칙·줄, 값은 가림) 로그에 남긴다.
#   「leaks found: 1」만으로는 fixture 오탐인지 실제 유출인지 구분할 수 없다(실측 2026-11-01 run 41261554251).
REPORT="${RUNNER_TEMP:-/tmp}/gitleaks-dir.json"
set +e; "$GL" dir . --no-banner --redact --config security/gitleaks.toml --exit-code 1 --report-format json --report-path "$REPORT"; RC=$?; set -e
if [ "$RC" -ne 0 ]; then
  echo "::error::작업트리에서 비밀값 후보 발견 — 아래 파일·규칙·줄을 확인한다(값은 가림)"
  if command -v jq >/dev/null && [ -s "$REPORT" ]; then
    jq -r '.[] | "  \(.File):\(.StartLine)  rule=\(.RuleID)  지문=\(.Fingerprint)  \(.Description)"' "$REPORT"
    echo "  오탐이면 .gitleaksignore 에 지문 한 줄 + PR 보안 검증 기록에 사유. 실제 비밀이면 교체(revoke) 후 이력 정리."
  else
    cat "$REPORT" 2>/dev/null | head -c 4000
  fi
  exit 1
fi
echo "✓ 작업트리: 유출 없음"

# ③ PR 커밋 범위(이력) — base 가 주어졌을 때만
if [ -n "${GITLEAKS_BASE_SHA:-}" ] && [ -n "${GITLEAKS_HEAD_SHA:-}" ]; then
  REPORT2="${RUNNER_TEMP:-/tmp}/gitleaks-git.json"
  set +e; "$GL" git . --no-banner --redact --config security/gitleaks.toml --exit-code 1 --log-opts="${GITLEAKS_BASE_SHA}..${GITLEAKS_HEAD_SHA}" --report-format json --report-path "$REPORT2"; RC=$?; set -e
  if [ "$RC" -ne 0 ]; then
    echo "::error::커밋 범위에서 비밀값 후보 발견(값은 가림)"
    command -v jq >/dev/null && [ -s "$REPORT2" ] && jq -r '.[] | "  \(.File):\(.StartLine)  commit=\(.Commit[0:7])  rule=\(.RuleID)"' "$REPORT2"
    exit 1
  fi
  echo "✓ 커밋 범위 ${GITLEAKS_BASE_SHA:0:7}..${GITLEAKS_HEAD_SHA:0:7}: 유출 없음"
fi
