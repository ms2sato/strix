#!/usr/bin/env bash
# lab/ 配下の固定方針を機械的に確認する（ARTEX-safe lab/scripts/check-pins.sh を流用）。
#   - `@latest` を使っていない
#   - `curl … | sh` / `| bash` を使っていない
#   - FROM / compose image: が digest（@sha256:）で固定されている（ローカルビルドの strix-lab/* を除く）
#   - PIN_ME（未確定の placeholder）が残っていない
#   - digest なしでフロントエンドを取得する `# syntax=` ディレクティブがない
# コメント行は除外し、本スクリプト自身は対象外。
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
fail=0
files() { find . -type f \( -name Dockerfile -o -name '*.yml' -o -name '*.conf' -o -name '*.sh' -o -name '*.example' -o -name '*.lock' -o -name '*.in' \) -not -path './scripts/*' | sort; }
code() { for f in $(files); do grep -nE '.' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | sed "s|^|$f:|"; done; }

echo "== @latest"
if code | grep -E '@latest'; then fail=1; else echo "  none"; fi

echo "== curl | sh / bash"
if code | grep -E 'curl[^|]*\|[[:space:]]*(ba)?sh\b'; then fail=1; else echo "  none"; fi

echo "== PIN_ME placeholder"
if code | grep -E 'PIN_ME'; then fail=1; else echo "  none"; fi

echo "== FROM without digest"
bad=0
while IFS= read -r rec; do
  f=${rec%%:*}; rest=${rec#*:}; line=${rest#*:}
  ref=$(sed -E 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+).*/\2/' <<<"$line")
  if [[ "$ref" == \$* ]]; then
    var=$(sed -E 's/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/\1/' <<<"$ref")
    grep -qE "^ARG[[:space:]]+${var}=[^[:space:]]+@sha256:[0-9a-f]{64}" "$f" || { echo "  $f: ARG ${var} に digest がない"; bad=1; }
  elif grep -qE "AS[[:space:]]+${ref}([[:space:]]|$)" "$f"; then
    : # 同ファイル内のステージ参照
  elif [[ "$ref" != *@sha256:* ]]; then
    echo "  $f: $line"; bad=1
  fi
done < <(code | grep -E ':FROM[[:space:]]')
[ "$bad" = 0 ] && echo "  all pinned" || fail=1

echo "== compose image: without digest"
if code | grep -E ':[[:space:]]+image:' | grep -vE '@sha256:[0-9a-f]{64}' | grep -vE 'image:[[:space:]]+strix-lab/'; then fail=1; else echo "  all pinned (strix-lab/* はローカルビルド)"; fi

echo "== docker/dockerfile syntax directive"
if for f in $(files); do grep -nE '^#[[:space:]]*syntax=' "$f" | sed "s|^|$f:|"; done | grep .; then fail=1; else echo "  none"; fi

[ "$fail" = 0 ] && echo "RESULT: OK" || echo "RESULT: NG（PIN_ME や未固定が残っている間は NG が正常。手順 3 で固定する）"
exit $fail
