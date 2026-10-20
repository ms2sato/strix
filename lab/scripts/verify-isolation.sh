#!/usr/bin/env bash
# pentest-lab の疎通テスト（到達可 / 不可）。docs/safe-notes.md §6 手順 5。
# lab/compose.yml（+ compose.observe.yml --profile observe）が up の状態で実行する。
#
#   lab/scripts/verify-isolation.sh
#
# nettest-lab はサンドボックス相当の位置（pentest-lab）、nettest-ctl は pentest-ctl の位置から確認する。
# サンドボックス本体は Strix が動的に作るため、ここでは同じネットワーク上の素のコンテナで代用する。
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
C="docker compose -f compose.yml -f compose.observe.yml"
PROXY=http://10.188.2.10:3128
pass=0; fail=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
ng(){ echo "  FAIL  $1  [$2]"; fail=$((fail+1)); }
inc(){ svc=$1; shift; $C exec -T "$svc" sh -c "$*" 2>&1; }
expect_fail(){ out=$(inc "$2" "$3"); if [ $? -ne 0 ]; then ok "$1"; else ng "$1" "到達できた: $(echo "$out"|head -c 120)"; fi; }
expect_ok(){ out=$(inc "$2" "$3"); if [ $? -eq 0 ]; then ok "$1"; else ng "$1" "$(echo "$out"|head -c 120)"; fi; }
# allowlist 外 / 非許可の送信元で CONNECT が 403 になることを確認する
expect_403(){ out=$(inc "$2" "curl -sS -g --max-time 10 -x $PROXY -o /dev/null -w '%{http_code}' '$3'"); if echo "$out" | grep -q 403; then ok "$1"; else ng "$1" "$(echo "$out"|tail -c 120)"; fi; }

echo "== pentest-lab（サンドボックス相当）→ 外は塞がれている"
expect_fail "nettest-lab → インターネット https://1.1.1.1 直接"        nettest-lab "curl -s --max-time 5 https://1.1.1.1/ >/dev/null"
expect_fail "nettest-lab → 外部 DNS 1.1.1.1:53 直接"                   nettest-lab "nslookup example.com 1.1.1.1 >/dev/null 2>&1 || nc -z -w3 1.1.1.1 53"
expect_fail "nettest-lab → 169.254.169.254（メタデータ）"             nettest-lab "curl -s --max-time 5 http://169.254.169.254/ >/dev/null"
expect_fail "nettest-lab → 外部ドメインの名前解決"                     nettest-lab "getent hosts example.com"
expect_fail "nettest-lab → squid の名前解決（pentest-ctl は見えない）"  nettest-lab "getent hosts egress-proxy"
expect_fail "nettest-lab → squid 10.188.2.10:3128（他ネットワーク）"  nettest-lab "nc -z -w3 10.188.2.10 3128"

echo "== pentest-lab → 検査対象には届く"
expect_ok "nettest-lab → target-web:8080"                            nettest-lab "curl -sf --max-time 5 http://target-web:8080/ >/dev/null"

echo "== egress プロキシ: 利用元と宛先の制限"
expect_403 "nettest-ctl（strix-cli 以外の送信元）→ api.anthropic.com は拒否" nettest-ctl "https://api.anthropic.com/v1/models"
expect_403 "nettest-ctl → IP リテラル 1.1.1.1:443 は拒否"            nettest-ctl "https://1.1.1.1/"

echo; echo "RESULT: PASS=$pass FAIL=$fail"
[ $fail -eq 0 ]
