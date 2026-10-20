#!/bin/bash
# strix-lab サンドボックスのエントリポイント。
#
# 上流のイメージは CA の秘密鍵をビルド時に生成してイメージに残すため、そのイメージを使う全員が同じ鍵を持つ
# （docs/audit-notes.md §2.4）。ここではコンテナ起動時に CA を生成し、コンテナごとに別の鍵にする。
# その後は上流の docker-entrypoint.sh（UID の付け替え、Caido の起動、プロキシ設定）をそのまま実行する。
#
# 上流の entrypoint は UID を付け替えた後に "$0" を再実行する。"$0" は docker-entrypoint.sh を指すので、
# CA の生成は 1 回だけ行われる。
set -euo pipefail

CERT_DIR=/app/certs

if [ ! -f "${CERT_DIR}/ca.p12" ]; then
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/ca.key"
  openssl req -x509 -new -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -days 30 \
    -subj "/O=strix-lab/CN=strix-lab sandbox CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign"
  openssl pkcs12 -export \
    -out "${CERT_DIR}/ca.p12" \
    -inkey "${CERT_DIR}/ca.key" \
    -in "${CERT_DIR}/ca.crt" \
    -passout pass:"" \
    -name "strix-lab sandbox CA"
  chmod 0644 "${CERT_DIR}/ca.crt"
  # コンテナ内のシステム trust store に入れる（上流 containers/Dockerfile:85-86 と同じ効果。ホストには入れない）
  sudo cp "${CERT_DIR}/ca.crt" /usr/local/share/ca-certificates/strix-lab-ca.crt
  sudo update-ca-certificates >/dev/null
fi

# 上の CA 生成で設定した umask 077 は exec 後の上流 docker-entrypoint.sh にも引き継がれる。
# すると上流が `sudo tee /etc/profile.d/proxy.sh` で作る proxy 設定が 0600(root) になり、
# UID 付け替え後の非 root ユーザーが読めず、上流の `. /etc/profile.d/proxy.sh`（set -e 下）が
# "Permission denied" で失敗 → コンテナが起動直後に exit 1 で落ちる（段階2 調査で特定・再現）。
# 通常の umask に戻してから上流へ渡す。
umask 022

# openai-agents SDK はランタイムヘルパーを固定の共有パス /tmp/openai-agents/bin に導入する。
# サンドボックス内の exec は root（ステージング / アカウント provision）とエージェント uid が混在するため、
# このディレクトリを最初に作ったユーザー以外は 755 のままだと書けず、
# "cannot create .../bin/<helper>.tmp: Permission denied" でエージェントが crash する（段階2 調査で特定・再現）。
# 全 exec ユーザーがヘルパーを導入できるよう、起動時に world-writable で用意しておく（使い捨てサンドボックス内のみ）。
mkdir -p /tmp/openai-agents/bin
chmod 0777 /tmp/openai-agents /tmp/openai-agents/bin

exec /usr/local/bin/docker-entrypoint.sh "$@"
