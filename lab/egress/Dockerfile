# egress プロキシ（squid）。Debian bookworm の squid 5.7 を apt（Debian 署名で検証）から入れる。
# ubuntu/squid 等のサードパーティイメージを使わないのは、押された日が新しすぎる（<7 日）か
# 古すぎる（セキュリティ更新が入っていない）かのどちらかだったため。
#
# debian bookworm-20260918-slim  pushed 2026-09-19  linux/amd64,arm64
FROM debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update \
    && apt-get install -y --no-install-recommends squid ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/spool/squid /var/log/squid /run/squid \
    && chown -R proxy:proxy /var/spool/squid /var/log/squid /run/squid
USER proxy
EXPOSE 3128
# -N: フォアグラウンド  -d 1: 起動ログを stderr へ
CMD ["squid", "-N", "-d", "1", "-f", "/etc/squid/squid.conf"]
