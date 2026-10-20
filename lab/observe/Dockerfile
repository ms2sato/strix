# 観測・疎通テスト用のユーティリティイメージ（ADR 0001 の初回起動観測と疎通テストで使う）。
# 本番の構成には含めない。lab/compose.observe.yml からのみ参照する。
#
# debian bookworm-20260918-slim  pushed 2026-09-19  linux/amd64,arm64
FROM debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates tcpdump dnsutils curl netcat-openbsd iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10002 observe && useradd -u 10002 -g 10002 -m observe
USER observe
CMD ["sleep", "infinity"]
