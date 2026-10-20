# Strix サンドボックスイメージ（自前ビルド・版固定）。docs/safe-notes.md §2。
# 上流 containers/Dockerfile を置き換える。上流のファイルは変更しない。
#
# ビルドコンテキストはリポジトリのルート:
#   docker compose -f lab/compose.yml --profile build-only build sandbox-image
#
# 方針
# - ベースイメージはすべて tag@digest で固定する。
# - `curl | sh`、`@latest`、HEAD のままの git clone は使わない。
# - 直接取得するバイナリは版を固定し、sha256 を照合する（ARG の SHA256 と一致しなければビルド失敗）。
# - Go ツールは `go install <module>@<版>`。モジュールの中身は sum.golang.org で検証される。
# - npm は版を明示し、NPM_CONFIG_IGNORE_SCRIPTS=true の下で入れる。
# - apt は Debian の署名で検証される公式リポジトリだけを使う（ARTEX-safe と同じ扱い）。
# - CA 秘密鍵はイメージに入れない。コンテナ起動時に lab-entrypoint.sh が生成する（コンテナごとに別の鍵）。
# - 組み立て（取得済みファイルの配置）は RUN --network=none で行う。
#
# 段階1は、Strix の動作に必須のもの（Caido、Chromium + agent-browser、Python venv）と、
# 基本的な検査ツールに絞る。上流イメージとの差（入れていないツール）は lab/README.md に一覧する。
#
# 版・digest・sha256 は手順 3 で確定済み（lab/README.md「取得物の一覧」）。
# 注: `# syntax=` ディレクティブはフロントエンドを digest なしで取得するため書かない。

# ---- 固定するベースイメージ（tag@digest） --------------------------------------
# Python 3.12（caido-sdk-client と Strix の caido_api.py 用）。CLI と同じイメージにそろえる
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# node 24.20.0（ARTEX-safe lab/Dockerfile で選定済み。pushed 2026-08-27）
ARG NODE_IMAGE=node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e
# golang 1.26.9（ARTEX-safe lab/Dockerfile で選定済み。pushed 2026-10-08）
ARG GO_IMAGE=golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c

# ---- 版を固定する取得物（一覧は lab/README.md「取得物の一覧」） -------------------
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG SUBFINDER_VERSION=v2.17.0
ARG FFUF_VERSION=v2.3.0
ARG GOVULNCHECK_VERSION=v1.9.0
ARG CAIDO_VERSION=0.56.0
ARG CAIDO_SHA256_AMD64=1bc13f1ad558cd333924890d9d09b73f1cdf6726b7855265cd4c4ddece0211d3
ARG CAIDO_SHA256_ARM64=5fe8c37ac0435ce5924014cf035902686051be86831824744e435636a62d3689
ARG TRIVY_VERSION=0.76.0
ARG TRIVY_SHA256_AMD64=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
ARG TRIVY_SHA256_ARM64=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG NUCLEI_TEMPLATES_VERSION=10.5.0
ARG NUCLEI_TEMPLATES_SHA256=80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41
ARG AGENT_BROWSER_VERSION=0.26.0
# white-box 用: 秘密情報スキャナ（Go リリースバイナリ。trivy/gitleaks と同じく sha256 照合）
ARG TRUFFLEHOG_VERSION=3.99.2
ARG TRUFFLEHOG_SHA256_AMD64=3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4
ARG TRUFFLEHOG_SHA256_ARM64=929b81efffca752eafd58bf6f17bf725d354f338636a7bbbee65c086d2f9ddf3

# =============================================================================
# 1. Go ツール（ネットワークあり: proxy.golang.org + sum.golang.org 検証）
# =============================================================================
FROM ${GO_IMAGE} AS go-tools
ARG NUCLEI_VERSION
ARG HTTPX_VERSION
ARG KATANA_VERSION
ARG SUBFINDER_VERSION
ARG FFUF_VERSION
ARG GOVULNCHECK_VERSION
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOSUMDB=sum.golang.org \
    GOPROXY=https://proxy.golang.org \
    GOFLAGS=-trimpath \
    GOBIN=/out/bin
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install github.com/ffuf/ffuf/v2@${FFUF_VERSION} \
 && go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}

# =============================================================================
# 2. 版固定バイナリとテンプレートの取得（ネットワークあり、sha256 を照合）
# =============================================================================
FROM ${PY_IMAGE} AS fetch
ARG TARGETARCH
ARG CAIDO_VERSION
ARG CAIDO_SHA256_AMD64
ARG CAIDO_SHA256_ARM64
ARG TRIVY_VERSION
ARG TRIVY_SHA256_AMD64
ARG TRIVY_SHA256_ARM64
ARG GITLEAKS_VERSION
ARG GITLEAKS_SHA256_AMD64
ARG GITLEAKS_SHA256_ARM64
ARG NUCLEI_TEMPLATES_VERSION
ARG NUCLEI_TEMPLATES_SHA256
ARG TRUFFLEHOG_VERSION
ARG TRUFFLEHOG_SHA256_AMD64
ARG TRUFFLEHOG_SHA256_ARM64
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
# fetch <url> <sha256> <出力ファイル>: 取得して照合する。一致しなければ失敗
RUN set -eu; \
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$3" "$1"; echo "$2  $3" | sha256sum -c -; }; \
    case "${TARGETARCH}" in \
      amd64) CAIDO_ARCH=x86_64;  CAIDO_SHA=${CAIDO_SHA256_AMD64}; TRIVY_ARCH=Linux-64bit;  TRIVY_SHA=${TRIVY_SHA256_AMD64}; GL_ARCH=x64;   GL_SHA=${GITLEAKS_SHA256_AMD64}; TH_ARCH=amd64; TH_SHA=${TRUFFLEHOG_SHA256_AMD64} ;; \
      arm64) CAIDO_ARCH=aarch64; CAIDO_SHA=${CAIDO_SHA256_ARM64}; TRIVY_ARCH=Linux-ARM64;  TRIVY_SHA=${TRIVY_SHA256_ARM64}; GL_ARCH=arm64; GL_SHA=${GITLEAKS_SHA256_ARM64}; TH_ARCH=arm64; TH_SHA=${TRUFFLEHOG_SHA256_ARM64} ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    fetch "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" "${CAIDO_SHA}" caido.tgz; \
    fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" "${TRIVY_SHA}" trivy.tgz; \
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" "${GL_SHA}" gitleaks.tgz; \
    fetch "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" "${TH_SHA}" trufflehog.tgz; \
    fetch "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" "${NUCLEI_TEMPLATES_SHA256}" nuclei-templates.tgz; \
    mkdir -p /out/bin /out/nuclei-templates; \
    tar -xzf caido.tgz -C /out/bin; \
    tar -xzf trivy.tgz -C /out/bin trivy; \
    tar -xzf gitleaks.tgz -C /out/bin gitleaks; \
    tar -xzf trufflehog.tgz -C /out/bin trufflehog; \
    tar -xzf nuclei-templates.tgz -C /out/nuclei-templates --strip-components=1; \
    chmod 0755 /out/bin/*

# =============================================================================
# 3. npm（ネットワークあり: registry.npmjs.org のみ。版固定、install script を実行しない）
# =============================================================================
FROM ${NODE_IMAGE} AS npm-tools
ARG AGENT_BROWSER_VERSION
ENV NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_MIN_RELEASE_AGE=7 \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_PREFIX=/out/npm-global
# 要確認: agent-browser が install script なしで動くか（手順 3 で `agent-browser doctor --offline --quick` を確認する）
RUN npm install -g "agent-browser@${AGENT_BROWSER_VERSION}" \
 && npm cache clean --force

# =============================================================================
# 4. Python venv（ネットワークあり: pypi.org のみ。requirements.lock のハッシュと一致するものだけ）
# =============================================================================
FROM ${PY_IMAGE} AS py-venv
COPY lab/sandbox/requirements.lock /tmp/requirements.lock
RUN python -m venv /app/.venv \
 && /app/.venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.lock

# =============================================================================
# 4b. white-box 用 SAST venv（pypi のみ。requirements-sast.lock のハッシュと一致するものだけ）
#     caido 用 /app/.venv とは分離する（依存の衝突回避）。bandit と semgrep を入れる。
# =============================================================================
FROM ${PY_IMAGE} AS py-sast
COPY lab/sandbox/requirements-sast.lock /tmp/requirements-sast.lock
RUN python -m venv /opt/sast \
 && /opt/sast/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-sast.lock

# =============================================================================
# 5. 実行イメージ
# =============================================================================
FROM ${PY_IMAGE} AS runtime
LABEL description="Strix sandbox (strix-lab, pinned self-build)"

# apt: Debian bookworm の署名付きリポジトリから。上流イメージ（Kali）のうち Debian にあるものを入れる
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      sudo ca-certificates openssl curl wget git jq ripgrep unzip xz-utils \
      procps iproute2 iputils-ping dnsutils netcat-openbsd whois \
      file xxd less gdb \
      nmap sqlmap \
      chromium fonts-liberation libnss3-tools libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

# 上流と同じ利用者・パスを再現する（Strix のプロンプトと caido_bootstrap が前提にしている）
# sudo は上流どおり付与する（Strix は "sudo available" を前提にする。隔離はコンテナの外で強制する）
RUN useradd -m -s /bin/bash pentester \
 && usermod -aG sudo pentester \
 && echo "pentester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/pentester \
 && chmod 0440 /etc/sudoers.d/pentester \
 && touch /home/pentester/.hushlogin \
 && mkdir -p /home/pentester/tools/wordlists /app/certs /workspace /opt/strix-python \
 && chown -R pentester:pentester /home/pentester /app /workspace

# Node（node イメージからランタイムだけをコピー）
COPY --from=npm-tools /usr/local/bin/node /usr/local/bin/node
COPY --from=npm-tools /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN --network=none ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=npm-tools --chown=pentester:pentester /out/npm-global /home/pentester/.npm-global

# Go ツールと版固定バイナリ
COPY --from=go-tools --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/
COPY --from=fetch /out/bin/caido-cli /usr/local/bin/caido-cli
COPY --from=fetch /out/bin/trivy /usr/local/bin/trivy
COPY --from=fetch /out/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=fetch /out/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=fetch --chown=pentester:pentester /out/nuclei-templates /home/pentester/nuclei-templates

# Python venv と Strix の caido_api（上流 containers/Dockerfile:254-255 と同じ配置）
COPY --from=py-venv --chown=pentester:pentester /app/.venv /app/.venv
# white-box 用 SAST venv（bandit / semgrep）。PATH に /opt/sast/bin を足す
COPY --from=py-sast --chown=pentester:pentester /opt/sast /opt/sast

# semgrep の Ruby ローカルルール（オフライン用。egress deny-all で semgrep.dev を引けないため同梱）。
# 自作の curated ルール（版管理・外部 fetch なし）。使い方: semgrep --config /opt/sast-rules/semgrep
COPY --chown=pentester:pentester lab/sandbox/semgrep-rules /opt/sast-rules/semgrep
COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py

# エントリポイント: CA を起動時に生成してから、上流の entrypoint を実行する
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY lab/sandbox/lab-entrypoint.sh /usr/local/bin/lab-entrypoint.sh

RUN --network=none set -eu; \
    chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/lab-entrypoint.sh; \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"; \
    # login shell でも PATH を維持する（上流 containers/Dockerfile:262-263 と同じ）
    LAB_PATH='/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:/opt/sast/bin'; \
    echo "export PATH=\"${LAB_PATH}:\$PATH\"" >> /home/pentester/.bashrc; \
    echo "export PATH=\"${LAB_PATH}:\$PATH\"" >> /home/pentester/.profile; \
    # agent-browser の設定（上流 containers/Dockerfile:116-133 と同じ値）
    { \
      echo 'export AGENT_BROWSER_EXECUTABLE_PATH="${AGENT_BROWSER_EXECUTABLE_PATH:-/usr/bin/chromium}"'; \
      echo 'export AGENT_BROWSER_ARGS="${AGENT_BROWSER_ARGS:---disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US}"'; \
      echo 'export AGENT_BROWSER_SCREENSHOT_DIR="${AGENT_BROWSER_SCREENSHOT_DIR:-/workspace/.agent-browser-screenshots}"'; \
      echo 'export AGENT_BROWSER_IDLE_TIMEOUT_MS="${AGENT_BROWSER_IDLE_TIMEOUT_MS:-180000}"'; \
    } > /etc/profile.d/agent-browser.sh; \
    chmod 0644 /etc/profile.d/agent-browser.sh

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:/opt/sast/bin:$PATH" \
    VIRTUAL_ENV=/app/.venv \
    PYTHONPATH=/opt/strix-python \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium \
    AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US" \
    AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots \
    AGENT_BROWSER_IDLE_TIMEOUT_MS=180000 \
    # 同梱テンプレートを使い、実行時の更新確認・自動更新をしない（internal ネットワークでも遮断される）
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    NUCLEI_TEMPLATES_DIR=/home/pentester/nuclei-templates \
    # npm を実行時に使われても install script を走らせない
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_PREFIX=/home/pentester/.npm-global

USER pentester
WORKDIR /workspace
ENTRYPOINT ["lab-entrypoint.sh"]
