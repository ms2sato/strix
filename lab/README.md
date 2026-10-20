# strix-lab — Strix を最小隔離で動かす環境

Strix（AI 自律ペンテストツール）を、外への経路がない Docker ネットワークで動かすための構成。
背景と判断は [../docs/audit-notes.md](../docs/audit-notes.md)（段階0 監査）と [../docs/safe-notes.md](../docs/safe-notes.md)（段階1 計画）を参照。

> **状態（2026-10-17）:** digest / 版 / sha256 は確定済み（`lab/scripts/check-pins.sh` は green）。
> フェーズ1（自前ビルド → deny-all で観測 → 隔離確認）まで実施。フェーズ2（Strix をダミー標的へ実走）は
> Anthropic キーが揃ってから別途承認。

## 構成

```
pentest-ctl  (internal: true / 10.188.2.0/24)  strix-cli(10.188.2.5), egress-proxy(10.188.2.10)
pentest-lab  (internal: true / 10.188.0.0/24)  strix-cli, strix-sandbox（Strix が作成）, target-web
pentest-edge (bridge / 10.188.1.0/24)          egress-proxy だけが外に出られる
```

- **サンドボックスと検査対象は pentest-ctl に参加しない** → squid（外への唯一の経路）に届かない。サンドボックスからの外向きはゼロ。
- **CLI の通信はすべて squid 経由**に強制され、許可は allowlist のドメイン（= `api.anthropic.com`）だけ。
- CLI は pentest-lab にも参加し、Strix が Caido（サンドボックスの IP:48080）に直接つなぐ方式が動く。

## 準備

1. `cp lab/.env.example lab/.env` して `LAB_UID` / `LAB_GID` / `DOCKER_GID` を自分の環境に合わせる。
   - `DOCKER_GID` は `getent group docker | cut -d: -f3`。
2. Anthropic の API キーを chmod 600 のファイルに置く（**チャットに貼らない。lab 専用・予算上限付きのキー**）。
   - 例: `install -m 600 /dev/stdin ~/.config/strix-lab/anthropic-key`（貼り付けて Ctrl-D）

## 使い方（手順 3 以降。すべて承認後）

```sh
# 3. ビルド（取得物の一覧は下記。supply-chain-guard の承認後に実行）
docker compose -f lab/compose.yml --profile build-only build sandbox-image
docker compose -f lab/compose.yml --profile cli build strix-cli
docker compose -f lab/compose.yml build egress-proxy

# 4. 観測つき起動（allowlist は空のまま）→ 誰がどこへ出ようとするかを squid ログで見る
docker compose -f lab/compose.yml -f lab/compose.observe.yml --profile observe up -d \
  egress-proxy target-web nettest-ctl nettest-lab
docker compose -f lab/compose.yml logs -f egress-proxy   # 別端末で

# Docker へのアクセスはオーバーレイで選ぶ（§3.3）。既定は sockproxy。
#   SOCK="-f lab/compose.sockproxy.yml"      # 既定（create 検査プロキシ。初回は未検証なので挙動を確認する）
#   SOCK="-f lab/compose.directsock.yml"     # フォールバック（Strix が動かないときだけ一時的に）
SOCK="-f lab/compose.sockproxy.yml"

export LLM_API_KEY=$(cat ~/.config/strix-lab/anthropic-key)
docker compose -f lab/compose.yml $SOCK --profile cli run --rm strix-cli \
  -t http://target-web:8080 --scan-mode quick --max-budget 5

# 5. 疎通テスト（到達可/不可）
lab/scripts/verify-isolation.sh

# 6. LLM を許可してスモークテスト
cp lab/egress/allowlist.llm.example lab/egress/allowlist.txt   # api.anthropic.com だけ
docker compose -f lab/compose.yml up -d --force-recreate egress-proxy
docker compose -f lab/compose.yml $SOCK --profile cli run --rm strix-cli \
  -t http://target-web:8080 --scan-mode quick --max-budget 5
```

目的は配管（CLI → sandbox → target-web → Anthropic → findings）の疎通確認。検出精度の評価は後段。

## 取得物の一覧（何を・どこから・どの版/digest）

2026-10-17 に確定（manifest/バイナリを取得してハッシュを記録しただけ。ビルド・up・image pull・install はしていない）。
`check-pins.sh` は green。

### ベースイメージ（tag@digest で固定）

| 用途 | イメージ@digest |
|---|---|
| CLI / sandbox / sockproxy / target-web | `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` |
| uv バイナリの供給元 | `ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336` |
| sandbox: Go ツールのビルド | `golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c`（ARTEX-safe 選定） |
| sandbox: Node ランタイム | `node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e`（ARTEX-safe 選定） |
| egress / observe | `debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`（ARTEX-safe 選定） |

digest は `docker buildx imagetools inspect <ref>`（index の digest。pull なし）で解決。

### CLI イメージ（lab/cli/Dockerfile）

| 取得物 | どこから | 固定方法 |
|---|---|---|
| Python 依存（Strix 本体の依存 120 個） | pypi.org | `uv.lock` の sha256（`uv sync --frozen`）。litellm は 1.101.0 固定 |
| uv 本体 | 上記 uv イメージ(0.13.1) | digest 固定イメージからバイナリをコピー |

Strix 自身は install しない（`--no-install-project`）。`docker` CLI は確認用スタブを置くだけ。

### サンドボックスイメージ（lab/sandbox/Dockerfile）

Go ツールの版は `proxy.golang.org/<module>/@latest`（`go install` が解決する経路）で取得:

| Go ツール | 版 |
|---|---|
| nuclei (`/v3`) | `v3.11.1` |
| httpx | `v1.12.0` |
| katana | `v1.8.0` |
| subfinder (`/v2`) | `v2.17.0` |
| ffuf (`/v2`) | `v2.3.0` |
| govulncheck (`golang.org/x/vuln`) | `v1.9.0` |

版固定 + sha256 照合のバイナリ/アーカイブ:

| 取得物 | 版 | sha256（amd64 / arm64） |
|---|---|---|
| caido-cli | 0.56.0 | `1bc13f1a…0211d3` / `5fe8c37a…2d3689` |
| trivy | 0.76.0 | `e24b1c51…45fe7` / `aab21e67…8f4c`（公式 checksums より） |
| gitleaks | 8.30.1 | `551f6fc8…470eb` / `e4a487ee…b4b080`（公式 checksums より） |
| trufflehog（white-box・秘密情報） | 3.99.2 | `3c7b0d1d…8deca4` / `929b81ef…9ddf3`（公式 checksums より） |
| nuclei-templates | 10.5.0 | `80fbabce…1f9a41`（tag アーカイブを取得して記録。※下記注意） |
| agent-browser（npm） | 0.26.0 | 版固定 + `ignore-scripts`（要動作確認） |
| Python venv（caido-sdk-client 0.2.0 ほか 34 個） | — | `lab/sandbox/requirements.lock`（`--require-hashes`、`--universal` で amd64/arm64 両対応、1578 ハッシュ） |
| white-box SAST venv（bandit 1.9.4 / semgrep 1.181.0 ほか、計 70 個） | pypi.org | `lab/sandbox/requirements-sast.lock`（`--require-hashes`、`--universal`、1012 ハッシュ）。caido 用 venv とは分離し `/opt/sast` に置く |

> **注意（nuclei-templates）:** GitHub の tag ソースアーカイブ（`/archive/refs/tags/...`）の sha256 は、git のアーカイブ生成仕様の変更で将来変わり得る（稀だが前例あり）。より堅くするなら、ビルド時にコミット SHA で clone して vendoring する。段階2で検討。
>
> 完全な sha256（省略なし）は `lab/sandbox/Dockerfile` の各 `ARG ..._SHA256` を参照。
| Python venv（caido-sdk-client 等） | pypi.org | `requirements.lock` の `--require-hashes` | lock 未生成 |
| OS パッケージ（sudo, openssl, chromium, nmap, sqlmap, ripgrep, git, jq 等） | Debian bookworm（apt、Debian 署名で検証） | ベース digest + apt | 固定済み |

上流 `containers/Dockerfile` との主な違い（意図的に変更した点）:

- `kalilinux/kali-rolling:latest` → `python:3.12-slim` / `debian:bookworm`（digest 固定）。
- `go install ...@latest` → 版固定。`npm -g ...@latest` → agent-browser のみ版固定。
- trivy / trufflehog / uv の `curl | sh` → 版固定バイナリ + sha256。
- `nuclei -update-templates`（ビルド時取得） → テンプレートを版固定で同梱し、実行時更新を無効化。
- **CA 秘密鍵をイメージに残さない** → `lab/sandbox/lab-entrypoint.sh` が起動時に生成（コンテナごとに別の鍵、有効期間 30 日）。
- white-box 用に **semgrep / bandit / trufflehog を追加**（版固定 + sha256/`--require-hashes`）。
  - **semgrep の注意:** egress は api.anthropic.com のみ許可のため、`semgrep --config auto` や `p/...` のレジストリ取得（semgrep.dev）は**遮断される**。ローカルルール（`--config <file>`）か同梱ルールのみオフラインで動く。レジストリルールを使う場合は egress 方針の変更（semgrep.dev 許可）か semgrep-rules の vendoring をオーケストレーターと要相談。bandit（組込みチェック）と trufflehog（正規表現ベース）はオフラインで完結する。
- まだ**入れていない**上流ツール（必要時に検討）: arjun, dirsearch, wafw00f, retire, eslint, jshint, js-beautify, ast-grep, tree-sitter, JS-Snooper, jsniper.sh, jwt_tool, wapiti, interactsh-client, caido-sdk 以外の Go ツール。Strix の system prompt はこれらに言及するため、スキャンで不足の影響を記録する。

## まだ決まっていない / 段階2

- **docker.sock の最小化（§3.3）**: 現状 compose は `/var/run/docker.sock` を直マウント。create 検査プロキシ（許可パスの bind のみ・Privileged 禁止・CapAdd は NET_ADMIN/NET_RAW のみ・NetworkMode は pentest-lab のみ・Image は strix-lab/sandbox のみ）を噛ませる予定。ただし Strix は `exec` を多用するため、プロキシが exec のストリームを中継できる必要がある。実装の確実性を含め、オーケストレーターと詰める（rootless dockerd 併用も候補）。
- 安全化パッチ（テレメトリ/更新チェックの既定 OFF、URL プローブ無効化、OAST を lab 内 interactsh に向け替え、キーを永続化しない）は観測の後。
- スモークテストが通ったら、検査対象をラボ運用者が用意する実アプリ（非公開の自前資産）に差し替える。
