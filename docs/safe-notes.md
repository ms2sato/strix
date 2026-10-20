# Strix を最小隔離で動かす計画（段階1）

> **状態: 計画のみ。まだ何も実行していない。** 以下のコマンドは、オーケストレーターとユーザーの承認（supply-chain-guard ゲート）を経てから実行する。
> 前提となる監査結果は [audit-notes.md](audit-notes.md)。表の `#n` は audit-notes §1 の番号。

## 決定事項（2026-10-17、ユーザー確認済み）

| 項目 | 決定 |
|---|---|
| CLI の置き場所 | **コンテナに入れる**（コントローラーコンテナ。§3） |
| サンドボックスイメージ | **自前で版固定ビルド**（上流イメージは使わない。§2） |
| 依存の導入 | **`uv sync --frozen`**（uv は公式イメージを digest 固定で取得。§1） |
| LLM | **Claude Opus 4.8（`claude-opus-4-8`）**。既存の Anthropic 互換ゲートウェイを流用する案が有力（§4。2026-10-17 更新。当初案の OpenCode Go から変更） |
| 要調整 | サンドボックスイメージ: ユーザーからは「自前ビルド」、オーケストレーター経由では「上流 1.3.0 を digest 固定」と指示があり、どちらにするか確認中。docker.sock を最小化する方法も確認中（§3.3） |
| 安全化パッチ | **初回の観測の後**に入れる（§6 手順 7） |

## 0. 方針

1. **取得するものはすべて版・ハッシュ・digest で固定する。** `curl | bash`、`@latest`、タグだけの pull は使わない。
2. **外への経路はネットワークで強制して塞ぐ。** 環境変数での無効化は二重化として使い、それだけには頼らない（サンドボックスには NET_ADMIN と NOPASSWD sudo がある）。
3. **外に出てよいのは LLM エンドポイントだけ**（ドメイン allowlist の egress プロキシ経由、利用元は CLI コンテナだけ）。
4. **検査対象は lab 内のコンテナ（ダミーデータ）だけ。** 本番・社内の実環境は対象にしない。
5. 初回は **全遮断で起動して通信の試行を観測する**（ARTEX-safe の lab と同じ手順）。
6. ARTEX-safe と同じく、ビルドは「依存の取得（ネットワークあり・lock 固定）」と「組み立て（`RUN --network=none`）」に分ける。

## 1. CLI イメージ（`lab/cli.Dockerfile`）

`install.sh` と PyPI の wheel は使わない（audit-notes §2.1）。**本 fork の固定コミットのソース + `uv.lock`（sha256 固定）**からビルドする。

```dockerfile
# 版と digest は実装時に確定し、lab/README.md に選定理由と併記する
ARG PY_IMAGE=python:3.12.x-slim-bookworm@sha256:<digest>
ARG UV_IMAGE=ghcr.io/astral-sh/uv:<version>@sha256:<digest>

FROM ${UV_IMAGE} AS uv

# 依存の取得（ネットワークあり。取得されるのは uv.lock のハッシュと一致するものだけ）
FROM ${PY_IMAGE} AS deps
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
#   --frozen             : uv.lock を更新せずそのまま使う
#   --no-dev             : 開発用依存を入れない
#   --no-install-project : 版固定のない hatchling の取得と build hook を回避
RUN uv sync --frozen --no-dev --no-install-project

# 実行イメージ（非 root、ソースはコピーするだけ）
FROM ${PY_IMAGE} AS runtime
COPY --from=deps /app/.venv /app/.venv
COPY strix/ /app/strix/
ENV PATH=/app/.venv/bin:$PATH PYTHONPATH=/app
USER 10001:10001
ENTRYPOINT ["python", "-m", "strix.interface.main", "-n"]
```

- `pip install strix-agent` は使わない（`litellm>=1.101.0` に上限がなく、ロックを無視して最新が入る。litellm は 2026-03 に PyPI で侵害の前例あり）。
- プロジェクトを install しないため、`strix-agent` の版は `unknown` になる。影響はテレメトリの版表示と更新チェックだけで、更新チェックは `unknown` のとき通知しない（`strix/interface/update_check.py:199-201`）。安全側に倒れる。
- Docker ソケットへのアクセスは、ホストの docker グループの GID を `group_add` で与える。

## 2. サンドボックスイメージ（`lab/sandbox.Dockerfile`、自前ビルド）

上流の `containers/Dockerfile` は `@latest` / `curl | sh` / `kali-rolling:latest` を含み、そのままビルドしても安全にならない（audit-notes §2.4）。fork に版固定の Dockerfile を新しく書く。

| 上流の問題 | 自前ビルドでの対処 |
|---|---|
| `kalilinux/kali-rolling:latest` + `apt-get upgrade` | ベースを digest で固定。Kali の apt は日々変わるため、Debian（digest + snapshot.debian.org の日付固定）に移し、Kali 固有のツールは個別に版指定で入れる案を第一候補とする（実装時に比較） |
| Go ツールの `@latest` | `go install <module>@vX.Y.Z`（sum.golang.org で検証）。取得とビルドを分け、ビルドは `--network=none` |
| `curl ... \| sh`（uv / trufflehog / trivy） | GitHub Releases の版固定バイナリ + sha256 検証。uv は公式イメージ（digest）からコピー |
| gitleaks の `latest` | 版固定 + sha256 |
| npm `@latest` | 版を明示し、`NPM_CONFIG_IGNORE_SCRIPTS=true`、`NPM_CONFIG_MIN_RELEASE_AGE=7` |
| pipx の版なし導入、jwt_tool の requirements | 版固定 + `--require-hashes` |
| 第三者リポジトリの `git clone`（HEAD） | コミット SHA で固定 |
| caido-cli（版固定だがハッシュなし） | sha256 検証を追加 |
| **CA 秘密鍵をビルド時に生成してイメージに残す** | **コンテナ起動時（entrypoint）に生成**し、コンテナごとに別の鍵にする |
| `nuclei -update-templates`（ビルド時に最新を取得） | テンプレートの版を固定して同梱。実行時の更新は internal ネットワークで遮断される |

- Strix が前提にしているもの（`caido-cli`、`/app/certs`、`agent-browser`、`docker-entrypoint.sh`、`/opt/strix-python/caido_api.py`、system prompt に載っているツール群）は維持する。入れないツールがあれば、system prompt との差を記録する。
- イメージは `strix-lab/sandbox:<fork のコミット>` としてローカルに置き、`STRIX_IMAGE` で指定する。手元にあるので pull は発生しない（`strix/interface/environment.py:191-218`、`strix/runtime/docker_client.py:179-181`）。
- ツールが多いため、作業量は CLI イメージより大きい。段階的に進める（まず Strix の動作に必須の Caido・Chromium/agent-browser・基本ツールだけを入れ、残りを順に足す）。

## 3. ネットワーク構成（CLI をコンテナに入れる）

### 3.1 構成図

```
strix-ctl     (internal: true / 例 10.188.2.0/24)
  ├─ strix-cli       コントローラー（固定 IP 例 10.188.2.5）
  └─ egress-proxy    squid（10.188.2.10）。利用元は strix-cli の IP だけ

strix-lab     (internal: true / 外への経路なし / 例 10.188.0.0/24)
  ├─ strix-cli       Caido（サンドボックスの IP:48080）へ直接つなぐ
  ├─ strix-sandbox   Strix が作成（STRIX_DOCKER_SANDBOX_NETWORK=strix-lab）
  └─ 検査対象         別 compose から参加（ダミーデータ）

strix-edge    (通常 bridge)
  └─ egress-proxy    外へ出られるのはここだけ。allowlist = LLM（ゲートウェイ）のドメインのみ

ホストの Docker デーモン
  └─ strix-cli から /var/run/docker.sock 経由でサンドボックスを作成
```

- **サンドボックスは `strix-ctl` に入らない**ので、squid（LLM の経路）に届かない。サンドボックスからの外向きはゼロ（OAST・テンプレート更新・自己更新もすべて遮断）。
- **CLI のすべての通信**（LLM・テレメトリ・更新確認・URL プローブ・LiteLLM の外部取得）はコンテナのネットワークで強制され、許可されるのは squid 経由の allowlist 宛だけになる。
- CLI がサンドボックスと同じ `strix-lab` にいるため、Strix が Caido にコンテナ IP で直接つなぐ方式（`strix/runtime/docker_client.py:127-160`）がそのまま動く。
- サンドボックスには常に `host.docker.internal → host-gateway` が付くが、internal ネットワークにはホストへのルートがないため届かない（疎通テストで確認する）。

### 3.2 CLI コンテナの設定

- `cap_drop: ALL`、`no-new-privileges`、`read_only: true`（書き込みは結果ディレクトリと tmpfs だけ）、非 root。
- マウントするのは次だけ:
  - `/var/run/docker.sock`
  - 結果の出力先（`strix_runs/`）
  - 設定ファイル（`--config` 先。キーを含むので `chmod 600`）
  - ローカルソースを渡す場合は、**ホストと同じパス**に読み取り専用でマウントする（bind mount のパスはホストの Docker デーモンが解釈するため）。中身は作業用のコピーにする。
- ホームディレクトリ、`~/.ssh`、他の認証情報はマウントしない。

### 3.3 残るリスク（Docker ソケット）

- **ソケットを持つ CLI は、ホストの `/` をマウントしたコンテナも作れる。** つまり、ソケットを悪用する前提の悪意あるコードには、コンテナに入れても防げない（ホストで動かす場合と同じ）。
- それ以外の面（ネットワークの強制、ホストのファイルが見えないこと）ではコンテナの方が明確に有利、というのが今回の判断。
- 段階2の強化案:
  - lab 専用の rootless Docker デーモンを使う（ソケットを奪われても、ホストの root にはならない）。
  - lab 全体を VM の中で動かす。

### 3.4 squid の設定方針（ARTEX-safe の `lab/egress` を流用）

- 既定の `allowlist.txt` は **空（全拒否）**。観測後に LLM（ゲートウェイ）のドメインだけを追加する。
- CONNECT 443 のみ許可。IP リテラル宛の CONNECT は拒否。
- 利用元は `strix-cli` の固定 IP だけ。

## 4. LLM（Claude Opus 4.8）

Strix の LLM 経路は 2 種類だけ: (a) LiteLLM 経由の `provider/model` + API キー、(b) ChatGPT（Codex）サブスクのログイン（`strix/config/codex.py`）。Claude のサブスクでログインする実装は無い。

### 設定の形（経路ごと）

| 経路 | `STRIX_LLM` | `LLM_API_BASE` | 呼び出し方 | allowlist |
|---|---|---|---|---|
| **A. Anthropic 互換ゲートウェイ（流用案・有力）** | `anthropic/claude-opus-4-8` | ゲートウェイの base URL | LiteLLM の anthropic プロバイダ → `{base}/v1/messages`（`x-api-key`）。**Messages API 互換が必要**（要確認） | ゲートウェイのホスト |
| B. Anthropic 直 | `anthropic/claude-opus-4-8` | 設定しない | 同上（api.anthropic.com） | `api.anthropic.com` |
| C. OpenAI 互換ゲートウェイ | `claude-opus-4-8`（接頭辞なし）または `openai/claude-opus-4-8` | ゲートウェイの `/v1` | OpenAI SDK の Chat Completions（`strix/config/models.py:1039-1052` の docstring がこの用途を想定） | ゲートウェイのホスト |
| D. OpenRouter | `openrouter/anthropic/claude-opus-4.8` 等 | 設定しない | LiteLLM の openrouter | `openrouter.ai` |

- `LLM_API_KEY` は SDK と LiteLLM の既定キーに設定され、さらに LiteLLM が要求する `ANTHROPIC_API_KEY` にも複製される（`strix/config/models.py:713-716,755-770`）。
- `LLM_API_BASE` は `OPENAI_BASE_URL` と `litellm.api_base`（プロセス全体の既定）に設定される（`strix/config/models.py:717-719`）。経路 A ではこれが anthropic プロバイダの base になる。
- ゲートウェイが `x-api-key` ではなく `Authorization: Bearer` を求める場合は、`LLM_EXTRA_HEADERS` で足す（`strix/config/models.py:910-925`）。
- Claude 系のモデル名では strict tool schema を自動で無効にする（`strix/config/models.py:982-991`。Claude の strict tool の上限を超えるため）。
- Strix は `temperature` を送らない（grep で該当なし）。思考は `STRIX_REASONING_EFFORT`（既定 `high`）を LiteLLM が Anthropic の thinking に変換する。ARTEX-safe で見た「Opus 5.5 は思考の無効化で 400」の問題は、Opus 4.8 では該当しない見込み（要観測）。
- **送られるもの:** Strix が LLM に渡すもの（white-box ならエージェントが読んだソースの大部分、black-box なら対象の HTTP 応答、発見事項）は、すべてゲートウェイの運営者と Anthropic に届く。lab の対象はダミーデータなので問題ない。

### コストと予算上限（`--max-budget`）

- コストは、LiteLLM が返す `response_cost` を使い、無ければ LiteLLM の価格表で推定する（`strix/report/state.py:1054-1086,1131-1175`、`strix/report/pricing.py:10-58`）。**価格表に `claude-opus-4-8` が無いと、コストは記録されず（0 扱い）、`--max-budget` が発動しない**（`strix/core/hooks.py:78-90`）。
- `LITELLM_LOCAL_MODEL_COST_MAP=True` では、litellm 1.101.0 の wheel に同梱された価格表だけを使う。**2026-10-17 に確認: 1.101.0 の同梱表に `claude-opus-4-8`（素の名前）と `anthropic.claude-opus-4-8` がある**（`v1.101.0` の `model_prices_and_context_window_backup.json`）。`anthropic/claude-opus-4-8` は末尾の `claude-opus-4-8` で引けるので、`--max-budget` は機能する見込み（実行時に最終確認）。
- 無かった場合の回避策:
  1. fork に小さなパッチを当て、lab 用の価格 JSON を `litellm.register_model()` で登録する（推奨。段階2のパッチに含める）。
  2. ゲートウェイ側の利用上限で管理する（Strix の予算上限は使えない前提にする）。
- 文脈長（コンテキストウィンドウ）も価格表から取る。無い場合はフォールバックの 200,000 トークンを使う（`STRIX_CONTEXT_FALLBACK_TOKENS`、`strix/config/settings.py:139`）。

### 観測で確認すること

1. 経路 A のゲートウェイが `/v1/messages`（ストリーミング + tool use + thinking）に対応しているか。
2. 価格表に `claude-opus-4-8` があるか（無ければ予算上限は効かない）。
3. ツール呼び出しを含む短いスキャンが最後まで通るか。

## 5. 環境変数・設定（二重化のための無効化）

`lab/strix.env`（コミットしない。`chmod 600`）にまとめ、CLI コンテナに渡す。

```sh
# 外部送信の無効化（audit-notes §3.1）。ネットワークでも塞がれるが二重化する
STRIX_TELEMETRY=0                     # #2 PostHog, #3 Scarf
STRIX_NO_UPDATE_CHECK=1               # #4 更新チェック, #5 自己更新（さらに常に -n で起動）
LITELLM_LOCAL_MODEL_COST_MAP=True     # #16 LiteLLM の価格表のリモート取得
STRIX_APP_URL=http://127.0.0.1:9      # #12 viewer の中継（保険。viewer は使わない）
# PERPLEXITY_API_KEY / EXA_API_KEY / POSTMAN_API_KEY は設定しない（#9, #10）
# mcp-servers.json は置かない（#11）

# 隔離
STRIX_DOCKER_SANDBOX_NETWORK=strix-lab
STRIX_IMAGE=strix-lab/sandbox:<fork のコミット>
STRIX_SANDBOX_MEM_LIMIT=4g
STRIX_SANDBOX_CPUS=2
STRIX_SANDBOX_PIDS_LIMIT=1024

# LLM の経路
HTTPS_PROXY=http://10.188.2.10:3128
HTTP_PROXY=http://10.188.2.10:3128
NO_PROXY=localhost,127.0.0.1,10.188.0.0/24   # Caido（サンドボックスの IP）をプロキシに流さない。httpx の CIDR 対応は要確認
```

起動例（予算上限付き・対象は lab のコンテナ名）:

```sh
docker compose -f lab/compose.yml run --rm strix-cli \
  --config /config/cli-config.json \
  -t http://target-web:8080 --scan-mode quick --max-budget 5
```

### キーの扱い

- チャットに貼らない。利用上限を設定した lab 専用のキーを使い、検査が終わったら失効させる。
- Strix はスキャンごとに、環境変数のキーを設定ファイルに平文で書く（`strix/config/loader.py:64-91`）。`--config` で lab 専用のパスに向ける。
- キーはサンドボックスのコンテナには渡らない（`strix/runtime/session_manager.py:316-330`）。

## 6. 進め方（承認ゲートごと）

| 手順 | 内容 | ゲート |
|---|---|---|
| 1 | 本計画のレビュー | オーケストレーター / ユーザー（済） |
| 2 | fork に lab 構成を追加: `lab/cli.Dockerfile`、`lab/sandbox.Dockerfile`、`lab/compose.yml`（3 ネットワーク + squid）、`lab/target-example/`、`lab/scripts/verify-isolation.sh`。まだ実行しない | コードレビュー |
| 3 | ビルド（ベースイメージ・依存の取得を含む） | **supply-chain-guard（実行の承認）** |
| 4 | allowlist を空にして起動し、ダミー対象にスキャン。tcpdump と squid ログで、**誰が・どこへ**出ようとするかを記録する（audit-notes §4 の未確認事項を埋める） | 実行の承認 |
| 5 | 疎通テスト: サンドボックス → インターネット / ホスト / 169.254.169.254 / squid が不可、CLI → allowlist 外が不可、CLI → Caido が可、検査対象 → squid が不可 | 結果をレビュー |
| 6 | allowlist に LLM（ゲートウェイ）のドメインだけを追加し、quick スキャンを短時間で実行（ツール呼び出し・予算上限の確認） | 実行の承認 |
| 7（段階2） | fork で安全化パッチ: テレメトリ・更新チェックの既定 OFF、`host.docker.internal` の無効化オプション、ソースの読み取り専用マウント、URL プローブの無効化、OAST を lab 内 interactsh に向ける、キーを永続化しない。あわせて rootless Docker / VM による強化を検討 | コードレビュー |

## 7. 未定事項

1. Claude Opus 4.8 を配信するゲートウェイのドメインと形式（Anthropic 互換か OpenAI 互換か。ユーザー/オーケストレーターから受け取る）。
2. サンドボックスのベース: Debian + snapshot 固定と、Kali の digest 固定（apt は浮動）のどちらにするか。実装時に比較してレビューに出す。
