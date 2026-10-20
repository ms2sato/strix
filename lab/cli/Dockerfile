# Strix CLI（コントローラー）イメージ。docs/safe-notes.md §1。
#
# ビルドコンテキストはリポジトリのルート:
#   docker compose -f lab/compose.yml build strix-cli
#
# 方針
# - install.sh / PyPI の wheel は使わない。本 fork のソース + uv.lock（sha256 固定）から入れる。
# - 依存の取得（ネットワークあり）とイメージの組み立てを分ける。組み立ては RUN --network=none。
# - プロジェクト自身は install しない（--no-install-project）。版固定のない hatchling の取得と
#   Go TUI の build hook を避けるため。起動は `python -m strix.interface.main`。
# - 実行時は非 root（uid は compose の user: で指定）、read_only、HOME は tmpfs。
#
# 注: `# syntax=` ディレクティブはフロントエンドを digest なしで取得するため書かない。
#
# digest / 版は手順 3（supply-chain-guard）で確定済み。選定内容は lab/README.md「取得物の一覧」。
# lab/scripts/check-pins.sh で固定状況を確認できる。

# ---- 固定するベースイメージ（tag@digest） --------------------------------------
# Strix は Python 3.12 以上が必要（pyproject.toml: requires-python = ">=3.12"）
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# uv は公式イメージからバイナリだけをコピーする（curl | sh を使わない）
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336

FROM ${UV_IMAGE} AS uv

# =============================================================================
# 1. 依存の取得（ネットワークあり: pypi.org のみ。uv.lock の sha256 と一致するものだけ）
# =============================================================================
FROM ${PY_IMAGE} AS deps
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
#   --frozen             : uv.lock を更新せずそのまま使う（ハッシュ検証あり）
#   --no-dev             : 開発用依存（pyinstaller 等）を入れない
#   --no-install-project : プロジェクト自身をビルドしない
RUN uv sync --frozen --no-dev --no-install-project

# =============================================================================
# 2. 実行イメージ（ネットワークなしで組み立てる）
# =============================================================================
FROM ${PY_IMAGE} AS runtime
COPY --from=deps /app/.venv /app/.venv
COPY strix/ /app/strix/
# Strix は起動時に `docker` CLI の有無だけを確認する（strix/interface/environment.py:166-188）。
# 実際の操作は Docker SDK がソケット経由で行うため、CLI 本体は入れずに確認用のスタブを置く。
RUN --network=none printf '%s\n' \
      '#!/bin/sh' \
      'echo "strix-lab: docker CLI is intentionally not installed in this image" >&2' \
      'exit 1' > /usr/local/bin/docker \
    && chmod 0755 /usr/local/bin/docker \
    && mkdir -p /work /home/strix
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /work
# headless（-n）固定。対話モードの更新プロンプト（自己更新）は使わない
ENTRYPOINT ["python", "-m", "strix.interface.main", "-n"]
