# Docker ソケット検査プロキシ（docs/safe-notes.md §3.3）。標準ライブラリだけで動くので追加取得はない。
# ベースは CLI / sandbox / target と同じ python:3.12-slim（追加イメージを増やさない）。
# digest は手順 3 で確定済み（lab/README.md）。
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
FROM ${PY_IMAGE}
# ビルドコンテキストは ./sockproxy（compose.sockproxy.yml の build.context）
COPY sockproxy.py /app/sockproxy.py
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["python", "/app/sockproxy.py"]
