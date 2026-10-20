#!/usr/bin/env python3
"""strix-lab のスモークテスト用ダミー標的（意図的に脆弱）。

目的は配管（Strix CLI → sandbox → この標的 → LLM → findings）の疎通確認だけ。
検出精度の評価は後段。Python 標準ライブラリだけで書き、外部イメージ・pip の取得を要しない
（ベースイメージは CLI / sandbox と同じ python:3.12-slim を使い回す）。

意図的な脆弱性:
  1. 反射 XSS: GET /greet?name=... を無エスケープで HTML に反映する。
  2. IDOR:     GET /api/notes?id=N が、所有者チェックなしに他人のメモを返す。

このアプリは strix-lab ネットワークの中だけで動かし、外部には公開しない。ダミーデータのみ。
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


# ダミーのメモ。所有者が違うが、API は所有者を確認せずに返す（IDOR）。
_NOTES = {
    "1": {"owner": "alice", "text": "alice のメモ: 買い物リスト"},
    "2": {"owner": "bob", "text": "bob の秘密メモ: 社外秘のダミー値 FLAG-IDOR-DEMO"},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "strix-lab-target/1.0"

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path == "/":
            body = (
                b"<html><body><h1>strix-lab target</h1>"
                b'<p>Try <a href="/greet?name=world">/greet?name=world</a> '
                b'and <a href="/api/notes?id=1">/api/notes?id=1</a>.</p>'
                b"</body></html>"
            )
            self._send(200, body, "text/html; charset=utf-8")
            return

        if parts.path == "/greet":
            name = (query.get("name") or ["guest"])[0]
            # 脆弱: name を無エスケープで反映する（反射 XSS）
            body = f"<html><body><h1>Hello, {name}!</h1></body></html>".encode()
            self._send(200, body, "text/html; charset=utf-8")
            return

        if parts.path == "/api/notes":
            note_id = (query.get("id") or ["1"])[0]
            note = _NOTES.get(note_id)
            if note is None:
                self._send(404, b'{"error":"not found"}', "application/json")
                return
            # 脆弱: リクエスト元の所有者を確認せずに返す（IDOR）
            self._send(200, json.dumps(note).encode(), "application/json")
            return

        self._send(404, b"not found", "text/plain; charset=utf-8")

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002
        # アクセスログは stdout へ（docker compose logs target-web）
        print("target-web " + (fmt % args))  # noqa: T201


def main() -> None:
    # 標的は strix-lab の中だけ。コンテナ内の 0.0.0.0:8080 を listen する（ポートは外に publish しない）
    _ = html  # 無エスケープが意図的であることを明示（lint 向け）
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104


if __name__ == "__main__":
    main()
