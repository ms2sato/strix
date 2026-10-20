"""pentest-lab の Docker ソケット検査プロキシ（docs/safe-notes.md §3.3）。

strix-cli に生の /var/run/docker.sock を渡さず、このプロキシ（TCP 2375、pentest-sock ネットワーク内だけ）
を経由させる。Strix のサンドボックス運用に必要な API だけを通し、次を拒否する。

- 許可リストにない API（イメージの pull / build、volume / network の作成・接続、system 系など）
- 許可イメージ以外、許可ネットワーク以外、Privileged、許可外の CapAdd、許可外の bind mount を含むコンテナ作成
- このプロキシ経由で作ったコンテナ以外への操作（ホスト上の他のコンテナへの exec など）

!!! 未検証・レビュー前 !!!
  このプロキシはまだ一度も実行していない（docs/safe-notes.md の手順 3 より前）。特に exec / attach の
  hijack ストリーム中継と、どのコンテナを「自分が作った」とみなす状態管理は、レビューと実機確認が必須。
  それまでは compose の既定経路にしない（lab/compose.sockproxy.yml のオーバーレイで opt-in）。

設計
- 1 接続 1 リクエスト。上流へは Connection: close を付け、検査を通した後にクライアントが追送した
  バイトを上流へ流さない。例外は exec/attach の Upgrade（hijack）で、上流が 101 を返した後に双方向中継する。
- コンテナ作成の 201 応答から id を覚え、/containers/<id>/... の操作はその集合に限る。
  プロキシ再起動で集合は消える（その場合は作成済みコンテナを操作できなくなる = フェイルクローズ）。

標準ライブラリだけで動く。設定は環境変数:
  SOCKPROXY_LISTEN                 既定 0.0.0.0:2375（内部ネットワーク限定で待受）
  SOCKPROXY_UPSTREAM               既定 /var/run/docker.sock
  SOCKPROXY_ALLOWED_IMAGE          既定 strix-lab/sandbox:local
  SOCKPROXY_ALLOWED_NETWORK        既定 pentest-lab
  SOCKPROXY_ALLOWED_BIND_PREFIXES  bind mount を許すホストパスの接頭辞（: 区切り）。既定は空＝bind 禁止
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any
from urllib.parse import unquote, urlsplit


LISTEN = os.environ.get("SOCKPROXY_LISTEN", "0.0.0.0:2375")  # noqa: S104 - internal network only
UPSTREAM = os.environ.get("SOCKPROXY_UPSTREAM", "/var/run/docker.sock")
ALLOWED_IMAGE = os.environ.get("SOCKPROXY_ALLOWED_IMAGE", "strix-lab/sandbox:local")
ALLOWED_NETWORK = os.environ.get("SOCKPROXY_ALLOWED_NETWORK", "pentest-lab")
ALLOWED_BIND_PREFIXES = tuple(
    p.rstrip("/") + "/"
    for p in os.environ.get("SOCKPROXY_ALLOWED_BIND_PREFIXES", "").split(":")
    if p.strip()
)
ALLOWED_CAPS = frozenset({"NET_ADMIN", "NET_RAW"})
ALLOWED_EXTRA_HOSTS = frozenset({"host.docker.internal:host-gateway"})
MAX_HEAD = 64 * 1024
MAX_JSON_BODY = 4 * 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s sockproxy %(levelname)s %(message)s")
log = logging.getLogger("sockproxy")

# API バージョン接頭辞（/v1.44/...）を落として素のパスで照合する
_VERSION_PREFIX = re.compile(r"^/v\d+\.\d+")

# このプロキシ経由で作成したコンテナの id（短縮形と完全形の両方を入れる）。
_created: set[str] = set()


def _strip_version(path: str) -> str:
    return _VERSION_PREFIX.sub("", path) or "/"


# メソッド + 素パスで許可を判定する。値は「bool（無条件許可）」か「検査関数」。
# ここに無いものはすべて拒否（pull / build / commit / volumes / networks / system など）。
_RE_PING = re.compile(r"^/_ping$")
_RE_VERSION = re.compile(r"^/version$")
_RE_INFO = re.compile(r"^/info$")
_RE_IMAGE_INSPECT = re.compile(r"^/images/.+/json$")
_RE_CONTAINERS_CREATE = re.compile(r"^/containers/create$")
_RE_CONTAINER_OP = re.compile(
    r"^/containers/(?P<id>[^/]+)/(start|stop|kill|wait|restart|json|exec|archive|logs|attach|resize)$"
)
_RE_CONTAINER_DELETE = re.compile(r"^/containers/(?P<id>[^/]+)$")
_RE_EXEC_START = re.compile(r"^/exec/(?P<id>[^/]+)/(start|resize)$")
_RE_EXEC_INSPECT = re.compile(r"^/exec/(?P<id>[^/]+)/json$")


def _container_id_from(path: str) -> str | None:
    for rx in (_RE_CONTAINER_OP, _RE_CONTAINER_DELETE):
        m = rx.match(path)
        if m:
            return unquote(m.group("id"))
    return None


def _check_create_body(body: bytes) -> str | None:
    """コンテナ作成の本文を検査する。問題があれば拒否理由（文字列）、無ければ None。"""
    try:
        spec: dict[str, Any] = json.loads(body or b"{}")
    except (ValueError, TypeError):
        return "create: 本文が JSON ではない"
    image = spec.get("Image")
    if image != ALLOWED_IMAGE:
        return f"create: Image={image!r} は許可されていない（許可: {ALLOWED_IMAGE!r}）"
    host = spec.get("HostConfig") or {}
    if host.get("Privileged"):
        return "create: Privileged は禁止"
    for key in ("UsernsMode", "PidMode", "IpcMode", "CgroupnsMode"):
        val = host.get(key)
        if isinstance(val, str) and val.startswith("host"):
            return f"create: {key}={val!r} は禁止"
    net = host.get("NetworkMode")
    if net not in (None, "default", ALLOWED_NETWORK):
        return f"create: NetworkMode={net!r} は許可されていない（許可: {ALLOWED_NETWORK!r}）"
    for cap in host.get("CapAdd") or []:
        if str(cap).upper().removeprefix("CAP_") not in ALLOWED_CAPS:
            return f"create: CapAdd={cap!r} は許可されていない"
    if host.get("Devices"):
        return "create: Devices の割り当ては禁止"
    for host_path, read_only in _iter_binds(host):
        if not ALLOWED_BIND_PREFIXES or not host_path.startswith(ALLOWED_BIND_PREFIXES):
            return f"create: bind mount {host_path!r} は許可パス {ALLOWED_BIND_PREFIXES} の外"
        # 検査対象ソースの bind は read-only のみ許可する（white-box ソースをサンドボックスから改変させない）。
        if not read_only:
            return f"create: bind mount {host_path!r} は read-only でない（rw bind は禁止）"
    for eh in host.get("ExtraHosts") or []:
        if str(eh) not in ALLOWED_EXTRA_HOSTS:
            return f"create: ExtraHosts={eh!r} は許可されていない"
    return None


def _iter_binds(host: dict[str, Any]) -> list[tuple[str, bool]]:
    """HostConfig から bind の (ホストパス, read_only か) を集める（Binds と Mounts(type=bind) の両方）。"""
    paths: list[tuple[str, bool]] = []
    for b in host.get("Binds") or []:
        # 形式は "src:dst[:opts]"。opts に "ro" があれば read-only。
        parts = str(b).split(":")
        src = parts[0]
        opts = parts[2].split(",") if len(parts) >= 3 else []
        read_only = "ro" in opts
        if src.startswith("/"):
            paths.append((src if src.endswith("/") else src + "/", read_only))
    for m in host.get("Mounts") or []:
        if isinstance(m, dict) and m.get("Type") == "bind":
            src = str(m.get("Source", ""))
            read_only = bool(m.get("ReadOnly"))
            if src.startswith("/"):
                paths.append((src if src.endswith("/") else src + "/", read_only))
    return paths


def _authorize(method: str, path: str) -> tuple[bool, str]:
    """(許可か, 理由) を返す。本文検査が要るものは True を返し、呼び出し側が本文を検査する。"""
    if method in ("GET", "HEAD"):
        if _RE_PING.match(path) or _RE_VERSION.match(path) or _RE_INFO.match(path):
            return True, ""
        if _RE_IMAGE_INSPECT.match(path) or _RE_EXEC_INSPECT.match(path):
            return True, ""
    if _RE_CONTAINERS_CREATE.match(path) and method == "POST":
        return True, ""  # 本文は呼び出し側で検査。"create" を id と誤認しないよう id 判定より前に置く
    cid = _container_id_from(path)
    if cid is not None:
        if cid in _created:
            return True, ""
        return False, f"未知のコンテナ {cid} への操作は拒否（このプロキシ経由で作成していない）"
    if (_RE_EXEC_START.match(path) or _RE_EXEC_INSPECT.match(path)) and method in ("POST", "GET"):
        # exec id とコンテナの対応は保持しないため、ここは通す（exec の作成自体は
        # /containers/<id>/exec で、その時点でコンテナ id を検査済み）。
        return True, ""
    return False, f"許可リストにない API: {method} {path}"


# --- HTTP の最小パーサ（上流は Docker daemon なので素直な HTTP/1.1） ---------------


def _parse_request(head: bytes) -> tuple[str, str, dict[str, str]]:
    lines = head.split(b"\r\n")
    method, raw_path, _ = lines[0].decode("latin1").split(" ", 2)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        k, _, v = line.decode("latin1").partition(":")
        headers[k.strip().lower()] = v.strip()
    return method, raw_path, headers


def _deny(code: int, reason: str) -> bytes:
    body = json.dumps({"message": reason}).encode()
    return (
        f"HTTP/1.1 {code} Forbidden\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with_close = getattr(dst, "can_write_eof", None)
        if with_close and dst.can_write_eof():
            try:
                dst.write_eof()
            except OSError:
                pass


async def _handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
    peer = client_w.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(client_r.readuntil(b"\r\n\r\n"), timeout=30)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        client_w.close()
        return
    if len(head) > MAX_HEAD:
        client_w.write(_deny(431, "header too large"))
        await client_w.drain()
        client_w.close()
        return

    method, raw_path, headers = _parse_request(head)
    path = _strip_version(urlsplit(raw_path).path)

    body = b""
    clen = int(headers.get("content-length", "0") or "0")
    if clen:
        if clen > MAX_JSON_BODY:
            client_w.write(_deny(413, "body too large"))
            await client_w.drain()
            client_w.close()
            return
        body = await client_r.readexactly(clen)

    allowed, reason = _authorize(method, path)
    if allowed and _RE_CONTAINERS_CREATE.match(path):
        reason2 = _check_create_body(body)
        if reason2:
            allowed, reason = False, reason2
    if not allowed:
        log.warning("DENY %s %s from %s: %s", method, path, peer, reason)
        client_w.write(_deny(403, reason))
        await client_w.drain()
        client_w.close()
        return

    log.info("ALLOW %s %s from %s", method, path, peer)

    is_hijack = method == "POST" and (
        _RE_EXEC_START.match(path) or (_RE_CONTAINER_OP.match(path) and path.endswith("/attach"))
    )

    # 上流（docker.sock）へ接続して中継する
    up_r, up_w = await asyncio.open_unix_connection(UPSTREAM)
    # 非 hijack では、検査後にクライアントが追送したバイトを上流へ流さないため Connection: close に差し替える。
    # hijack（exec/attach start）は Connection/Upgrade を保持しないと daemon が接続を乗っ取れないため、原文のまま送る。
    rebuilt = _rebuild_head(method, raw_path, headers, keep_connection=is_hijack)
    up_w.write(rebuilt + body)
    await up_w.drain()
    if is_hijack:
        # 101 Upgrade 後は双方向の生ストリーム。両方向を中継する
        await asyncio.gather(_pipe(up_r, client_w), _pipe(client_r, up_w))
    else:
        # 応答を中継し、作成の 201 なら id を記録する
        await _relay_response(up_r, client_w, record_create=_RE_CONTAINERS_CREATE.match(path) is not None)
    client_w.close()
    up_w.close()


def _rebuild_head(method: str, raw_path: str, headers: dict[str, str], *, keep_connection: bool = False) -> bytes:
    out = [f"{method} {raw_path} HTTP/1.1"]
    for k, v in headers.items():
        if k == "host":
            continue
        if k == "connection" and not keep_connection:
            continue
        if k == "upgrade" and not keep_connection:
            continue
        out.append(f"{k}: {v}")
    out.append("host: docker")
    if not keep_connection:
        out.append("connection: close")
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin1")


async def _relay_response(up_r: asyncio.StreamReader, client_w: asyncio.StreamWriter, *, record_create: bool) -> None:
    try:
        head = await up_r.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return
    client_w.write(head)
    # 応答本体を終端（上流が Connection: close なので EOF まで）まで中継する
    buf = bytearray()
    async for chunk in _iter_body(up_r):
        buf += chunk
        client_w.write(chunk)
    await client_w.drain()
    if record_create:
        _record_created_id(bytes(buf))


async def _iter_body(reader: asyncio.StreamReader):
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            break
        yield chunk


def _record_created_id(body: bytes) -> None:
    try:
        # chunked の場合も JSON 本体を含むので、最後の { から末尾を試す
        start = body.find(b"{")
        if start < 0:
            return
        obj = json.loads(body[start : body.rfind(b"}") + 1])
        cid = obj.get("Id")
        if isinstance(cid, str) and cid:
            _created.add(cid)
            _created.add(cid[:12])
            log.info("recorded created container %s", cid[:12])
    except (ValueError, TypeError):
        pass


async def main() -> None:
    host, _, port = LISTEN.rpartition(":")
    server = await asyncio.start_server(_handle, host or "0.0.0.0", int(port))  # noqa: S104
    log.info("sockproxy listening on %s, upstream %s, image=%s net=%s binds=%s",
             LISTEN, UPSTREAM, ALLOWED_IMAGE, ALLOWED_NETWORK, ALLOWED_BIND_PREFIXES or "(none)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
