"""Lab-fork (opt-in) conservative condenser for known-verbose tool output.

Some tools (nuclei ``-json``, semgrep ``--json``, raw HTTP responses) emit very
large output where most bytes are boilerplate, not signal. When the lab opt-in
``STRIX_TOOL_OUTPUT_PARSE`` is on, :func:`condense` turns such output into a
compact, finding-preserving view *before* it is bounded into agent history.

Safety contract (see the orchestrator's conservative-parser requirements):
- The caller always spills the FULL raw output to disk first and appends a
  pointer, so condensing never loses data — the agent can read the original.
- Findings / anomalies are never dropped: every nuclei match, every semgrep
  result, every HTTP status line and header is kept; only repetitive per-item
  verbosity (large JSON blobs, long bodies) is folded.
- Fail open: anything this module does not confidently recognize returns
  ``None`` so the caller keeps the upstream raw head/tail behavior.
- ``level`` ("conservative" default, or "aggressive") only tunes how much of
  the already-preserved essentials to keep; conservative keeps more.
"""

from __future__ import annotations

import json
import logging
from typing import Any


logger = logging.getLogger(__name__)

# Only bother for genuinely large output; small output is passed through.
_MIN_CONDENSE_BYTES = 8 * 1024

_BODY_HEAD_BYTES = {"conservative": 4096, "aggressive": 1024}
_MSG_MAX = {"conservative": 400, "aggressive": 160}

_SECURITY_HEADERS = {
    "set-cookie", "location", "www-authenticate", "content-type",
    "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "x-xss-protection", "access-control-allow-origin", "access-control-allow-credentials",
    "cache-control", "authorization", "x-powered-by", "server",
}


def condense(text: str, level: str = "conservative") -> str | None:
    """Return a condensed, finding-preserving view of ``text``, or None.

    None means "not recognized / do not condense" — the caller then keeps the
    upstream raw head/tail behavior (fail open).
    """
    if not isinstance(text, str) or len(text.encode("utf-8", "ignore")) < _MIN_CONDENSE_BYTES:
        return None
    lvl = level if level in _BODY_HEAD_BYTES else "conservative"
    for detector, parser in (
        (_is_semgrep_json, _condense_semgrep),
        (_is_nuclei_jsonl, _condense_nuclei),
        (_is_http_response, _condense_http),
    ):
        try:
            if detector(text):
                out = parser(text, lvl)
                # Only use it if it actually helped and preserved structure.
                if out and len(out) < len(text):
                    return out
                return None
        except Exception:
            logger.debug("condense parser failed; failing open", exc_info=True)
            return None
    return None


# --- semgrep --json -----------------------------------------------------------


def _is_semgrep_json(text: str) -> bool:
    s = text.lstrip()
    if not s.startswith("{"):
        return False
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(obj, dict) and "results" in obj and isinstance(obj["results"], list)


def _condense_semgrep(text: str, level: str) -> str | None:
    obj = json.loads(text)
    results = obj.get("results") or []
    errors = obj.get("errors") or []
    msg_max = _MSG_MAX[level]
    lines = [f"semgrep: {len(results)} result(s), {len(errors)} error(s) (condensed; full output on disk)"]
    for r in results:  # keep EVERY result
        if not isinstance(r, dict):
            lines.append(str(r))
            continue
        check = r.get("check_id", "?")
        path = r.get("path", "?")
        start = (r.get("start") or {}).get("line", "?")
        extra = r.get("extra") or {}
        sev = extra.get("severity", "?")
        msg = str(extra.get("message", "")).replace("\n", " ").strip()
        if len(msg) > msg_max:
            msg = msg[:msg_max] + "…"
        lines.append(f"[{sev}] {check} {path}:{start} — {msg}")
    for e in errors:  # keep every error verbatim-ish
        em = e if isinstance(e, str) else json.dumps(e, ensure_ascii=False)
        lines.append("error: " + em[: msg_max * 2])
    return "\n".join(lines)


# --- nuclei -json / -jsonl ----------------------------------------------------


def _is_nuclei_jsonl(text: str) -> bool:
    json_lines = 0
    hit = 0
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            json_lines += 1
            if "template-id" in obj or "templateID" in obj or ("info" in obj and "matched-at" in obj):
                hit += 1
    return json_lines > 0 and hit >= 1 and hit >= json_lines // 2


def _condense_nuclei(text: str, level: str) -> str | None:
    kept: list[str] = []
    findings = 0
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            # Non-JSON line (e.g. a nuclei log/error): keep it verbatim — never drop.
            kept.append(line)
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            kept.append(line)  # unparseable: keep, do not drop
            continue
        tid = obj.get("template-id") or obj.get("templateID") or "?"
        info = obj.get("info") or {}
        sev = info.get("severity", "?")
        name = info.get("name", "")
        matched = obj.get("matched-at") or obj.get("host") or ""
        typ = obj.get("type", "")
        findings += 1
        kept.append(f"[{sev}] {tid} {typ} — {matched}" + (f" ({name})" if name else ""))
    header = f"nuclei: {findings} finding(s) (condensed; full output on disk)"
    return "\n".join([header, *kept])


# --- raw HTTP response --------------------------------------------------------


def _is_http_response(text: str) -> bool:
    s = text.lstrip()
    return s.startswith("HTTP/1.") or s.startswith("HTTP/2") or s.startswith("HTTP/3")


def _condense_http(text: str, level: str) -> str | None:
    # Split headers / body on the first blank line (CRLF or LF).
    sep_idx = None
    for sep in ("\r\n\r\n", "\n\n"):
        i = text.find(sep)
        if i != -1:
            sep_idx = (i, len(sep))
            break
    if sep_idx is None:
        return None  # not a clean response; fail open
    i, seplen = sep_idx
    header_block = text[:i]
    body = text[i + seplen :]

    header_lines = header_block.split("\n")
    status_line = header_lines[0].strip() if header_lines else ""
    out = [status_line]
    # Keep ALL headers (small, possibly security-relevant). Mark known-security ones.
    for h in header_lines[1:]:
        hl = h.strip()
        if not hl:
            continue
        name = hl.split(":", 1)[0].strip().lower()
        prefix = "* " if name in _SECURITY_HEADERS else "  "
        out.append(prefix + hl)

    body_bytes = body.encode("utf-8", "ignore")
    head_n = _BODY_HEAD_BYTES[level]
    if len(body_bytes) <= head_n:
        out.append("")
        out.append(body)
    else:
        head = body_bytes[:head_n].decode("utf-8", "ignore")
        out.append("")
        out.append(head)
        out.append(
            f"[Strix lab: body folded — {len(body_bytes)} bytes total, first {head_n} shown; "
            "full raw response on disk (read with exec_command)]"
        )
    return "\n".join(out)
