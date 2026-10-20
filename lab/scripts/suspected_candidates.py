#!/usr/bin/env python3
"""Lab post-processing: extract a Strix run's *suspected-but-unconfirmed*
candidates alongside its confirmed findings, from local run artifacts only.

Target-agnostic: reads a run directory's
``vulnerabilities.json`` (confirmed), ``coverage.json`` (tested surfaces +
outcomes), ``.state/notes.json`` (agent-written leads), and ``.state/agents.db``
(``reasoning`` items + ``think`` tool scratchpad). It surfaces what the agent
*noticed/suspected* so recall can be measured against an external ground truth —
"confirmed / candidate (noticed, unreported) / not surfaced at all".

Usage:  python3 lab/scripts/suspected_candidates.py <run_dir> [--json]
No network, no LLM, read-only.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path

# A "subject" = a controller#action, a route path, or a named vuln surface the
# agent referenced. Heuristic, deliberately broad (recall-oriented).
_SUBJECT_RES = [
    re.compile(r"\b([A-Za-z_][\w:]*(?:Controller)?#[a-z_][\w]*)"),  # Foo#bar / FooController#bar
    re.compile(r"(?<![\w/])(/[A-Za-z0-9_][\w./:{}-]{2,})"),          # /path/segments
    re.compile(r"\b([a-z_]+#[a-z_]+)\b"),                            # snake#snake controller#action
]


def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _reasoning_and_think(run_dir: Path) -> list[tuple[str, str]]:
    """Return (source, text) pairs from agents.db reasoning items + think calls."""
    out: list[tuple[str, str]] = []
    db = run_dir / ".state" / "agents.db"
    if not db.exists():
        return out
    con = sqlite3.connect(str(db))
    try:
        rows = con.execute("select message_data from agent_messages order by created_at")
        for (md,) in rows:
            try:
                data = json.loads(md)
            except (json.JSONDecodeError, TypeError):
                continue
            for it in data if isinstance(data, list) else [data]:
                if not isinstance(it, dict):
                    continue
                if it.get("type") == "reasoning":
                    txt = " ".join(s.get("text", "") for s in (it.get("summary") or [])) or " ".join(
                        c.get("text", "") for c in (it.get("content") or [])
                    )
                    if txt:
                        half = len(txt) // 2
                        if txt[:half].strip() == txt[half:].strip():
                            txt = txt[:half].strip()
                        out.append(("reasoning", txt.strip()))
                elif it.get("type") == "function_call" and it.get("name") == "think":
                    try:
                        a = json.loads(it.get("arguments", "") or "{}")
                    except json.JSONDecodeError:
                        a = {}
                    t = a.get("thought") or a.get("content") or ""
                    if t:
                        out.append(("think", str(t)))
    finally:
        con.close()
    return out


def _subjects(text: str) -> set[str]:
    subs: set[str] = set()
    for rx in _SUBJECT_RES:
        for m in rx.findall(text):
            s = m if isinstance(m, str) else m[0]
            if 3 <= len(s) <= 80:
                subs.add(s)
    return subs


def extract(run_dir: Path) -> dict:
    vulns = _load_json(run_dir / "vulnerabilities.json", [])
    if not isinstance(vulns, list):
        vulns = []
    confirmed = [
        {
            "id": v.get("id"),
            "title": v.get("title"),
            "endpoint": v.get("endpoint"),
            "method": v.get("method"),
            "cwe": v.get("cwe"),
            "severity": v.get("severity"),
        }
        for v in vulns
        if isinstance(v, dict)
    ]
    confirmed_subjects = set()
    for v in confirmed:
        for field in (v.get("endpoint"), v.get("title")):
            if field:
                confirmed_subjects |= _subjects(str(field))

    # The structured coverage (surface/risk_area/outcome) lives under .state/;
    # the top-level coverage.json is a different (export) shape.
    coverage = _load_json(run_dir / ".state" / "coverage.json", None)
    if not isinstance(coverage, dict):
        coverage = _load_json(run_dir / "coverage.json", {})
    cov_entries = []
    if isinstance(coverage, dict):
        for rec in coverage.values():
            if isinstance(rec, dict):
                cov_entries.append(
                    {
                        "surface": rec.get("surface"),
                        "risk_area": rec.get("risk_area"),
                        "outcome": rec.get("outcome"),
                    }
                )

    notes = _load_json(run_dir / ".state" / "notes.json", {})
    note_texts: list[str] = []
    if isinstance(notes, dict):
        for entries in notes.values():
            if isinstance(entries, dict):
                for n in entries.values():
                    if isinstance(n, dict):
                        note_texts.append((n.get("title") or "") + "\n" + (n.get("content") or ""))
            elif isinstance(entries, str):
                note_texts.append(entries)

    rt = _reasoning_and_think(run_dir)

    # Candidate subjects = everything mentioned in reasoning/think/notes, minus
    # subjects already in a confirmed finding.
    candidates: dict[str, dict] = {}
    for source, text in rt + [("note", t) for t in note_texts]:
        for subj in _subjects(text):
            if subj in confirmed_subjects:
                continue
            excerpt = re.sub(r"\s+", " ", text).strip()
            idx = excerpt.find(subj)
            snippet = excerpt[max(0, idx - 90) : idx + 120] if idx >= 0 else excerpt[:200]
            c = candidates.setdefault(subj, {"subject": subj, "sources": set(), "excerpt": snippet})
            c["sources"].add(source)
    cand_list = [
        {"subject": c["subject"], "sources": sorted(c["sources"]), "excerpt": c["excerpt"]}
        for c in candidates.values()
    ]
    cand_list.sort(key=lambda z: z["subject"])

    return {
        "run": run_dir.name,
        "confirmed": confirmed,
        "coverage": cov_entries,
        "candidates": cand_list,
        "counts": {
            "confirmed": len(confirmed),
            "coverage_entries": len(cov_entries),
            "candidate_subjects": len(cand_list),
        },
    }


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print("usage: suspected_candidates.py <run_dir> [--json]", file=sys.stderr)
        raise SystemExit(2)
    result = extract(Path(args[0]))
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"# run {result['run']}  —  {result['counts']}")
    print("\n## confirmed findings (vulnerabilities.json)")
    for v in result["confirmed"]:
        print(f"  [{v.get('severity')}] {v.get('cwe')} {v.get('method')} {v.get('endpoint')} — {v.get('title')}")
    print("\n## coverage (tested surfaces + outcome)")
    for c in result["coverage"]:
        print(f"  [{c.get('outcome')}] {c.get('risk_area')}  ::  {c.get('surface')}")
    print("\n## suspected candidate subjects (noticed in reasoning/think/notes, not in a confirmed finding)")
    for c in result["candidates"]:
        print(f"  - {c['subject']}  ({','.join(c['sources'])})\n      … {c['excerpt']}")


if __name__ == "__main__":
    main()
