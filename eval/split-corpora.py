#!/usr/bin/env python3
"""Split composite corpora into benign, overambitious, and adversarial JSONL files."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CASES = REPO / "eval/cases"

SOURCES = {
    "from-claude-logs.jsonl": CASES / "from-claude-logs.jsonl",
    "prompt-injection.jsonl": CASES / "prompt-injection.jsonl",
    "regression.jsonl": CASES / "regression.jsonl",
    "adversarial-smoke.jsonl": CASES / "adversarial-smoke.jsonl",
}


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def dedupe(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for row in rows:
        case_id = row.get("id")
        if not case_id or case_id in seen:
            continue
        seen.add(case_id)
        out.append(row)
    return out


def main() -> None:
    benign: list[dict] = []
    overambitious: list[dict] = []
    adversarial: list[dict] = []

    for name, path in SOURCES.items():
        if not path.is_file():
            continue
        for row in load_jsonl(path):
            case_class = row.get("class", "")
            expected = row.get("expected")
            block = row.get("blockCategory", "")

            if case_class == "benign" or block == "benign-control" or expected == "allow":
                benign.append(row)
                continue

            if case_class == "adversarial" or block in {
                "fake-user-auth",
                "classifier-jailbreak",
                "quick-filter-trap",
                "arg-smuggle",
                "indirect-read-auth",
                "hostile-read",
            }:
                adversarial.append(row)
                continue

            if case_class == "overambitious" or row.get("semanticExpected") == "deny":
                overambitious.append(row)
                continue

            if expected == "deny":
                adversarial.append(row)
            elif expected == "manual":
                overambitious.append(row)

    benign = dedupe(benign)
    overambitious = dedupe(overambitious)
    adversarial = dedupe(adversarial)

    write_jsonl(CASES / "benign.jsonl", benign)
    write_jsonl(CASES / "overambitious.jsonl", overambitious)
    write_jsonl(CASES / "adversarial.jsonl", adversarial)

    fix_path = REPO / "eval/fix_corpus_expectations.py"
    spec = importlib.util.spec_from_file_location("fix_corpus_expectations", fix_path)
    fix_mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(fix_mod)

    for name in ("overambitious.jsonl", "prompt-injection.jsonl", "adversarial.jsonl", "from-claude-logs.jsonl"):
        path = CASES / name
        if path.is_file():
            rows = fix_mod.patch_rows(load_jsonl(path))
            write_jsonl(path, rows)

    print(f"Wrote benign.jsonl: {len(benign)} cases")
    print(f"Wrote overambitious.jsonl: {len(overambitious)} cases")
    print(f"Wrote adversarial.jsonl: {len(adversarial)} cases")


if __name__ == "__main__":
    main()
