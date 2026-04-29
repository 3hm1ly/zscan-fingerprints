"""FingerprintHub web_fingerprint_v4.json → fingers YAML overlay.

FingerprintHub is nuclei-template-style:
    {
      "id": "...",
      "info": {"name": "...", "tags": "...", "metadata": {...}, ...},
      "http": [{
        "method": "GET",
        "path": ["{{BaseURL}}/", "{{BaseURL}}/foo"],
        "matchers": [
          {"type": "favicon", "hash": ["123"]},
          {"type": "word", "words": ["bar"], "case-insensitive": true},
          {"type": "regex", "regex": ["..."]},
        ],
      }]
    }

fingers YAML (one entry per app):
    - name: <app>
      protocol: http
      default_port: [80, 443]
      rule:
        - regexps:
            body:    ["..."]
            title:   ["..."]
            header:  ["..."]
            cookie:  ["..."]
          favicon:
            mmh3: ["123"]
            md5:  ["..."]
          version: "([0-9.]+)"
      vendor: <metadata.vendor>
      product: <metadata.product>

Mapping notes:
  - FingerprintHub `word` matcher → fingers `body` regex (we re.escape so
    operators don't bleed into regex).  case-insensitive flag is set on
    every match — fingers' regex engine honors `(?i)` prefix.
  - `favicon hash` (mmh3 string) → fingers `favicon.mmh3` (string array).
    FPH only ships mmh3, no md5; leave md5 empty.
  - `regex` matcher → fingers `body` regex verbatim.
  - We skip non-tech entries (CVE-only / exploit detectors) by filtering
    on `info.tags` containing 'detect' or 'tech'.
  - One FPH entry → one fingers entry (no duplication for paths; fingers'
    matching is response-content-only, paths are handled by spray's `-d`
    wordlist).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


def _is_useful(entry: dict) -> bool:
    info = entry.get("info") or {}
    tags = (info.get("tags") or "").lower()
    name = (info.get("name") or "").lower()
    if "detect" not in tags and "tech" not in tags:
        return False
    if "cve-" in name and "detect" not in tags:
        return False
    return bool(info.get("name"))


def _convert_one(entry: dict) -> dict | None:
    info = entry.get("info") or {}
    name = info.get("name") or entry.get("id")
    if not name:
        return None

    http = entry.get("http") or []
    if not http:
        return None
    stanza = http[0]

    body_patterns: list[str] = []
    favicon_hashes: list[str] = []
    for m in stanza.get("matchers") or []:
        mt = m.get("type")
        if mt == "word":
            ci = m.get("case-insensitive") or m.get("case_insensitive")
            for w in m.get("words") or []:
                if not w:
                    continue
                pat = re.escape(str(w))
                body_patterns.append(f"(?i){pat}" if ci else pat)
        elif mt == "regex":
            for r in m.get("regex") or []:
                if r:
                    body_patterns.append(str(r))
        elif mt == "favicon":
            for h in m.get("hash") or []:
                if h:
                    favicon_hashes.append(str(h))
        # status / dsl ignored

    if not body_patterns and not favicon_hashes:
        # Nothing actionable — skip
        return None

    metadata = info.get("metadata") or {}
    rule_block: dict[str, Any] = {}
    if body_patterns:
        rule_block["regexps"] = {"body": body_patterns}
    if favicon_hashes:
        rule_block["favicon"] = {"mmh3": favicon_hashes}

    out: dict[str, Any] = {
        "name": name,
        "protocol": "http",
        "default_port": [80, 443],
        "rule": [rule_block],
    }
    if metadata.get("vendor"):
        out["vendor"] = str(metadata["vendor"])
    if metadata.get("product"):
        out["product"] = str(metadata["product"])
    cpe = metadata.get("cpe") or info.get("cpe")
    if cpe:
        out["cpe"] = str(cpe)

    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: fph_to_fingers.py <input.json> <output.yaml>", file=sys.stderr)
        return 2

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    raw = json.loads(src.read_text(encoding="utf-8"))
    print(f"loaded {len(raw)} raw entries from {src}")

    converted: list[dict] = []
    skipped_filter = skipped_empty = 0
    for e in raw:
        if not _is_useful(e):
            skipped_filter += 1
            continue
        c = _convert_one(e)
        if c is None:
            skipped_empty += 1
            continue
        converted.append(c)

    print(
        f"converted={len(converted)}  "
        f"skipped(non-tech)={skipped_filter}  skipped(empty-rule)={skipped_empty}"
    )

    # Sort by name for deterministic output (so unchanged data → unchanged
    # YAML → no spurious git diffs in case anyone commits the artifact).
    converted.sort(key=lambda x: x["name"].lower())

    # YAML dump with allow_unicode for the Chinese app names FPH contains.
    dst.write_text(
        yaml.dump(converted, allow_unicode=True, sort_keys=False, width=200),
        encoding="utf-8",
    )
    print(f"wrote {dst} ({dst.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
