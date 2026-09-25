#!/usr/bin/env python3
"""Generate vulnerable-component rules from NVD, gated against a benign corpus.

    python generate_rules.py --limit 1000
    python generate_rules.py --limit 1000 --min-score 9 --out rules/generated/nvd.yar

The gate is the point. Most candidates are rejected, and the rejection tally is
the interesting output: it shows how much of a CVE feed simply is not
expressible as a file-matching rule.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path

from securitysuite.config import load_config
from securitysuite.nvd import NvdClient
from securitysuite.rulegen import emit_file, generate

ROOT = Path(__file__).resolve().parent
RULE_DECLARATION_RE = re.compile(
    r"^\s*(?:(?:private|global)\s+)?rule\s+", re.MULTILINE
)

# Real files plus prose that mentions software by name. A generated rule that
# fires on any of this is too loose to ship.
BENIGN_PROSE = [
    b"Release notes: upgraded to version 2.14.1 of the logging library and "
    b"bumped the client to 1.2.3. See the changelog for details.\n",
    b"Our stack runs nginx 1.18.0 behind a load balancer, with PostgreSQL 13.4 "
    b"and Redis 6.2.5 on the data tier.\n",
    b"requirements.txt\nrequests==2.31.0\nurllib3==2.0.7\ncertifi==2024.2.2\n",
    b'{"name":"web","version":"1.0.0","dependencies":{"react":"18.2.0",'
    b'"express":"4.18.2","lodash":"4.17.21"}}',
    b"Quarterly review: the platform team upgraded three services this month. "
    b"No customer impact was recorded and all tests passed.\n",
    b"# Changelog\n## 2.7.0\n- Fixed a crash on startup\n- Updated dependencies\n",
    b"Dear team, please find attached the invoice for September. Payment terms "
    b"are 30 days. Regards, Accounts.\n",
]


def build_corpus() -> list:
    corpus = list(BENIGN_PROSE)
    # The repository's own files are the harshest realistic benign corpus: they
    # are full of product names, version numbers and security vocabulary.
    for pattern in ("*.md", "*.txt", "*.py", "samples/*", "web/*.js", "web/*.html"):
        for path in sorted(ROOT.glob(pattern))[:40]:
            try:
                if path.is_file() and path.stat().st_size < 2_000_000:
                    corpus.append(path.read_bytes())
            except OSError:
                continue
    return corpus


def count_rules_outside(output: Path) -> int:
    """Count hand-written rules without including the generated output file."""
    total = 0
    for path in sorted((ROOT / "rules").rglob("*.yar")):
        if path.resolve() == output.resolve():
            continue
        try:
            total += len(RULE_DECLARATION_RE.findall(
                path.read_text(encoding="utf-8", errors="replace")
            ))
        except OSError:
            continue
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=1000,
                        help="maximum candidate rules to consider (default 1000)")
    parser.add_argument("--total-rules", type=int,
                        help="emit enough generated rules for this exact ruleset total")
    parser.add_argument("--days", type=int, default=1460,
                        help="how far back to take recent CVEs (default 4 years)")
    parser.add_argument("--min-score", type=float, default=9.0,
                        help="minimum CVSS base score (default 9.0)")
    parser.add_argument("--out", default="rules/generated/nvd_components.yar")
    parser.add_argument("--dry-run", action="store_true",
                        help="report the tally without writing the file")
    args = parser.parse_args()

    out = ROOT / args.out
    generated_target = None
    candidate_limit = args.limit
    if args.total_rules is not None:
        hand_written = count_rules_outside(out)
        generated_target = args.total_rules - hand_written
        if generated_target < 1:
            print("[-] --total-rules must exceed the %d hand-written rules" % hand_written)
            return 2
        # The gate rejects some candidates. Harvest a measured buffer, then
        # keep the highest-priority survivors in deterministic order.
        candidate_limit = max(
            candidate_limit,
            math.ceil(generated_target * 1.25) + 50,
        )
        print("[*] Exact target  : %d total = %d hand-written + %d generated" % (
            args.total_rules, hand_written, generated_target
        ))

    cfg = load_config()
    client = NvdClient(cfg.nvd_cache_dir, cfg.nvd_api_key)
    if not client.api_key:
        print("[!] No NVD_API_KEY set - this will be slow (5 requests / 30 s).")

    corpus = build_corpus()
    print("[*] Benign corpus : %d documents" % len(corpus))
    print("[*] Harvesting CVEs from NVD (CVSS >= %.1f)..." % args.min_score)

    def progress(label, seen, total):
        print("    %-24s %d of %s" % (label, seen, format(total or 0, ",")))

    result = generate(client, days=args.days, limit=candidate_limit,
                      min_score=args.min_score, benign_corpus=corpus,
                      progress=progress)
    if "error" in result:
        print("[-] " + result["error"])
        return 1

    print()
    print("[*] CVEs examined : %d" % result["cves_examined"])
    print("[*] Candidates    : %d" % result["candidates"])
    print("[*] Survived gate : %d" % result["survivors"])
    print()
    if result["rejections"]:
        print("[*] Rejected, by reason:")
        for reason, count in sorted(result["rejections"].items(),
                                    key=lambda kv: -kv[1]):
            print("      %-44s %d" % (reason, count))
    kept = result["rules"]
    if generated_target is not None:
        if len(kept) < generated_target:
            print("[-] Only %d candidates survived; need %d. Increase --limit." % (
                len(kept), generated_target
            ))
            return 1
        kept = kept[:generated_target]
    if kept:
        kev = sum(1 for r in kept if r["kev"])
        print()
        print("[*] Kept %d rules, %d for CISA KEV entries" % (len(kept), kev))
        by_sev = {}
        for r in kept:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        print("[*] Severity      : " + ", ".join("%s %d" % kv for kv in sorted(by_sev.items())))
        print("[*] Sample        :")
        for r in kept[:5]:
            print("      %-16s %-28s %s" % (r["cve"], r["vendor"] + ":" + r["product"],
                                            ",".join(r["versions"][:3])))

    if args.dry_run:
        print("\n[*] --dry-run: nothing written.")
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(emit_file(kept), encoding="utf-8")
    print("\n[*] Wrote %s (%d rules)" % (out, len(kept)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
