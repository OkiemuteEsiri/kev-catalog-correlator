from __future__ import annotations

import argparse
from pathlib import Path

from .correlator import correlate, load_findings, load_kev_catalog
from .reporting import to_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate vulnerability findings with a KEV-style catalog")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--kev", required=True)
    parser.add_argument("--output", default="kev-correlation-report.md")
    args = parser.parse_args()

    results = correlate(load_findings(args.findings), load_kev_catalog(args.kev))
    Path(args.output).write_text(to_markdown(results), encoding="utf-8")
    print(f"Wrote {len(results)} correlated findings to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
