#!/usr/bin/env sage

# Factoring with high bits known (Coppersmith).
# Reference: https://facthacks.cr.yp.to/lattice.html
#
# Thin wrapper calling the shared implementation lattice_partial_p in RsaCtfTool.lib.algos.

import sys
from pathlib import Path

script_path = Path(sys.argv[0]).resolve() if (sys.argv and sys.argv[0].endswith(".sage")) else Path(__file__).resolve()
src_dir = str(script_path.parents[2]) if len(script_path.parents) >= 3 else str(script_path.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from RsaCtfTool.lib.algos import lattice_partial_p


def lattice(n, nearp):
    """Return [g, n // g] when a nontrivial factor is recovered, else []."""
    p, q = lattice_partial_p(n, nearp)
    if p is not None and q is not None:
        return [int(p), int(q)]
    return []


if __name__ in {"__main__", "sage.all"}:
    try:
        res = lattice(int(sys.argv[1]), int(sys.argv[2]))
        print(res)
    except Exception:
        print([])
