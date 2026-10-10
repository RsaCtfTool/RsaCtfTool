#!/usr/bin/env sage

# Reference: https://github.com/comaeio/OPCDE/blob/master/2017/15%20ways%20to%20break%20RSA%20security%20-%20Renaud%20Lifchitz/opcde2017-ds-lifchitz-break_rsa.pdf
#
# Thin wrapper calling the shared implementation small_fraction in RsaCtfTool.lib.algos.
# It uses beta=0.49 (slightly below 0.5) via lattice_partial_p to ensure
# Coppersmith's divisor bound holds for factors slightly smaller than sqrt(N).

import sys
from pathlib import Path

script_path = Path(sys.argv[0]).resolve() if (sys.argv and sys.argv[0].endswith(".sage")) else Path(__file__).resolve()
src_dir = str(script_path.parents[2]) if len(script_path.parents) >= 3 else str(script_path.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from RsaCtfTool.lib.algos import small_fraction


def factor(n):
    p, q = small_fraction(n)
    return p


if __name__ in {"__main__", "sage.all"}:
    try:
        n = int(sys.argv[1])
        p = factor(n)
        if p is None:
            print(0)
        else:
            print(p)
    except Exception:
        print(0)
