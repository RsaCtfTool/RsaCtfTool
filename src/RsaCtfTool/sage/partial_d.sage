#!/usr/bin/env sage

# Partial key exposure attack (Coppersmith partial d).
# Reference: https://raw.githubusercontent.com/lwcM/RSA_attack/master/partial_key_exposure_attack.py
#
# Thin wrapper calling the shared implementation partial_d in RsaCtfTool.lib.algos.

import sys
from pathlib import Path

script_path = Path(sys.argv[0]).resolve() if (sys.argv and sys.argv[0].endswith(".sage")) else Path(__file__).resolve()
src_dir = str(script_path.parents[2]) if len(script_path.parents) >= 3 else str(script_path.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from RsaCtfTool.lib.algos import partial_d


if __name__ in {"__main__", "sage.all"}:
    try:
        n = int(sys.argv[1])
        e = int(sys.argv[2])
        dLow = int(sys.argv[3])
        known_bits = int(sys.argv[4]) if len(sys.argv) > 4 else None

        res = partial_d(n, e, dLow, known_bits)
        if res and res[0] is not None:
            print(f"{res[0]} {res[1]}")
    except Exception:
        pass
