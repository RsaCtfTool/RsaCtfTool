#!/usr/bin/env sage

# Factoring with high bits known (Coppersmith). Given n and nearp, an
# approximation to one factor of n whose high bits are correct, recover the
# exact factor. Replaces the previous gmpy2.remove-based parameter derivation,
# which always produced t = k = 0 and crashed on an empty lattice matrix.
# reference https://facthacks.cr.yp.to/lattice.html

import sys


def lattice(n, nearp):
    """Return [g, n // g] when a nontrivial factor is recovered, else []."""
    n = Integer(n)
    nearp = Integer(nearp)

    # Quick path: the approximation may already be an exact factor or share
    # a nontrivial divisor with n.
    g = gcd(n, nearp)
    if 1 < g < n:
        return [int(g), int(n // g)]

    nbits = n.nbits()
    pbits = nearp.nbits()
    # Conservative size ratio: a bit length only bounds the magnitude from
    # above, so use the guaranteed lower bound of the factor's size. This
    # keeps the small_roots precondition "a factor of size >= n^beta exists"
    # mathematically valid for every key.
    beta = QQ(pbits - 1) / QQ(nbits)
    if beta <= 0 or beta >= 1:
        return []

    # Coppersmith univariate: f = x + nearp has the small root p - nearp
    # modulo the target factor. The actual error size is unknown and the
    # window shrinks with beta (factor imbalance), so sweep the bound upward.
    # A reduced epsilon deepens the lattice and widens the practical window
    # at the cost of LLL time.
    epsilon = beta / 16
    max_bits = max(int((beta * beta - epsilon) * nbits * 0.95), 1)

    import os, sys
    # Add root to sys path so we can import RsaCtfTool
    rootpath = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if rootpath not in sys.path:
        sys.path.append(rootpath)
        
    from RsaCtfTool.lib.coppersmith import CoppersmithParameters, _select_coppersmith_parameters
    from sage.coppersmith import coppersmith_univariate_sage

    R.<x> = PolynomialRing(Zmod(n))
    f = x + nearp
    bits = min(32, max_bits)
    while True:
        X = Integer(2) ** bits
        cands = _select_coppersmith_parameters(f.degree(), n, beta=beta, X=X, epsilon=epsilon)
        if cands:
            m, t = cands[0]
            params = CoppersmithParameters(beta=beta, X=X, m=m, t=t)
            try:
                roots = coppersmith_univariate_sage(f, n, params)
                for r in roots:
                    g = gcd(n, nearp + Integer(r))
                    if 1 < g < n:
                        return [int(g), int(n // g)]
            except Exception:
                pass

        if bits >= max_bits:
            break
        bits = min(bits * 2, max_bits)
    return []


if __name__ in {"__main__", "sage.all"}:
    try:
        print(lattice(int(sys.argv[1]), int(sys.argv[2])))
    except Exception:
        print([])
