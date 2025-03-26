from sage.libs.ntl.ntl_ZZ_pX import ntl_ZZ_pContext, ntl_ZZ_pX
import sys

def poly_fast_ntl(ctx, f, xs):
    # Fast multipoint evaulation from Modern Computer Algebra 3rd edition 10.1
    n = len(xs)
    rems = [0] * (4 * n)  # segment tree max size

    def build_tree(i, l, r):
        if l + 1 == r:
            x = xs[l] if l < len(xs) else 0
            rems[i] = ntl_ZZ_pX([-x, 1], ctx)
            return
        mid = (l + r) >> 1
        build_tree(i * 2, l, mid)
        build_tree(i * 2 + 1, mid, r)
        rems[i] = rems[i * 2] * rems[i * 2 + 1]

    build_tree(1, 0, n)

    def compute(f, i, l, r):
        if l + 1 == r:
            yield f % rems[i]
            return
        mid = (l + r) >> 1
        yield from compute(f % rems[2 * i], 2 * i, l, mid)
        yield from compute(f % rems[2 * i + 1], 2 * i + 1, mid, r)

    return map(lambda r: Integer(r.list()[0]), compute(f, 1, 0, n))


def factor(n, e, bound):
    # https://mathoverflow.net/questions/120160/attack-on-crt-rsa
    D = ceil(sqrt(bound))
    ctx = ntl_ZZ_pContext(n)  # NTL's polynomial multiplication is much faster
    x = randint(1, n - 1)
    xe = int(power_mod(x, e, n))
    poly_factors = []
    for a in range(0, D):
        poly_factors.append(ntl_ZZ_pX([-x, power_mod(xe, a, n)], ctx))
    poly = product(poly_factors)
    xed = int(power_mod(xe, D, n))
    ys = [int(power_mod(xed, b, n)) for b in range(0, D)]
    for t in poly_fast_ntl(ctx, poly, ys):
        p = gcd(t, n)
        if p > 1 and p < n:
            return p, n // p


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please provide n, e and bound", file=sys.stderr)
        exit(1)
    n = Integer(sys.argv[1])
    e = Integer(sys.argv[2])
    bound = Integer(sys.argv[3])  # upper bound of min(d_p, d_q)
    for _ in range(3):  # Retrying
        r = factor(n, e, bound)
        if r is not None:
            p, q = r
            print(p)
            exit()
    print(0)  # Prints 0 if failed
