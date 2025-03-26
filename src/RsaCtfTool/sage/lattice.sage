from gmpy2 import isqrt, remove
import sys


def lattice(n, nearp, howclose, t, k):
    """ source https://facthacks.cr.yp.to/lattice.html """
    R.<x> = PolynomialRing(ZZ)
    f = howclose * x + nearp
    M = matrix(t)
    for i in range(t):
        # f = (f^i*n^max(k-i,0))
        # print(f,dir(f))
        # M[i] = (f^i*n^max(k-i,0)).coeffs()+[0]*(t-1-i)
        M[i] = (f ^ i * n ^ max(k - i, 0)).coefficients() + [0] * (t - 1 - i)

    M = M.LLL()
    Q = sum(z * (x / howclose) ^ i for i, z in enumerate(M[0]))
    for r, multiplicty in Q.roots():
        if nearp + r > 0:
            g = gcd(n, nearp + r)
            if g > 1: return [g, n / g]
    return []


def get_params():
    nearp = int(sys.argv[2])
    n = int(sys.argv[1])
    a, b = remove(nearp, 10)
    howclose = int(10 ** b)
    t = howclose // 200
    k = howclose // 500
    return (n, nearp, howclose, t, k)


print(lattice(*get_params()))
