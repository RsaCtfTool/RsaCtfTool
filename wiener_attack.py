# -*- coding: utf-8 -*-

from sympy.solvers import solve
from sympy import Symbol


class WienerAttack(object):
    def partial_quotiens(self, x, y):
        pq = []
        while x != 1:
                pq.append(x / y)
                a = y
                b = x % y
                x = a
                y = b
        return pq

    def rational(self, pq):
        i = len(pq) - 1
        num = pq[i]
        denom = 1
        while i > 0:
                i -= 1
                a = (pq[i] * num) + denom
                b = num
                num = a
                denom = b
        return (num, denom)

    def convergents(self, pq):
        c = []
        for i in range(1, len(pq)):
                c.append(self.rational(pq[0:i]))
        return c

    def phiN(self, e, d, k):
        return ((e * d) - 1) / k

    def __init__(self, n, e):
        self.p = None
        self.q = None
        pq = self.partial_quotiens(e, n)
        c = self.convergents(pq)
        x = Symbol('x')
        for (k, d) in c:
            if k != 0:
                y = n - self.phiN(e, d, k) + 1
                roots = solve(x**2 - y*x + n, x)
                if len(roots) == 2:
                    p = roots[0]
                    q = roots[1]
                    if p * q == n:
                        self.p = p
                        self.q = q
                        break
