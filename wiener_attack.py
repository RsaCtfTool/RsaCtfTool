# -*- coding: utf-8 -*-

from sympy.solvers import solve
from sympy import Symbol


class WienerAttack(object):

    def solveQuadratic(self, a, b, c):
        x = Symbol('x')
        return solve(a * x ** 2 + b * x + c, x)

    def makeIndexedConvergent(self, sequence, index):
        (a, b) = (1, sequence[index])
        while index > 0:
            index -= 1
            (a, b) = (b, sequence[index] * b + a)
        return (b, a)

    def makeConvergents(self, sequence):
        r = []
        for i in xrange(0, len(sequence)):
            r.append(self.makeIndexedConvergent(sequence, i))
        return r

    def makeNextFraction(self, fraction):
        (a, b) = fraction
        res = b / a
        a1 = b % a
        b1 = a
        return res, (a1, b1)

    def makeContinuedFraction(self, fraction):
        (a, b) = fraction
        v = []
        v.append(0)
        while not a == 1:
            r, fraction = self.makeNextFraction(fraction)
            (a, b) = fraction
            v.append(r)
        v.append(b)
        return v

    def __init__(self, n, e):
        conv = self.makeConvergents(self.makeContinuedFraction((e, n)))
        for frac in conv:
            (k, d) = frac
            if k == 0:
                continue
            phiN = ((e * d) - 1) / k
            roots = self.solveQuadratic(1, -(n-phiN+1), n)
            if len(roots) == 2:
                p, q = roots[0] % n, roots[1] % n
                if p*q == n:
                    self.p = p
                    self.q = q
