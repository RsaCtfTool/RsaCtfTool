#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import Solver, Int, set_param, sat
from attacks.abstract_attack import AbstractAttack
from lib.number_theory import isqrt, next_prime
from lib.keys_wrapper import PrivateKey

set_param("parallel.enable", True)


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def z3_solve(self, n, timeout_amount):
        """Integer factorization using z3 theorem prover implementation:
        We can factor composite integers by SAT solving the model N=PQ directly using the clasuse (n==p*q),
        wich gives a lot of degree of freedom to z3, so we want to contraint the search space.
        Since every composite number n=pq, there always exists some p>sqrt(n) and q<sqrt(n).
        We can safely asume the divisor p is in the range n > p >= next_prime(sqrt(n))
        if this later clause doesn't hold and sqrt(p) is prime the number is a perfect square.
        We can also asume that p and q are alyaws odd otherwise our whole composite is even.
        Not all composite numbers generate a valid model that z3 can SAT.
        SAT solving is efficient with low bit count set in the factors,
        the complexity of the algorithm grows exponential with every bit set.
        The problem of SAT solving integer factorization still is NP complete,
        making this just a showcase. Don't expect big gains.
        """
        s = Solver()
        s.set("timeout", timeout_amount * 1000)
        p = Int("p")
        q = Int("q")
        i = int(isqrt(n))
        np = int(next_prime(i))
        s.add(
            p * q == n,
            n > p,
            n > q,
            p >= np,
            q < i,
            q > 1,
            p > 1,
            q % 2 != 0,
            p % 2 != 0,
        )
        try:
            s_check_output = s.check()
            if s_check_output == sat:
                res = s.model()
                P, Q = res[p].as_long(), res[q].as_long()
                assert P * Q == n
                return P, Q
            else:
                return None, None
        except:
            return None, None

    def attack(self, publickey, cipher=[], progress=True):
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # solve with z3 theorem prover
        try:
            z3_res = self.z3_solve(publickey.n, self.timeout)
        except:
            self.logger.warning("[!] z3: Internal Error.")
            return (None, None)

        if z3_res and len(z3_res) > 1:
            p, q = z3_res
            publickey.p = p
            publickey.q = q

        if publickey.q is not None:
            priv_key = PrivateKey(
                int(publickey.p),
                int(publickey.q),
                int(publickey.e),
                int(publickey.n),
            )
            return priv_key, None
        else:
            return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        # The complexity of the problem grows exponential with every bit set.
        # p=0b10000000000001111, q=0b10000000000000011
        key_data = """-----BEGIN PUBLIC KEY-----
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFAQASAC0CAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
