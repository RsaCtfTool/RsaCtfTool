#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import Solver, Int ,set_param
from attacks.abstract_attack import AbstractAttack
from gmpy2 import isqrt
from lib.utils import timeout, TimeoutError
from lib.keys_wrapper import PrivateKey
set_param('parallel.enable', True)

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def z3_solve(self, n, timeout_amount):
        s = Solver()
        s.set("timeout", timeout_amount * 1000)
        p = Int("x")
        q = Int("y")
        i = int(isqrt(n))
        if i**2 == n: # check if we are dealing with a perfect square otherwise try to SMT.
            return i,i
        s.add(p * q == n, p > 1, q > i, q > p) # In every composite n=pq,there exists a p>sqrt(n) and q<sqrt(n).
        try:
            s_check_output = s.check()
            res = s.model()
            return res[p].as_long(), res[q].as_long()
        except:
            return None, None

    def attack(self, publickey, cipher=[], progress=True):

        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # solve with z3 theorem prover
        with timeout(self.timeout):
            try:
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
                    return (priv_key, None)
                else:
                    return (None,None)
            except TimeoutError:
                return (None, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCMwDQYJKoZIhvcNAQEBBQADEgAwDwIIMAYCAQ8CAQMCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
