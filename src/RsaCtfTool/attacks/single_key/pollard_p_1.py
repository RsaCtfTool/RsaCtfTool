#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import pollard_P_1


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard P1"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # Pollard P-1 attack
        poll_res = pollard_P_1(publickey.n, progress)
        if poll_res and len(poll_res) > 1:
            p, rem = poll_res[0], poll_res[1]
            from RsaCtfTool.lib.number_theory import is_prime, recursive_factorize
            if is_prime(rem):
                publickey.p, publickey.q = p, rem
                return self.create_private_key_from_pqe(
                    publickey.p, publickey.q, publickey.e, publickey.n
                )
            else:
                sub_primes = recursive_factorize(rem)
                all_primes = [p] + sub_primes
                import functools
                if functools.reduce(lambda x, y: x * y, all_primes, 1) == publickey.n:
                    return self.create_private_key_from_primes(
                        all_primes, publickey.e, publickey.n
                    )

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MBswDQYJKoZIhvcNAQEBBQADCgAwBwICCg0CAQc=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
