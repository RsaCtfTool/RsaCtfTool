#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import fermat


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""
        try:
            r = fermat(publickey.n)
            if r is None:
                return None, None
            p1, p2 = r
            from RsaCtfTool.lib.number_theory import is_prime, recursive_factorize

            if is_prime(p1) and is_prime(p2):
                publickey.p, publickey.q = p1, p2
                return self.create_private_key(publickey)
            else:
                # Generalized Fermat: e.g. A = p1*p2, B = p3*p4 near sqrt(n)
                all_primes = []
                for factor in (p1, p2):
                    if is_prime(factor):
                        all_primes.append(factor)
                    else:
                        all_primes.extend(recursive_factorize(factor))
                import functools

                if functools.reduce(lambda x, y: x * y, all_primes, 1) == publickey.n:
                    return self.create_private_key_from_primes(
                        all_primes, publickey.e, publickey.n
                    )
        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG6ZYBPnfEFpkADglB1IDARrL3
Gk+Vs1CsGk1CY3KSPYpFYdlvv7AkBZWQcgGtMiXPbt7X3gLZHDhv+sKAty0Plcrn
H0Lr4NPtrqznzqMZX6MsHGCA2Q74U9Bt1Fcskrn4MQu8DGNaXiaVJRF1EDCmWQgW
VU52MDG8uzHj8RnGXwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
