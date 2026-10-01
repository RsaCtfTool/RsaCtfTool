#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd


def a(n):
    return int(str(n)[::-1])


def b(n):
    return int(bin(n)[2:][::-1], 2)


def c(n):
    return int(oct(n)[2:][::-1], 8)


def d(n):
    return int(hex(n)[2:][::-1], 16)


def FF(n):
    F = []
    for p in range(1, 6):
        np = pow(n, p)

        F.append(gcd(n, a(np)))
        F.append(gcd(n, b(np)))
        F.append(gcd(n, c(np)))
        F.append(gcd(n, d(np)))

        F.append(gcd(n, n ^ a(np)))
        F.append(gcd(n, n ^ b(np)))
        F.append(gcd(n, n ^ c(np)))
        F.append(gcd(n, n ^ d(np)))

    return list(set(filter(lambda x: n > x > 1, F)))


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Test n against gcds with inverted-factorial products in multiple bases"""
        try:
            pq = FF(publickey.n)
            if len(pq) == 2:
                publickey.p, publickey.q = pq
            elif len(pq) == 1:
                publickey.p = pq[0]
                publickey.q = publickey.n // pq[0]
            elif len(pq) > 2:
                import functools

                if functools.reduce(lambda x, y: x * y, pq, 1) == publickey.n:
                    return self.create_private_key_from_primes(
                        pq, publickey.e, publickey.n
                    )
                publickey.primes = pq
            else:
                self.logger.error("No factors found...")
                return None, None
        except Exception:
            self.logger.error("Factorization error...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((3 * 5, 7)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
