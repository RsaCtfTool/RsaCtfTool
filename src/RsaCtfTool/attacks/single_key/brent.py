#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import brent


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard Rho-brent"""

        try:
            # pollard Rho-brent attack

            poll_res = brent(publickey.n)

            if poll_res is not None and 1 < poll_res < publickey.n:
                from RsaCtfTool.lib.number_theory import is_prime, recursive_factorize
                p = poll_res
                rem = publickey.n // p
                if is_prime(rem):
                    publickey.p = p
                    publickey.q = rem
                    return self.create_private_key_from_pqe(
                        publickey.p, publickey.q, publickey.e, publickey.n
                    )
                else:
                    # Multi-Prime RSA: recursively factorize composite remainder
                    sub_primes = recursive_factorize(rem)
                    all_primes = [p] + sub_primes
                    import functools
                    if functools.reduce(lambda x, y: x * y, all_primes, 1) == publickey.n:
                        return self.create_private_key_from_primes(
                            all_primes, publickey.e, publickey.n
                        )

            return None, None
        except TypeError:
            return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((83 * 97, 17)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
