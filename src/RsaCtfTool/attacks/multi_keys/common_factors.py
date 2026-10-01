#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, list_prod
from RsaCtfTool.lib.keys_wrapper import PrivateKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickeys, cipher=[], progress=True):
        """Common factor attack"""
        if not isinstance(publickeys, list):
            return None, None

        pubs = [pub.n for pub in publickeys]
        # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
        priv_keys = []
        M = list_prod(tuple(pubs))
        for i in range(0, len(pubs)):
            pub = pubs[i]
            p = gcd(pub, M // pub)
            if pub > p > 1:
                x = publickeys[i]
                rem = pub // p
                from RsaCtfTool.lib.number_theory import is_prime, recursive_factorize
                if is_prime(rem):
                    x.p = p
                    x.q = rem
                    priv_key_1 = PrivateKey(int(x.p), int(x.q), int(x.e), int(x.n))
                else:
                    sub_primes = recursive_factorize(rem)
                    all_primes = [p] + sub_primes
                    priv_key_1 = PrivateKey(primes=all_primes, e=int(x.e), n=int(x.n))

                if priv_key_1.key is not None or priv_key_1.d is not None:
                    priv_keys.append(priv_key_1)
                self.logger.info(f"[*] Found common factor in modulus for {x.filename}")

        priv_keys = list(set(priv_keys))
        if not priv_keys:
            priv_keys = None

        return (priv_keys, None)
