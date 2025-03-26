#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.number_theory import gcd, list_prod
from lib.keys_wrapper import PrivateKey


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
                x.p = p
                x.q = pub // p
                # update each attackobj with a private_key
                priv_key_1 = PrivateKey(int(x.p), int(x.q), int(x.e), int(x.n))
                priv_keys.append(priv_key_1)
                self.logger.info(f"[*] Found common factor in modulus for {x.filename}")

        priv_keys = list(set(priv_keys))
        if not priv_keys:
            priv_keys = None

        return (priv_keys, None)
