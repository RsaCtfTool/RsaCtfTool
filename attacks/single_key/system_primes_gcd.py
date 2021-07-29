#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from lib.system_primes import load_system_consts
from lib.rsalibnum import gcd


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """System primes in crypto constants"""
        with timeout(self.timeout):
            try:
                primes = load_system_consts()
                for prp in tqdm(primes, disable=(not progress)):
                    g = gcd(publickey.n, prp)
                    if publickey.n > g > 1:
                        publickey.q = g
                        publickey.p = publickey.n // publickey.q
                        priv_key = PrivateKey(
                            int(publickey.p),
                            int(publickey.q),
                            int(publickey.e),
                            int(publickey.n),
                        )
                        return (priv_key, None)
            except TimeoutError:
                return (None, None)
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCBcW4rpUeDXt1iPxWHCeb48HXZBIpulCr
t/e2LMmbGmPfBeS1cG7CKBFPBRdFIknRmApLezz8oBwSBcPhFmVMyBc9AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
