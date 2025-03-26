#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.system_primes import load_system_consts
from lib.number_theory import gcd, is_prime


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """System primes in crypto constants"""
        primes = load_system_consts()
        for prp in tqdm(primes, disable=(not progress)):
            p = gcd(publickey.n, prp)
            if publickey.n > p > 1:
                publickey.p = p
                q = publickey.n // p
                if is_prime(q):
                    publickey.p = p
                    publickey.q = q
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return priv_key, None
                else:
                    self.logger.error(
                        "[!] Currently this tool only supports RSA textbook semiprime modulus, your p and q are: (%d,%d)"
                        % (p, q)
                    )
                    return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MF0wDQYJKoZIhvcNAQEBBQADTAAwSQJCBcW4rpUeDXt1iPxWHCeb48HXZBIpulCr
t/e2LMmbGmPfBeS1cG7CKBFPBRdFIknRmApLezz8oBwSBcPhFmVMyBc9AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
