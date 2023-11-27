#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import ilog10
from factordb.factordb import FactorDB


def getfdb(composite):
    f = FactorDB(composite)
    f.connect()
    return f.get_factor_list()


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""
        try:
            n = publickey.n
            if ilog10(n) < (10**8):
                pq = getfdb(n)
                if pq[0] != n:
                    p, q = pq
                    if publickey.n != int(p) * int(q):
                        return None, None
                    publickey.p = p
                    publickey.q = q
                    priv_key = PrivateKey(
                        p=int(publickey.p),
                        q=int(publickey.q),
                        e=int(publickey.e),
                        n=int(publickey.n),
                    )
                    return priv_key, None
                else:
                    self.logger.error(
                        "[!] Composite not in factordb, couldn't factorize..."
                    )
                    return None, None
            else:
                self.logger.error(
                    "publickey.n size should be less than 10000000 digits..."
                )
                return None, None
        except:
            self.logger.error("[!] internal error :-(")
            return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MC0wDQYJKoZIhvcNAQEBBQADHAAwGQISAwm6aZnGyIrl57QGF+4RdcjlAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
