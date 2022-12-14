#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from factordb.factordb import FactorDB


def getfdb(composite):
  f = FactorDB(composite)
  f.connect()
  r = f.get_factor_list()
  return r


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]
        

    def attack(self, publickey, cipher=[], progress=True):
        """Factors available online?"""
        try:
            p, q = getfdb(publickey.n)
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
            
        except:
            return None, None


    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MC0wDQYJKoZIhvcNAQEBBQADHAAwGQISAwm6aZnGyIrl57QGF+4RdcjlAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
