#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import getpubkeysz, is_divisible


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against mersenne primes"""
        p = q = None
        mersenne_tab = [
            2,
            3,
            5,
            7,
            13,
            17,
            19,
            31,
            61,
            89,
            107,
            127,
            521,
            607,
            1279,
            2203,
            2281,
            3217,
            4253,
            4423,
            9689,
            9941,
            11213,
            19937,
            21701,
            23209,
            44497,
            86243,
            110503,
            132049,
            216091,
            756839,
            859433,
            1257787,
            1398269,
            2976221,
            3021377,
            6972593,
            13466917,
            20336011,
            24036583,
            25964951,
            30402457,
            32582657,
            37156667,
            42643801,
            43112609,
            57885161,
            74207281,
            77232917,
            82589933,
        ]
        n = publickey.n
        i = getpubkeysz(n)
        for mersenne_prime in tqdm(mersenne_tab, disable=(not progress)):
            if mersenne_prime > i:
                break
            m = (1 << mersenne_prime) - 1
            if is_divisible(n, m):
                p = m
                q = n // p
                break
        if p is not None and q is not None:
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None
        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIIB3zANBgkqhkiG9w0BAQEFAAOCAcwAMIIBxwKCAb4A////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
/f//////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////gAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQID
AQAB
-----END PUBLIC KEY-----"""
        self.timeout = 90
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
