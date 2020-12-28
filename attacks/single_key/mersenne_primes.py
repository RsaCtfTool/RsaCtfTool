#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run tests against mersenne primes"""
    with timeout(attack_rsa_obj.args.timeout):
        try:
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
            for mersenne_prime in tqdm(mersenne_tab):
                if publickey.n % ((2 ** mersenne_prime) - 1) == 0:
                    p = (2 ** mersenne_prime) - 1
                    q = publickey.n // ((2 ** mersenne_prime) - 1)
                    break
            if p is not None and q is not None:
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)
            return (None, None)
        except TimeoutError:
            return (None, None)
