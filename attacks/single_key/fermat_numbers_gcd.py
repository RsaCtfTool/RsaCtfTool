#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from math import log2
from gmpy2 import gcd,next_prime

def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run tests against fermat composites"""
    with timeout(attack_rsa_obj.args.timeout):
        try:
            limit = 10000
            p = q = None
            for x in tqdm(range(1,limit)):
                f = (2**2**x) + 1
                fermat = gcd(f,publickey.n)
                if 1 < fermat< publickey.n:
                    p = publickey.n // fermat
                    q = fermat
                    break
            if p is not None and q is not None:
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)
            return (None, None)
        except TimeoutError:
            return (None, None)
