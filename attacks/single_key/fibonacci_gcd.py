#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from math import log2
from gmpy2 import gcd,fib

def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run tests against fermat composites"""
    with timeout(attack_rsa_obj.args.timeout):
        try:
            limit = 10000
            p = q = None
            for x in tqdm(range(1,limit)):
                f = gcd(fib(x),publickey.n)
                if 1 < f < publickey.n:
                    p = publickey.n // f
                    q = f
                    break
            if p is not None and q is not None:
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)
            return (None, None)
        except TimeoutError:
            return (None, None)
