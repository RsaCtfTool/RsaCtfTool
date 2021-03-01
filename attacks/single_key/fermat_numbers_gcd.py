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
            pc = 0
            p = q = None
            while True:
                fermat = (2**2**pc) + 1
                if 1 < fermat< publickey.n:
                    p = publickey.n // fermat
                    q = fermat
                    break
                pc+=1
                if pc == limit: 
                  break
            if p is not None and q is not None:
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)
            return (None, None)
        except TimeoutError:
            return (None, None)
