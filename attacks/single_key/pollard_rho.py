#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import logging
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from gmpy2 import *


def pollard_rho(n, seed=2, p=2, mode=1):
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    if n % 5 == 0:
        return 5
    if is_prime(n):
        return n
    if mode == 1:
        f = lambda x: x ** p + 1
    else:
        f = lambda x: x ** p - 1
    x, y, d = seed, seed, 1
    while d == 1:
        x = f(x) % n
        y = f(f(y)) % n
        d = gcd((x - y) % n, n)
    return None if d == n else d


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run attack with Pollard Rho"""
    if not hasattr(publickey, "p"):
        publickey.p = None
    if not hasattr(publickey, "q"):
        publickey.q = None

    # pollard Rho attack

    with timeout(attack_rsa_obj.args.timeout):
        try:
            try:
                poll_res = pollard_rho(publickey.n)
            except RecursionError:
                print("RecursionError")
                return (None, None)

            if poll_res != None:
                publickey.p = poll_res
                publickey.q = publickey.n // publickey.p

            if publickey.q is not None:
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        except TimeoutError:
            return (None, None)
        except TypeError:
            return (None, None)

    return (None, None)
