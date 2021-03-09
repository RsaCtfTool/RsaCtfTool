#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import math
from lib.timeout import timeout
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import timeout, TimeoutError

# Source - http://stackoverflow.com/a/20465181
def isqrt(n):
    """Is n a square ?"""
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat(n):
    """Fermat attack"""
    a = isqrt(n)
    b2 = a * a - n
    b = isqrt(n)
    count = 0
    while b * b != b2:
        a = a + 1
        b2 = a * a - n
        b = isqrt(b2)
        count += 1
    p = a + b
    q = a - b
    assert n == p * q
    return p, q


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run fermat attack with a timeout"""
    try:
        with timeout(seconds=attack_rsa_obj.args.timeout):
            try:
                publickey.p, publickey.q = fermat(publickey.n)
            except TimeoutError:
                return (None, None)

    except FactorizationError:
        return (None, None)

    if publickey.p is not None and publickey.q is not None:
        try:
            priv_key = PrivateKey(int(publickey.p), int(publickey.q), int(publickey.e))
            return (priv_key, None)
        except ValueError:
            return (None, None)

    return (None, None)
