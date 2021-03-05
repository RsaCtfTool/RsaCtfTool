#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


def primes(n):
    """ Returns  a list of primes < n """
    sieve = [True] * n
    for i in range(3, int(n ** 0.5) + 1, 2):
        if sieve[i]:
            sieve[i * i :: 2 * i] = [False] * ((n - i * i - 1) // (2 * i) + 1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Try an attack where q < 100,000, from BKPCTF2016 - sourcekris"""
    with timeout(attack_rsa_obj.args.timeout):
        try:
            for prime in primes(100000):
                if publickey.n % prime == 0:
                    publickey.q = prime
                    publickey.p = publickey.n // publickey.q
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
        except TimeoutError:
            return (None, None)
    return (None, None)
